"use strict";

// Firefox 140 ESR (TB 15.x) silently treats MV2 backgrounds with
// "persistent": true as event pages. The page is only loaded when an
// event listener fires, and unloads after ~30 s of inactivity. We
// keep the page alive by:
//   1. Registering listeners synchronously at module load (forces
//      Firefox to parse the script when an event needs to be
//      dispatched).
//   2. Triggering startup from runtime.onStartup / runtime.onInstalled,
//      both of which fire reliably for a freshly-installed extension.
//   3. Holding the page alive with a recurring browser.alarms tick;
//      alarms reset the event-page inactivity timer the same way any
//      extension API event does.

const POLL_BACKOFF_MS = 1000;
const EXTENSION_VERSION = "0.1.0";
const KEEPALIVE_ALARM = "tbm-helper-keepalive";

let started = false;

function logInfo(...args) {
  try { console.log("[tor-browser-mcp helper]", ...args); } catch (e) {}
}

function logError(...args) {
  try { console.error("[tor-browser-mcp helper]", ...args); } catch (e) {}
}

async function loadConfig() {
  const url = browser.runtime.getURL("config.json");
  const response = await fetch(url);
  return response.json();
}

async function handleRequest(req, base, headers) {
  let body;
  try {
    if (req.method === "ping") {
      body = { id: req.id, result: { pong: true } };
    } else {
      body = {
        id: req.id,
        error: { code: "unknown_method", message: "unknown method: " + req.method },
      };
    }
  } catch (e) {
    body = {
      id: req.id,
      error: { code: "handler_error", message: String(e) },
    };
  }
  try {
    await fetch(base + "/response", {
      method: "POST",
      headers: headers,
      body: JSON.stringify(body),
    });
  } catch (e) {
    logError("response post failed:", e);
  }
}

async function startup() {
  if (started) return;
  started = true;

  // Ensure the keepalive alarm is armed before we enter the long-poll
  // loop. Event-page suspension is reset by alarm fires.
  try {
    await browser.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.25 });
  } catch (e) {
    logError("alarm.create failed:", e);
  }

  let config;
  try {
    config = await loadConfig();
  } catch (e) {
    logError("failed to load config.json:", e);
    return;
  }
  if (
    !config ||
    typeof config.bridge_host !== "string" ||
    typeof config.bridge_port !== "number" ||
    typeof config.token !== "string"
  ) {
    logError("config.json missing required fields");
    return;
  }

  const base = "http://" + config.bridge_host + ":" + config.bridge_port;
  const headers = {
    "Authorization": "Bearer " + config.token,
    "Content-Type": "application/json",
  };

  let hello;
  try {
    hello = await fetch(base + "/hello", {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ token: config.token, version: EXTENSION_VERSION }),
    });
  } catch (e) {
    logError("hello fetch failed:", e);
    return;
  }
  if (!hello.ok) {
    logError("hello rejected:", hello.status);
    return;
  }
  logInfo("bridge connected at", base);

  while (true) {
    let resp;
    try {
      resp = await fetch(base + "/poll", { method: "GET", headers: headers });
    } catch (e) {
      logError("poll fetch failed:", e);
      await new Promise(function (r) { setTimeout(r, POLL_BACKOFF_MS); });
      continue;
    }
    if (resp.status === 204) {
      continue;
    }
    if (resp.status === 401) {
      logError("poll auth rejected; shutting down poll loop");
      return;
    }
    if (resp.status === 503) {
      logInfo("bridge reports closed; shutting down poll loop");
      return;
    }
    if (!resp.ok) {
      logError("poll status:", resp.status);
      await new Promise(function (r) { setTimeout(r, POLL_BACKOFF_MS); });
      continue;
    }
    let req;
    try {
      req = await resp.json();
    } catch (e) {
      logError("poll body parse failed:", e);
      continue;
    }
    handleRequest(req, base, headers).catch(function (e) {
      logError("request handler failed:", e);
    });
  }
}

// Synchronous listener registrations. Their presence at module-parse
// time is what makes Firefox treat this as a real background page
// rather than a fully-dormant event page.
browser.runtime.onStartup.addListener(function () {
  startup().catch(logError);
});
browser.runtime.onInstalled.addListener(function () {
  startup().catch(logError);
});
browser.alarms.onAlarm.addListener(function (alarm) {
  if (alarm.name === KEEPALIVE_ALARM && !started) {
    startup().catch(logError);
  }
});

// Belt-and-braces: also kick startup at module-load. If Firefox does
// honour persistent: true on the current build, the script runs at
// install time and this path wins. If not, the listeners above pick up
// the slack.
startup().catch(logError);
