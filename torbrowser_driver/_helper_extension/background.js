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
let bridgeBase = null;
let bridgeHeaders = null;

const captures = new Map();
const initScripts = new Map();
// Strong references to live StreamFilter objects. Without this the
// filter can be reclaimed before Firefox has finished wiring it up to
// the response channel, which presents as onstart/ondata never firing
// while onstop still does.
const activeFilters = new Map();

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

function bytesToBase64(view) {
  const u8 = view instanceof Uint8Array ? view : new Uint8Array(view);
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) {
    binary += String.fromCharCode.apply(
      null,
      u8.subarray(i, Math.min(i + CHUNK, u8.length))
    );
  }
  return btoa(binary);
}

function headersToObject(list) {
  const out = {};
  for (const entry of list || []) {
    if (entry && typeof entry.name === "string") {
      out[entry.name] = entry.value == null ? "" : String(entry.value);
    }
  }
  return out;
}

async function postEvent(name, data) {
  if (!bridgeBase || !bridgeHeaders) return;
  try {
    await fetch(bridgeBase + "/event", {
      method: "POST",
      headers: bridgeHeaders,
      body: JSON.stringify({ name: name, data: data }),
    });
  } catch (e) {
    logError("event post failed:", name, e);
  }
}

function startCapture(params) {
  const captureId = params.capture_id;
  const patterns = Array.isArray(params.patterns) ? params.patterns : ["<all_urls>"];
  const captureBody = !!params.capture_response_body;
  const maxBytes = typeof params.max_body_bytes === "number"
    ? params.max_body_bytes
    : 5 * 1024 * 1024;
  if (typeof captureId !== "string" || !captureId) {
    throw new Error("capture.start: missing capture_id");
  }
  if (captures.has(captureId)) {
    throw new Error("capture.start: duplicate capture_id " + captureId);
  }
  const filter = { urls: patterns };

  function onBeforeRequest(details) {
    const rid = String(details.requestId);
    postEvent("request.observed", {
      capture_id: captureId,
      request_id: rid,
      method: details.method,
      url: details.url,
      started_at: details.timeStamp,
    });
    if (!captureBody) return;
    try {
      const stream = browser.webRequest.filterResponseData(details.requestId);
      let sent = 0;
      // Serialize per-request body_chunk POSTs so the driver sees them
      // in the order Firefox handed them to the filter; without this,
      // the localhost HTTP pool can deliver the is_final marker before
      // earlier chunks and the response body is finalized empty.
      let chain = Promise.resolve();
      function enqueueChunk(payload) {
        chain = chain.then(function () { return postEvent("body_chunk", payload); });
      }
      activeFilters.set(rid, stream);
      stream.ondata = function (event) {
        // Copy bytes into our own ArrayBuffer before write() so the
        // page-bound passthrough cannot detach the buffer underneath
        // us. filter.write() is documented to transfer ownership of
        // ArrayBuffer arguments in Firefox.
        const snapshot = new Uint8Array(event.data.byteLength);
        snapshot.set(new Uint8Array(event.data));
        try { stream.write(event.data); } catch (e) {}
        if (sent >= maxBytes) return;
        const remaining = maxBytes - sent;
        let view;
        if (snapshot.byteLength > remaining) {
          view = snapshot.subarray(0, remaining);
          sent += remaining;
        } else {
          view = snapshot;
          sent += snapshot.byteLength;
        }
        if (view.byteLength === 0) return;
        enqueueChunk({
          capture_id: captureId,
          request_id: rid,
          chunk_b64: bytesToBase64(view),
          is_final: false,
        });
      };
      stream.onstop = function () {
        try { stream.close(); } catch (e) {}
        activeFilters.delete(rid);
        enqueueChunk({
          capture_id: captureId,
          request_id: rid,
          chunk_b64: "",
          is_final: true,
        });
      };
      stream.onerror = function () {
        try { stream.close(); } catch (e) {}
        activeFilters.delete(rid);
        enqueueChunk({
          capture_id: captureId,
          request_id: rid,
          chunk_b64: "",
          is_final: true,
        });
      };
    } catch (e) {
      logError("filterResponseData failed:", e);
      postEvent("response.error", {
        capture_id: captureId,
        request_id: rid,
        error: "filter_attach_failed: " + String(e && e.message || e),
      });
    }
  }

  function onSendHeaders(details) {
    postEvent("request.headers", {
      capture_id: captureId,
      request_id: String(details.requestId),
      request_headers: headersToObject(details.requestHeaders),
    });
  }

  function onHeadersReceived(details) {
    postEvent("response.observed", {
      capture_id: captureId,
      request_id: String(details.requestId),
      status_code: details.statusCode,
      response_headers: headersToObject(details.responseHeaders),
    });
  }

  function onCompleted(details) {
    postEvent("response.completed", {
      capture_id: captureId,
      request_id: String(details.requestId),
      ip: details.ip || null,
      completed_at: details.timeStamp,
    });
  }

  function onErrorOccurred(details) {
    postEvent("response.error", {
      capture_id: captureId,
      request_id: String(details.requestId),
      error: details.error || null,
      completed_at: details.timeStamp,
    });
  }

  browser.webRequest.onBeforeRequest.addListener(onBeforeRequest, filter);
  browser.webRequest.onSendHeaders.addListener(onSendHeaders, filter, ["requestHeaders"]);
  browser.webRequest.onHeadersReceived.addListener(onHeadersReceived, filter, ["responseHeaders"]);
  browser.webRequest.onCompleted.addListener(onCompleted, filter, ["responseHeaders"]);
  browser.webRequest.onErrorOccurred.addListener(onErrorOccurred, filter);

  captures.set(captureId, {
    onBeforeRequest: onBeforeRequest,
    onSendHeaders: onSendHeaders,
    onHeadersReceived: onHeadersReceived,
    onCompleted: onCompleted,
    onErrorOccurred: onErrorOccurred,
  });
  return { started: true, capture_id: captureId };
}

function stopCapture(params) {
  const captureId = params.capture_id;
  const entry = captures.get(captureId);
  if (!entry) return { stopped: false, capture_id: captureId };
  try { browser.webRequest.onBeforeRequest.removeListener(entry.onBeforeRequest); } catch (e) {}
  try { browser.webRequest.onSendHeaders.removeListener(entry.onSendHeaders); } catch (e) {}
  try { browser.webRequest.onHeadersReceived.removeListener(entry.onHeadersReceived); } catch (e) {}
  try { browser.webRequest.onCompleted.removeListener(entry.onCompleted); } catch (e) {}
  try { browser.webRequest.onErrorOccurred.removeListener(entry.onErrorOccurred); } catch (e) {}
  captures.delete(captureId);
  return { stopped: true, capture_id: captureId };
}

async function registerInitScript(params) {
  const scriptId = params.script_id;
  const source = params.source;
  if (typeof scriptId !== "string" || !scriptId) {
    throw new Error("init_script.register: missing script_id");
  }
  if (typeof source !== "string" || !source) {
    throw new Error("init_script.register: missing source");
  }
  if (initScripts.has(scriptId)) {
    throw new Error("init_script.register: duplicate script_id " + scriptId);
  }
  const handle = await browser.contentScripts.register({
    matches: ["<all_urls>"],
    js: [{ code: source }],
    runAt: "document_start",
    allFrames: true,
  });
  initScripts.set(scriptId, handle);
  return { registered: true, script_id: scriptId };
}

function unregisterInitScript(params) {
  const scriptId = params.script_id;
  const handle = initScripts.get(scriptId);
  if (!handle) return { removed: false, script_id: scriptId };
  try { handle.unregister(); } catch (e) {}
  initScripts.delete(scriptId);
  return { removed: true, script_id: scriptId };
}

async function dispatchRequest(req) {
  const method = req.method;
  const params = req.params || {};
  switch (method) {
    case "ping":
      return { pong: true };
    case "capture.start":
      return startCapture(params);
    case "capture.stop":
      return stopCapture(params);
    case "init_script.register":
      return await registerInitScript(params);
    case "init_script.unregister":
      return unregisterInitScript(params);
    default:
      const err = new Error("unknown method: " + method);
      err._code = "unknown_method";
      throw err;
  }
}

async function handleRequest(req, base, headers) {
  let body;
  try {
    const result = await dispatchRequest(req);
    body = { id: req.id, result: result };
  } catch (e) {
    body = {
      id: req.id,
      error: {
        code: (e && e._code) || "handler_error",
        message: e ? String(e.message || e) : "unknown error",
      },
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

  bridgeBase = "http://" + config.bridge_host + ":" + config.bridge_port;
  bridgeHeaders = {
    "Authorization": "Bearer " + config.token,
    "Content-Type": "application/json",
  };

  let hello;
  try {
    hello = await fetch(bridgeBase + "/hello", {
      method: "POST",
      headers: bridgeHeaders,
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
  logInfo("bridge connected at", bridgeBase);

  while (true) {
    let resp;
    try {
      resp = await fetch(bridgeBase + "/poll", { method: "GET", headers: bridgeHeaders });
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
    handleRequest(req, bridgeBase, bridgeHeaders).catch(function (e) {
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
