"use strict";

// The driver installs this extension into a permanent-private-browsing
// profile after granting internal:privateBrowsingAllowed on the gecko
// id, so Firefox's ext-backgroundPage onManifestEntry hook actually
// instantiates the background page. With that grant in place
// "persistent": true gives a real persistent page; the synchronous
// listener registrations below and the alarms keepalive are defensive
// in case a future Firefox build tightens event-page suspension.

const POLL_BACKOFF_MS = 1000;
const EXTENSION_VERSION = "0.1.0";
const KEEPALIVE_ALARM = "tbm-helper-keepalive";

let started = false;
let bridgeBase = null;
let bridgeHeaders = null;

const captures = new Map();
const initScripts = new Map();
// Driver-controlled route table. Keyed by route_id. The blocking
// listeners walk this in (descending priority, ascending insertion
// index) order and apply the first matching entry.
const routes = new Map();
// Active state for browser_network_state_set. When true, the offline
// listener is installed and cancels every new request.
let offlineActive = false;
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

function compareRoutes(a, b) {
  if (a.priority !== b.priority) return b.priority - a.priority;
  return a.insertion_index - b.insertion_index;
}

function orderedRoutes() {
  return Array.from(routes.values()).sort(compareRoutes);
}

// WebExtension match-pattern matching, JS port. Accepts the literal
// "<all_urls>" plus the documented <scheme>://<host><path> shapes
// (schemes: *, http, https, ws, wss, ftp, file; host: *, *.<suffix>,
// literal, or empty for file://; path is a glob where * matches any
// number of characters). Mirrors validate_match_pattern on the
// driver side -- anything that side accepts must match here.
function parsePattern(pattern) {
  if (pattern === "<all_urls>") {
    return { all: true };
  }
  const schemeEnd = pattern.indexOf("://");
  if (schemeEnd <= 0) return null;
  const scheme = pattern.slice(0, schemeEnd);
  const rest = pattern.slice(schemeEnd + 3);
  const pathStart = rest.indexOf("/");
  if (pathStart < 0) return null;
  const host = rest.slice(0, pathStart);
  const path = rest.slice(pathStart);
  return { all: false, scheme: scheme, host: host, path: path };
}

function schemeMatches(parsedScheme, urlScheme) {
  if (parsedScheme === "*") return urlScheme === "http" || urlScheme === "https" || urlScheme === "ws" || urlScheme === "wss" || urlScheme === "ftp";
  return parsedScheme === urlScheme;
}

function hostMatches(parsedHost, urlHost) {
  if (parsedHost === "*") return true;
  if (parsedHost === "") return urlHost === "";
  if (parsedHost.startsWith("*.")) {
    const suffix = parsedHost.slice(2);
    return urlHost === suffix || urlHost.endsWith("." + suffix);
  }
  return parsedHost === urlHost;
}

function globMatches(pattern, value) {
  // Convert glob (only * wildcard) to anchored regex.
  let re = "^";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "*") {
      re += ".*";
    } else if ("\\.^$+?()[]{}|/".indexOf(ch) >= 0) {
      re += "\\" + ch;
    } else {
      re += ch;
    }
  }
  re += "$";
  return new RegExp(re).test(value);
}

function matchPattern(url, pattern) {
  const parsed = parsePattern(pattern);
  if (!parsed) return false;
  if (parsed.all) {
    return url.startsWith("http://") || url.startsWith("https://") ||
           url.startsWith("ws://") || url.startsWith("wss://") ||
           url.startsWith("ftp://") || url.startsWith("file://");
  }
  let parsedUrl;
  try { parsedUrl = new URL(url); } catch (e) { return false; }
  const urlScheme = parsedUrl.protocol.replace(/:$/, "");
  if (!schemeMatches(parsed.scheme, urlScheme)) return false;
  if (!hostMatches(parsed.host, parsedUrl.hostname)) return false;
  const urlPath = parsedUrl.pathname + parsedUrl.search;
  return globMatches(parsed.path, urlPath);
}

function findRouteForMode(url, modes) {
  for (const route of orderedRoutes()) {
    if (modes.indexOf(route.mode) < 0) continue;
    if (matchPattern(url, route.pattern)) return route;
  }
  return null;
}

function isBridgeUrl(url) {
  return bridgeBase != null && typeof url === "string" && url.indexOf(bridgeBase) === 0;
}

function routeOnBeforeRequest(details) {
  if (isBridgeUrl(details.url)) return undefined;
  const route = findRouteForMode(details.url, ["mock", "redirect"]);
  if (!route) return undefined;
  return { redirectUrl: route.redirect_url };
}

function applyHeaderEdits(headerList, setMap, removeList) {
  // Case-insensitive remove, then set (replacing existing names case-
  // insensitively, appending otherwise). Returns a new array.
  const removeLower = (removeList || []).map(function (n) { return String(n).toLowerCase(); });
  let kept = (headerList || []).filter(function (h) {
    return removeLower.indexOf(String(h.name).toLowerCase()) < 0;
  });
  if (setMap) {
    for (const name of Object.keys(setMap)) {
      const value = String(setMap[name]);
      const lowerName = name.toLowerCase();
      let replaced = false;
      kept = kept.map(function (h) {
        if (String(h.name).toLowerCase() === lowerName) {
          replaced = true;
          return { name: h.name, value: value };
        }
        return h;
      });
      if (!replaced) {
        kept.push({ name: name, value: value });
      }
    }
  }
  return kept;
}

function routeOnBeforeSendHeaders(details) {
  if (isBridgeUrl(details.url)) return undefined;
  const route = findRouteForMode(details.url, ["headers"]);
  if (!route) return undefined;
  if (!route.set_request_headers && (!route.remove_request_headers || route.remove_request_headers.length === 0)) {
    return undefined;
  }
  return {
    requestHeaders: applyHeaderEdits(
      details.requestHeaders,
      route.set_request_headers,
      route.remove_request_headers
    ),
  };
}

function routeOnHeadersReceived(details) {
  if (isBridgeUrl(details.url)) return undefined;
  const route = findRouteForMode(details.url, ["headers"]);
  if (!route) return undefined;
  if (!route.set_response_headers && (!route.remove_response_headers || route.remove_response_headers.length === 0)) {
    return undefined;
  }
  return {
    responseHeaders: applyHeaderEdits(
      details.responseHeaders,
      route.set_response_headers,
      route.remove_response_headers
    ),
  };
}

function offlineOnBeforeRequest(details) {
  // The extension's own long-poll traffic to the driver-side bridge
  // must continue while offline is engaged; otherwise the call that
  // toggles state back to online cannot be delivered.
  if (isBridgeUrl(details.url)) return undefined;
  return { cancel: true };
}

function addRoute(params) {
  const routeId = params.route_id;
  if (typeof routeId !== "string" || !routeId) {
    throw new Error("route.add: missing route_id");
  }
  routes.set(routeId, {
    route_id: routeId,
    pattern: String(params.pattern || ""),
    mode: String(params.mode || ""),
    priority: typeof params.priority === "number" ? params.priority : 0,
    insertion_index: typeof params.insertion_index === "number" ? params.insertion_index : 0,
    redirect_url: params.redirect_url || null,
    set_request_headers: params.set_request_headers || null,
    remove_request_headers: params.remove_request_headers || null,
    set_response_headers: params.set_response_headers || null,
    remove_response_headers: params.remove_response_headers || null,
  });
  return { added: true, route_id: routeId, count: routes.size };
}

function removeRoute(params) {
  const ids = Array.isArray(params.route_ids) ? params.route_ids : [];
  let removed = 0;
  for (const id of ids) {
    if (routes.delete(id)) removed += 1;
  }
  return { removed: removed, count: routes.size };
}

function listRoutes() {
  return { routes: orderedRoutes().map(function (r) {
    return {
      route_id: r.route_id,
      pattern: r.pattern,
      mode: r.mode,
      priority: r.priority,
      insertion_index: r.insertion_index,
    };
  }) };
}

function clearRoutes() {
  const n = routes.size;
  routes.clear();
  return { removed: n };
}

function setNetworkState(params) {
  const state = params && params.state;
  if (state !== "online" && state !== "offline") {
    const err = new Error("network_state.set: invalid state " + JSON.stringify(state));
    err._code = "invalid_state";
    throw err;
  }
  if (state === "offline" && !offlineActive) {
    browser.webRequest.onBeforeRequest.addListener(
      offlineOnBeforeRequest,
      { urls: ["<all_urls>"] },
      ["blocking"]
    );
    offlineActive = true;
  } else if (state === "online" && offlineActive) {
    try { browser.webRequest.onBeforeRequest.removeListener(offlineOnBeforeRequest); } catch (e) {}
    offlineActive = false;
  }
  return { state: state };
}

// Register the routing listeners once at module-parse time. They are
// no-ops when the route table is empty; registering once avoids the
// add/remove churn that would otherwise tear down the listener every
// time the route table empties.
browser.webRequest.onBeforeRequest.addListener(
  routeOnBeforeRequest,
  { urls: ["<all_urls>"] },
  ["blocking"]
);
browser.webRequest.onBeforeSendHeaders.addListener(
  routeOnBeforeSendHeaders,
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);
browser.webRequest.onHeadersReceived.addListener(
  routeOnHeadersReceived,
  { urls: ["<all_urls>"] },
  ["blocking", "responseHeaders"]
);

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
    case "route.add":
      return addRoute(params);
    case "route.remove":
      return removeRoute(params);
    case "route.list":
      return listRoutes();
    case "route.clear":
      return clearRoutes();
    case "network_state.set":
      return setNetworkState(params);
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

  // Keepalive alarm. Defensive: with internal:privateBrowsingAllowed
  // granted on the current build the background page is persistent,
  // but a periodic alarm tick would also reset event-page suspension
  // if a future Firefox build re-enables it.
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

// Synchronous listener registrations. Defensive in case a future
// Firefox build downgrades persistent MV2 backgrounds to event pages;
// listeners registered at module-parse time are what such builds use
// to decide when to revive a suspended page.
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

// On the current build persistent: true means the script runs at
// install time and this path wins; the runtime.onStartup /
// runtime.onInstalled / alarms paths above remain as fallbacks.
startup().catch(logError);
