// MV3 service worker — the extension half of the D.4.1 native-messaging
// walking skeleton.
//
// On a request from the content script it opens a native-messaging port to the
// Secretary host, forwards a `query` describing the page's origins, logs the
// `available` reply, and tears the port down. There is no socket and no
// persistent connection: the port lives only for the round trip. No secrets and
// no fill — D.4.1 only proves the channel.

const HOST_NAME = "com.secretary.browser_host";

/** Message the content script posts to this worker. */
interface QueryRequest {
  kind: "secretary-query";
  top_origin: string;
  frame_origin: string;
  https: boolean;
}

/** Reply this worker posts back to the content script. */
interface QueryResult {
  ok: boolean;
  reply?: unknown;
  error?: string;
}

function isQueryRequest(msg: unknown): msg is QueryRequest {
  return (
    typeof msg === "object" &&
    msg !== null &&
    (msg as { kind?: unknown }).kind === "secretary-query"
  );
}

chrome.runtime.onMessage.addListener(
  (message: unknown, _sender, sendResponse: (result: QueryResult) => void) => {
    if (!isQueryRequest(message)) {
      return false; // not ours — let other listeners handle it
    }
    queryHost(message)
      .then((reply) => sendResponse({ ok: true, reply }))
      .catch((err: unknown) => sendResponse({ ok: false, error: String(err) }));
    return true; // keep the message channel open for the async sendResponse
  },
);

/**
 * Open a one-shot native-messaging port, send the `query`, and resolve with the
 * first reply frame. The port is always disconnected before resolving so the
 * host process can exit. A disconnect before any reply rejects with the
 * `lastError` (e.g. host not installed / manifest not bound).
 */
function queryHost(req: QueryRequest): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const port = chrome.runtime.connectNative(HOST_NAME);
    let settled = false;

    port.onMessage.addListener((reply: unknown) => {
      console.log("[secretary] available reply:", reply);
      settled = true;
      resolve(reply);
      port.disconnect();
    });

    port.onDisconnect.addListener(() => {
      const lastError = chrome.runtime.lastError;
      if (!settled) {
        reject(new Error(lastError?.message ?? "native host disconnected"));
      }
    });

    port.postMessage({
      type: "query",
      top_origin: req.top_origin,
      frame_origin: req.frame_origin,
      https: req.https,
    });
  });
}
