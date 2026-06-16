// Testable core of the extension's native-messaging logic, decoupled from the
// `chrome` global so it can be unit-tested in Node (vitest) without a browser.
//
// `background.ts` wires these to the real `chrome.runtime`; `content.ts` mirrors
// `collectQuery` inline (a content script cannot `import`, as it loads as a
// classic script — keep the two in sync).

/** Native-messaging host name; must match the installed host manifest `name`. */
export const HOST_NAME = "com.secretary.browser_host";

/** Message the content script posts to the background worker. */
export interface QueryRequest {
  kind: "secretary-query";
  top_origin: string;
  frame_origin: string;
  https: boolean;
}

/** Reply the background worker posts back to the content script. */
export interface QueryResult {
  ok: boolean;
  reply?: unknown;
  error?: string;
}

/** Narrow a `chrome.runtime.onMessage` payload to our request shape. */
export function isQueryRequest(msg: unknown): msg is QueryRequest {
  return (
    typeof msg === "object" &&
    msg !== null &&
    (msg as { kind?: unknown }).kind === "secretary-query"
  );
}

/** The subset of a page `Location` the host needs. */
export interface PageLocation {
  origin: string;
  protocol: string;
}

/**
 * Build the `query` request from the page location. In a top-level document
 * `frame_origin === top_origin`; real iframe/PSL handling is D.4.3.
 */
export function collectQuery(loc: PageLocation): QueryRequest {
  return {
    kind: "secretary-query",
    top_origin: loc.origin,
    frame_origin: loc.origin,
    https: loc.protocol === "https:",
  };
}

// Minimal structural types for the native port, so `queryHost` is testable with
// a fake and does not depend on the `@types/chrome` global at all.
export interface PortLike {
  onMessage: { addListener(cb: (msg: unknown) => void): void };
  onDisconnect: { addListener(cb: () => void): void };
  postMessage(msg: unknown): void;
  disconnect(): void;
}

export interface RuntimeLike {
  connectNative(name: string): PortLike;
  lastError?: { message?: string };
}

/**
 * Open a one-shot native-messaging port, send the `query`, and resolve with the
 * first reply frame. The port is always disconnected before resolving so the
 * host process can exit. A disconnect before any reply rejects with the
 * `lastError` (e.g. host not installed / manifest not bound).
 */
export function queryHost(runtime: RuntimeLike, req: QueryRequest): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const port = runtime.connectNative(HOST_NAME);
    let settled = false;

    port.onMessage.addListener((reply: unknown) => {
      settled = true;
      resolve(reply);
      port.disconnect();
    });

    port.onDisconnect.addListener(() => {
      if (!settled) {
        reject(new Error(runtime.lastError?.message ?? "native host disconnected"));
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
