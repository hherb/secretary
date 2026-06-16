// MV3 service worker — the extension half of the native-messaging round trip.
//
// On a request from the content script it opens a one-shot native-messaging
// port to the Secretary host (via `queryHost`), logs the `available` reply, and
// posts the result back. There is no socket and no persistent connection: the
// port lives only for the round trip. No secrets and no fill — the host returns
// only a count.
//
// The message logic lives in `./messaging.ts` so it is unit-testable without a
// browser; this file is the thin `chrome.runtime` wiring.

// NOTE: the `.js` extension is required — the emitted module SW resolves the
// specifier verbatim in the browser, and native ES modules need the extension.
// TS (`moduleResolution: bundler`) maps `./messaging.js` back to `messaging.ts`.
import { isQueryRequest, queryHost, type QueryResult } from "./messaging.js";

chrome.runtime.onMessage.addListener(
  (message: unknown, _sender, sendResponse: (result: QueryResult) => void) => {
    if (!isQueryRequest(message)) {
      return false; // not ours — let other listeners handle it
    }
    queryHost(chrome.runtime, message)
      .then((reply) => {
        console.log("[secretary] available reply:", reply);
        sendResponse({ ok: true, reply });
      })
      .catch((err: unknown) => sendResponse({ ok: false, error: String(err) }));
    return true; // keep the message channel open for the async sendResponse
  },
);
