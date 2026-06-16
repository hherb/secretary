// Content script — runs in the page, gathers the origins the host will need,
// and asks the background service worker to run a native-messaging query. It
// logs the availability count it gets back. No DOM is touched, nothing is
// filled; this is purely the page-side trigger for the D.4.1 round trip.
//
// NOTE: this file is loaded as a *classic* content script (not an ES module),
// so it must have no top-level `import`/`export`. The IIFE keeps its bindings
// out of the page's global scope.

(() => {
  const topOrigin = window.location.origin;
  // In a top-level document `frame_origin === top_origin`. Real iframe origin
  // handling (and the PSL / binding rules) is D.4.3, not this skeleton.
  const frameOrigin = window.location.origin;
  const https = window.location.protocol === "https:";

  chrome.runtime.sendMessage(
    {
      kind: "secretary-query",
      top_origin: topOrigin,
      frame_origin: frameOrigin,
      https,
    },
    (response: { ok: boolean; reply?: unknown; error?: string } | undefined) => {
      if (chrome.runtime.lastError) {
        console.error(
          "[secretary] query failed:",
          chrome.runtime.lastError.message,
        );
        return;
      }
      if (response?.ok) {
        console.log("[secretary] host responded:", response.reply);
      } else {
        console.error("[secretary] host error:", response?.error);
      }
    },
  );
})();
