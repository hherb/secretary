// Vitest setup — runs once before each test file. Polyfills JSDOM gaps
// that real browsers cover so component tests can mount the same UI
// code the production build runs.
//
// HTMLDialogElement.showModal / close: JSDOM 25 has the <dialog>
// element but not the imperative API (open issue:
// https://github.com/jsdom/jsdom/issues/3294). SettingsDialog and any
// future modal dialogs call showModal() / close() to toggle the open
// state. The polyfill mirrors the spec semantics narrowly enough for
// component tests: setting / clearing the `open` attribute, firing the
// `close` event on .close().

if (typeof HTMLDialogElement !== 'undefined') {
  const proto = HTMLDialogElement.prototype;

  if (typeof proto.showModal !== 'function') {
    proto.showModal = function showModal(this: HTMLDialogElement) {
      this.setAttribute('open', '');
    };
  }

  if (typeof proto.show !== 'function') {
    proto.show = function show(this: HTMLDialogElement) {
      this.setAttribute('open', '');
    };
  }

  if (typeof proto.close !== 'function') {
    proto.close = function close(this: HTMLDialogElement, returnValue?: string) {
      if (typeof returnValue === 'string') {
        this.setAttribute('returnValue', returnValue);
      }
      // Only fire `close` when the dialog was actually open — matches
      // the HTMLDialogElement spec (no spurious event on a closed-then-
      // re-closed dialog) and avoids the polyfill diverging from real
      // browsers in test code that handles the close event.
      const wasOpen = this.hasAttribute('open');
      this.removeAttribute('open');
      if (wasOpen) {
        this.dispatchEvent(new Event('close'));
      }
    };
  }
}
