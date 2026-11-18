// Shared by the popup and the background worker: talking to Keylo (native messaging) and filling a
// page's sign-in form.
"use strict";

const keylo = (() => {
  const HOST = "io.github.tulde23.keylo";
  let next = 1;

  /** One request to Keylo. Resolves with the reply; rejects with an Error (err.locked when Keylo is locked). */
  function ask(type, fields = {}) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendNativeMessage(HOST, { id: next++, type, ...fields }, (reply) => {
        const failure = chrome.runtime.lastError;
        if (failure) {
          const e = new Error(failure.message || String(failure));
          e.unreachable = true;
          return reject(e);
        }
        if (!reply || !reply.ok) {
          const e = new Error((reply && reply.error) || "Keylo didn't answer.");
          e.locked = !!(reply && reply.locked);
          return reject(e);
        }
        resolve(reply);
      });
    });
  }

  /**
   * Runs in the page (the extension's isolated world, top frame only): fills the sign-in form's
   * username and password. Returns {ok, error?}. Refuses in browsers driven by automation (agents,
   * Playwright, Selenium), which set navigator.webdriver.
   */
  function fillForm(username, password) {
    if (navigator.webdriver) {
      return { ok: false, error: "This browser is controlled by automation (an agent or a test tool), so Keylo won't fill it." };
    }
    const usable = (el) => {
      if (!el || el.disabled || el.readOnly) return false;
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
    };
    const all = (sel, root = document) => [...root.querySelectorAll(sel)].filter(usable);
    const set = (el, value) => {
      el.focus();
      // The native setter, so frameworks (React, Vue) see the change.
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, value);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    };

    const pw = all('input[autocomplete~="current-password"]')[0] || all('input[type="password"]')[0] || null;
    const textish = 'input[type="email"], input[type="text"], input[type="tel"], input:not([type])';
    let user = all('input[autocomplete~="username"], input[autocomplete~="email"]')[0] || null;
    if (!user) {
      const scope = (pw && pw.form) || document;
      const candidates = all(textish, scope);
      user = pw
        // The last text field before the password field.
        ? candidates.filter((e) => e.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING).pop() || null
        // A username-first page (the password comes on the next step).
        : candidates.find((e) => /user|email|login|account|identifier/i.test(`${e.name} ${e.id} ${e.autocomplete}`)) || null;
    }
    if (!pw && !user) return { ok: false, error: "No sign-in form was found on this page." };
    if (user && username) set(user, username);
    if (pw && password) set(pw, password);
    (pw || user).focus();
    return { ok: true, password: !!pw };
  }

  /** Fills `login` (by name) into the active tab, after Keylo checks it belongs to the tab's site. */
  async function fill(tab, name) {
    const values = await ask("fill", { name, url: tab.url });
    try {
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [0] },
        func: fillForm,
        args: [values.username, values.password],
      });
      return (result && result.result) || { ok: false, error: "The page didn't respond." };
    } finally {
      values.password = "";
    }
  }

  return { ask, fill };
})();
