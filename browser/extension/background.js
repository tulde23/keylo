// The keyboard shortcut (Ctrl+Shift+L / Cmd+Shift+L): fills the site's login when there's exactly one,
// otherwise opens the popup to choose. Pressing it is the user action that allows a fill.
"use strict";

if (typeof keylo === "undefined" && typeof importScripts === "function") {
  importScripts("keylo.js");
}

chrome.commands.onCommand.addListener(async (command, commandTab) => {
  if (command !== "fill-login") return;
  const tab = commandTab || (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab || !tab.url) return;
  try {
    const { logins } = await keylo.ask("logins", { url: tab.url });
    if (logins.length === 1) {
      await keylo.fill(tab, logins[0].name);
      return;
    }
  } catch {
    // Locked, or several or no logins: the popup explains and lets you choose.
  }
  if (chrome.action.openPopup) {
    try { await chrome.action.openPopup(); } catch { /* not allowed here */ }
  }
});

// Messages from the in-field icon (content script) and its menu (an extension frame in the page).
// The menu's requests are only accepted from that frame; the page itself can't send any.
function fromMenu(sender) {
  try {
    const u = new URL(sender.url);
    return sender.id === chrome.runtime.id && /^(chrome|moz)-extension:$/.test(u.protocol) && u.pathname === "/menu.html" && sender.frameId !== 0;
  } catch {
    return false;
  }
}

function siteOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return ""; }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tab = sender.tab;
  const reply = (promise) => {
    promise.then(sendResponse, (e) => sendResponse({ error: e.message, locked: !!e.locked, unreachable: !!e.unreachable }));
    return true;
  };
  if (!tab || !msg || typeof msg.type !== "string") return false;

  // The content script: should the icon show on this page?
  if (msg.type === "page-state" && sender.frameId === 0 && sender.id === chrome.runtime.id) {
    return reply((async () => {
      try {
        const { logins } = await keylo.ask("logins", { url: tab.url });
        return { count: logins.length, locked: false };
      } catch (e) {
        if (e.locked) return { count: 0, locked: true };
        throw e;
      }
    })());
  }

  if (!msg.type.startsWith("menu-") || !fromMenu(sender)) return false;
  const close = () => chrome.tabs.sendMessage(tab.id, { type: "keylo-close-menu" }, { frameId: 0 }).catch(() => {});

  switch (msg.type) {
    case "menu-logins":
      return reply((async () => {
        try {
          const { logins } = await keylo.ask("logins", { url: tab.url });
          return { logins, site: siteOf(tab.url) };
        } catch (e) {
          if (!e.locked) throw e;
          const status = await keylo.ask("status").catch(() => ({}));
          return { locked: true, verifier: status.verifier, logins: [], site: siteOf(tab.url) };
        }
      })());
    case "menu-unlock":
      return reply((async () => {
        await keylo.ask("unlock");
        const { logins } = await keylo.ask("logins", { url: tab.url });
        chrome.tabs.sendMessage(tab.id, { type: "keylo-state", state: { count: logins.length, locked: false } }, { frameId: 0 }).catch(() => {});
        return { ok: true };
      })());
    case "menu-fill":
      return reply((async () => {
        const result = await keylo.fill(tab, String(msg.name || ""));
        if (result.ok) close();
        return result;
      })());
    case "menu-close":
      close();
      return reply(Promise.resolve({ ok: true }));
    default:
      return false;
  }
});
