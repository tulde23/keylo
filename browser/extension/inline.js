// The Keylo icon in sign-in fields. Runs on https pages (and http://localhost) in the extension's
// isolated world, top frame only.
//
// - Finds the sign-in form's username and password fields, and shows a small Keylo icon in them when
//   Keylo has a login for the site (or is locked). It asks Keylo only once a page has such a field.
// - Clicking the icon opens Keylo's menu: an extension page in a frame, inside a closed shadow root,
//   at a per-session random address. The page can't read, script or reuse it. Filling happens only
//   from a click in that menu; Keylo still checks the page's address before releasing anything.
// - Nothing is shown in browsers driven by automation (navigator.webdriver).
"use strict";

(() => {
  if (window.top !== window || navigator.webdriver || window.__keyloInline) return;
  window.__keyloInline = true;

  const ICON = `<svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true">
    <rect x="1" y="1" width="18" height="18" rx="5" fill="#6d28d9"/>
    <circle cx="8" cy="9" r="3.2" fill="none" stroke="#fff" stroke-width="1.8"/>
    <path d="M10.6 10.6 15 15 M13 13l1.6-1.6" stroke="#fff" stroke-width="1.8" stroke-linecap="round" fill="none"/>
  </svg>`;

  // One host element for everything Keylo draws; its closed shadow root keeps the page out.
  const host = document.createElement("keylo-inline");
  host.style.cssText = "all: initial; position: fixed; inset: 0 auto auto 0; width: 0; height: 0; z-index: 2147483647;";
  const root = host.attachShadow({ mode: "closed" });
  root.innerHTML = `<style>
    .icon { position: fixed; width: 22px; height: 22px; padding: 2px; border: 0; margin: 0; background: transparent;
            cursor: pointer; border-radius: 6px; display: none; line-height: 0; }
    .icon:hover { background: rgba(109, 40, 217, 0.12); }
    .menu { position: fixed; width: 320px; height: 236px; border: 0; border-radius: 10px; display: none;
            box-shadow: 0 10px 40px rgba(20, 20, 40, 0.28); color-scheme: normal; }
  </style>`;
  const menu = document.createElement("iframe");
  menu.className = "menu";
  menu.setAttribute("title", "Keylo");
  root.append(menu);

  let fields = [];      // inputs that get an icon
  const icons = new Map(); // input → icon button
  let state = null;     // {count, locked} from Keylo for this page, or null (unknown / unreachable)
  let asked = false;
  let openFor = null;   // the input whose menu is open

  const usable = (el) => {
    if (!el || el.disabled || el.readOnly || !el.isConnected) return false;
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width >= 60 && r.height >= 16 && s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
  };

  /** The sign-in fields on the page: the password field and its username field, or a username-first field. */
  function findFields() {
    const pick = (sel, root = document) => [...root.querySelectorAll(sel)].filter(usable);
    const pw = pick('input[autocomplete~="current-password"]')[0] || pick('input[type="password"]').filter((e) => e.autocomplete !== "new-password")[0];
    const textish = 'input[type="email"], input[type="text"], input[type="tel"], input:not([type])';
    let user = pick('input[autocomplete~="username"]')[0];
    if (!user && pw) {
      user = pick(textish, pw.form || document).filter((e) => e.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING).pop();
    }
    if (!user && !pw) {
      // A username-first page: an email or username field inside a form.
      user = pick(textish).find((e) => e.form && /user|email|login|identifier/i.test(`${e.name} ${e.id} ${e.autocomplete}`));
    }
    return [user, pw].filter(Boolean);
  }

  function place() {
    for (const [input, icon] of icons) {
      if (!usable(input) || !state || !(state.count > 0 || state.locked)) {
        icon.style.display = "none";
        continue;
      }
      const r = input.getBoundingClientRect();
      icon.style.display = "block";
      icon.style.left = `${Math.round(r.right - 28)}px`;
      icon.style.top = `${Math.round(r.top + (r.height - 22) / 2)}px`;
    }
    if (openFor) {
      if (!usable(openFor)) return closeMenu();
      const r = openFor.getBoundingClientRect();
      const below = r.bottom + 6 + 236 <= window.innerHeight;
      menu.style.left = `${Math.round(Math.min(Math.max(8, r.right - 320), window.innerWidth - 328))}px`;
      menu.style.top = `${Math.round(below ? r.bottom + 6 : Math.max(8, r.top - 242))}px`;
    }
  }

  let placing = false;
  function schedulePlace() {
    if (placing) return;
    placing = true;
    requestAnimationFrame(() => { placing = false; place(); });
  }

  function openMenu(input) {
    openFor = input;
    // A fresh frame each time: the menu loads this page's logins when it opens.
    menu.src = chrome.runtime.getURL("menu.html");
    menu.style.display = "block";
    place();
  }

  function closeMenu() {
    openFor = null;
    menu.style.display = "none";
    menu.removeAttribute("src");
  }

  function scan() {
    const found = findFields();
    if (found.length && !host.isConnected) document.documentElement.append(host);
    for (const [input, icon] of icons) {
      if (!found.includes(input)) {
        icon.remove();
        icons.delete(input);
      }
    }
    for (const input of found) {
      if (icons.has(input)) continue;
      const icon = document.createElement("button");
      icon.className = "icon";
      icon.type = "button";
      icon.title = "Keylo";
      icon.setAttribute("aria-label", "Fill with Keylo");
      icon.innerHTML = ICON;
      icon.addEventListener("mousedown", (e) => e.preventDefault()); // keep focus in the field
      icon.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!e.isTrusted) return;
        if (openFor === input) closeMenu();
        else openMenu(input);
      });
      root.append(icon);
      icons.set(input, icon);
    }
    fields = found;
    if (fields.length && !asked) {
      asked = true;
      chrome.runtime.sendMessage({ type: "page-state" }, (reply) => {
        if (chrome.runtime.lastError || !reply || reply.error) return; // Keylo isn't reachable: no icons
        state = reply;
        schedulePlace();
      });
    }
    schedulePlace();
  }

  // The menu (via the background worker) asks to close, e.g. after filling or on Esc.
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "keylo-close-menu") closeMenu();
    if (msg && msg.type === "keylo-state") {
      state = msg.state;
      schedulePlace();
    }
  });

  // Clicking anywhere else, or Esc in the page, closes the menu.
  document.addEventListener("mousedown", (e) => { if (openFor && e.target !== host) closeMenu(); }, true);
  document.addEventListener("keydown", (e) => { if (openFor && e.key === "Escape") closeMenu(); }, true);
  window.addEventListener("scroll", schedulePlace, true);
  window.addEventListener("resize", schedulePlace);

  let pending;
  new MutationObserver(() => {
    clearTimeout(pending);
    pending = setTimeout(scan, 300);
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["type", "style", "class", "hidden"] });
  scan();
})();
