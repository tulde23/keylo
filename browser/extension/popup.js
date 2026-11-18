// The toolbar popup: this site's logins (fill, copy), search across all logins (copy), unlock, and a
// password generator. Values come from Keylo only for a fill (checked against this site) or a copy.
"use strict";

const $ = (id) => document.getElementById(id);
let tab = null;

function say(text, error = false) {
  const m = $("message");
  m.textContent = text;
  m.className = error ? "error" : "";
  m.hidden = !text;
}

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  Object.assign(e, props);
  for (const c of children) e.append(c);
  return e;
}

function host(url) {
  try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return ""; }
}

/** A login row: fill (when it belongs to this page) and copy buttons. */
function loginRow(login, fillable) {
  const actions = [];
  if (fillable) {
    actions.push(el("button", { className: "primary", textContent: "Fill", title: "Fill the username and password", onclick: () => fill(login) }));
  }
  if (login.username) actions.push(el("button", { className: "icon", textContent: "User", title: "Copy the username", onclick: () => copy(login, "username") }));
  actions.push(el("button", { className: "icon", textContent: "Pass", title: "Copy the password", onclick: () => copy(login, "password") }));
  if (login.hasCode) actions.push(el("button", { className: "icon", textContent: "Code", title: "Copy the one-time code", onclick: () => copy(login, "code") }));
  const sub = [login.username, login.url && host(login.url)].filter(Boolean).join(" · ");
  return el("li", { className: "login" },
    el("div", { className: "text" }, el("div", { className: "name", textContent: login.name }), el("div", { className: "sub", textContent: sub })),
    ...actions);
}

async function fill(login) {
  say("Filling… confirm in Keylo if it asks.");
  try {
    const r = await keylo.fill(tab, login.name);
    if (!r.ok) return say(r.error, true);
    window.close();
  } catch (e) {
    say(e.message, true);
  }
}

async function copy(login, field) {
  say(field === "username" ? "Copying…" : "Copying… confirm in Keylo if it asks.");
  try {
    const r = await keylo.ask("copy", { name: login.name, field });
    say(`Copied. The clipboard clears in ${r.seconds}s.`);
  } catch (e) {
    say(e.message, true);
  }
}

function showUnreachable(e) {
  $("main").replaceChildren(el("div", { className: "panel" },
    el("p", { textContent: "The extension can't reach Keylo." }),
    el("p", { className: "muted", textContent: "Install Keylo, then in Keylo open Settings → Browser and connect this browser (or run: keylo browser connect). Restart the browser afterwards." }),
    el("p", { className: "muted mono", textContent: e.message })));
}

function showLocked(verifier) {
  $("main").replaceChildren(el("div", { className: "panel" },
    el("p", { textContent: "Keylo is locked." }),
    el("button", { className: "primary", textContent: `Unlock with ${verifier || "your identity check"}`, onclick: unlock })));
  $("search-area").hidden = true;
}

async function unlock() {
  say("Confirm in the prompt…");
  try {
    await keylo.ask("unlock");
    say("");
    load();
  } catch (e) {
    say(e.message, true);
  }
}

async function load() {
  let status;
  try {
    status = await keylo.ask("status");
  } catch (e) {
    if (e.unreachable) return showUnreachable(e);
    return say(e.message, true);
  }
  if (!status.unlocked) return showLocked(status.verifier);

  $("search-area").hidden = false;
  const main = $("main");
  if (!tab || !/^https?:/.test(tab.url || "")) {
    main.replaceChildren(el("p", { className: "muted", textContent: "Open a website to fill its login. You can still search and copy." }));
    return;
  }
  try {
    const { logins, fillable } = await keylo.ask("logins", { url: tab.url });
    if (!fillable) {
      main.replaceChildren(el("p", { className: "muted", textContent: "This page isn't secure (not https), so Keylo won't fill it." }));
    } else if (logins.length === 0) {
      main.replaceChildren(el("p", { className: "muted", textContent: `No logins for ${host(tab.url)}. Search below to copy one.` }));
    } else {
      main.replaceChildren(el("h2", { textContent: "For this site" }), el("ul", { className: "logins" }, ...logins.map((l) => loginRow(l, true))));
    }
  } catch (e) {
    if (e.locked) return showLocked(status.verifier);
    say(e.message, true);
  }
}

let searchTimer;
$("search").addEventListener("input", (event) => {
  clearTimeout(searchTimer);
  const query = event.target.value.trim();
  searchTimer = setTimeout(async () => {
    if (!query) return $("results").replaceChildren();
    try {
      const { logins } = await keylo.ask("search", { query });
      // Found by search: copy only (filling is for logins that belong to this page).
      $("results").replaceChildren(...(logins.length ? logins.map((l) => loginRow(l, false)) : [el("li", { className: "muted", textContent: "No matches." })]));
    } catch (e) {
      say(e.message, true);
    }
  }, 200);
});

$("generate").addEventListener("click", async () => {
  try {
    const { password } = await keylo.ask("generate", { length: 20, symbols: true });
    const g = $("generated");
    g.textContent = password;
    g.hidden = false;
    await navigator.clipboard.writeText(password);
    say("Generated and copied. Save it in Keylo once you've used it.");
  } catch (e) {
    say(e.message, true);
  }
});

(async () => {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  $("site").textContent = tab && tab.url ? host(tab.url) : "";
  load();
})();
