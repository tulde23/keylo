// The menu under the Keylo icon in a sign-in field (an extension page in a frame the page can't
// reach). Lists this page's logins; a click fills one. Talks to Keylo through the background worker,
// which knows which tab and page this frame is in.
"use strict";

const $ = (id) => document.getElementById(id);

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

function send(type, fields = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, ...fields }, (reply) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!reply || reply.error) {
        const e = new Error((reply && reply.error) || "Keylo didn't answer.");
        e.locked = !!(reply && reply.locked);
        return reject(e);
      }
      resolve(reply);
    });
  });
}

// Clickjacking: a page could make this frame invisible or cover it and trick a click. Chrome reports
// whether the frame is actually visible (IntersectionObserver v2); fill only when it is.
let visible = true;
try {
  const io = new IntersectionObserver((entries) => {
    const last = entries[entries.length - 1];
    if (typeof last.isVisible === "boolean") visible = last.isVisible;
  }, { trackVisibility: true, delay: 100 });
  io.observe(document.documentElement);
} catch {
  // Not supported (Firefox): rely on the other checks.
}

async function fill(login) {
  if (!visible) return say("Keylo's menu is covered or hidden on this page, so it won't fill. Use the toolbar button instead.", true);
  say("Filling… confirm in Keylo if it asks.");
  try {
    const r = await send("menu-fill", { name: login.name });
    if (!r.ok) say(r.error || "Couldn't fill.", true);
  } catch (e) {
    say(e.message, true);
  }
}

function row(login) {
  const li = el("li", { className: "login", tabIndex: 0, title: `Fill ${login.name}` },
    el("div", { className: "text" },
      el("div", { className: "name", textContent: login.name }),
      el("div", { className: "sub", textContent: login.username || "" })));
  li.addEventListener("click", (e) => { if (e.isTrusted) fill(login); });
  li.addEventListener("keydown", (e) => { if (e.isTrusted && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); fill(login); } });
  return li;
}

async function load() {
  try {
    const r = await send("menu-logins");
    $("site").textContent = r.site || "";
    if (r.locked) {
      $("main").replaceChildren(el("div", { className: "panel" },
        el("p", { textContent: "Keylo is locked." }),
        el("button", { className: "primary", textContent: `Unlock with ${r.verifier || "your identity check"}`, onclick: unlock })));
      return;
    }
    if (!r.logins.length) {
      $("main").replaceChildren(el("p", { className: "muted", textContent: "No logins for this site." }));
      return;
    }
    const list = el("ul", { className: "logins" }, ...r.logins.map(row));
    $("main").replaceChildren(list);
    list.firstChild.focus();
  } catch (e) {
    say(e.message, true);
  }
}

async function unlock() {
  say("Confirm in the prompt…");
  try {
    await send("menu-unlock");
    say("");
    load();
  } catch (e) {
    say(e.message, true);
  }
}

document.addEventListener("keydown", (e) => { if (e.key === "Escape") send("menu-close").catch(() => {}); });
load();
