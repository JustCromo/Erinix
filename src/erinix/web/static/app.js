"use strict";
/* Erinix dashboard. Plain JavaScript, no libraries, no external requests.
   Safety rule: everything that comes from the server is put on the page with
   textContent / createTextNode, NEVER as HTML, because alert text can contain
   what an attacker typed into a URL, a user name or a user agent. */
(function () {
  const POLL_MS = 3000;
  const SEVERITY = {
    low: { label: "Low", icon: "●" },
    medium: { label: "Medium", icon: "▲" },
    high: { label: "High", icon: "◆" },
    critical: { label: "Critical", icon: "✖" },
  };
  const STATES = {
    protected: { icon: "✔", label: "Protected" },
    attention: { icon: "▲", label: "Needs attention" },
    critical: { icon: "✖", label: "Critical" },
    stopped: { icon: "■", label: "Not running" },
  };
  const RESPONSE = {
    report_only: "Watch only: Erinix reports, it does not act",
    interactive: "Asks you before acting",
    auto: "Acts automatically",
  };

  const LOGIN_MESSAGES = {
    invalid: "This sign-in link was already used or is not valid.",
    expired: "This sign-in link has expired.",
    unavailable: "Erinix could not read its data. Try: erinix doctor",
  };

  const state = { overview: null, alerts: [], filter: "open", csrf: null, version: "", locked: false, error: null, open: {}, lastKey: "", loginError: "" };
  const app = document.getElementById("app");

  // ---------------------------------------------------------------- helpers
  function add(el, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) child.forEach(function (c) { add(el, c); });
    else if (child instanceof Node) el.appendChild(child);
    else el.appendChild(document.createTextNode(String(child)));
  }
  function h(tag, props) {
    const el = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (key) {
        const val = props[key];
        if (val === null || val === undefined || val === false) return;
        if (key === "class") el.className = val;
        else if (key.indexOf("on") === 0) el.addEventListener(key.slice(2), val);
        else el.setAttribute(key, val === true ? "" : String(val));
      });
    }
    for (let i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }
  function sev(name) { return SEVERITY[name] ? name : "low"; }
  function plural(n, one, many) { return n === 1 ? one : many; }
  function timeAgo(epoch) {
    const s = Math.max(0, Math.floor(Date.now() / 1000 - epoch));
    if (s < 10) return "just now";
    if (s < 60) return s + " s ago";
    if (s < 3600) return Math.floor(s / 60) + " min ago";
    if (s < 86400) return Math.floor(s / 3600) + " h ago";
    return Math.floor(s / 86400) + " d ago";
  }
  function when(epoch) { return new Date(epoch * 1000).toLocaleString(); }
  function currentView() {
    const hash = location.hash || "#/";
    if (hash.indexOf("#/alerts") === 0) return "alerts";
    if (hash.indexOf("#/sources") === 0) return "sources";
    return "overview";
  }

  // -------------------------------------------------------------------- API
  async function request(method, path, body) {
    const headers = { Accept: "application/json" };
    if (method !== "GET") { headers["Content-Type"] = "application/json"; headers["X-Erinix-CSRF"] = state.csrf || ""; }
    const res = await fetch(path, { method: method, headers: headers, credentials: "same-origin", cache: "no-store", body: body ? JSON.stringify(body) : undefined });
    if (res.status === 401) { state.locked = true; throw new Error("locked"); }
    if (!res.ok) {
      let code = "";
      try { code = (await res.json()).error || ""; } catch (e) { code = ""; }
      const err = new Error("HTTP " + res.status);
      err.code = code;
      throw err;
    }
    return res.json();
  }

  async function refresh() {
    try {
      if (!state.csrf) {
        const session = await request("GET", "/api/session");
        state.csrf = session.csrf;
        state.version = session.version || "";
      }
      state.locked = false;
      const overview = await request("GET", "/api/overview");
      let alerts = state.alerts;
      if (currentView() === "alerts") alerts = (await request("GET", "/api/alerts?status=" + encodeURIComponent(state.filter) + "&limit=100")).alerts;
      const stable = Object.assign({}, overview); delete stable.heartbeat_age;
      const key = JSON.stringify([stable, alerts, state.filter, currentView()]);
      state.overview = overview; state.alerts = alerts; state.error = null;
      if (key !== state.lastKey) { state.lastKey = key; render(); }
    } catch (err) {
      state.error = err.message === "locked" ? null : "Cannot reach Erinix. Is it running? Try: erinix ui";
      state.lastKey = "";
      render();
    }
  }

  async function setStatus(id, status) {
    try { await request("POST", "/api/alerts/" + encodeURIComponent(id) + "/status", { status: status }); }
    catch (err) { state.error = "That did not work. Please try again."; }
    state.lastKey = "";
    refresh();
  }

  // ------------------------------------------------------------------ pieces
  function badge(name) {
    const s = SEVERITY[sev(name)];
    return h("span", { class: "badge sev-" + sev(name) }, h("span", { "aria-hidden": "true" }, s.icon), s.label);
  }

  function techRow(label, value) { return [h("dt", null, label), h("dd", null, value)]; }

  function alertCard(a) {
    const t = a.technical || {};
    const progress = a.progress;
    const details = h("details", { class: "more" }, h("summary", null, "See more"),
      h("dl", { class: "tech" },
        techRow("Rule", h("span", { class: "mono" }, t.rule)),
        techRow("Type", t.kind === "chain" ? "Attack chain (several steps)" : t.kind === "engine" ? "Erinix itself" : "Single event"),
        a.remote ? techRow("Source address", h("span", { class: "mono" }, a.remote)) : null,
        t.step ? techRow("Latest step", h("span", { class: "mono" }, t.step)) : null,
        techRow("Response mode", RESPONSE[t.response] || t.response),
        t.mitre && t.mitre.length ? techRow("MITRE ATT&CK", h("span", { class: "mono" }, t.mitre.join(", "))) : null,
        t.anchor_pid ? techRow("Process", h("span", { class: "mono" }, "pid " + t.anchor_pid)) : null,
        techRow("First seen", when(a.first_seen)),
        techRow("Last update", when(a.updated) + " (revision " + t.revision + ")"),
        t.evidence && t.evidence.length ? techRow("Evidence", h("span", { class: "mono" }, t.evidence.map(function (e) { return e[0] + ": " + e[1].join(", "); }).join(" | "))) : null,
        t.detail ? techRow("Details", t.detail) : null));
    details.open = !!state.open[a.id];
    details.addEventListener("toggle", function () { state.open[a.id] = details.open; });
    const bar = progress ? h("div", { class: "bar", "aria-hidden": "true" }) : null;
    if (bar) { const fill = h("span"); fill.style.width = Math.round(100 * progress.done / Math.max(1, progress.total)) + "%"; bar.appendChild(fill); }
    return h("article", { class: "alert sev-" + sev(a.severity) + (a.status === "dismissed" ? " is-dismissed" : "") },
      h("div", { class: "alert-head" }, badge(a.severity), h("h3", null, a.headline),
        h("time", { datetime: new Date(a.updated * 1000).toISOString(), title: when(a.updated) }, timeAgo(a.updated))),
      a.why ? h("p", { class: "why" }, a.why) : null,
      a.next_steps && a.next_steps.length ? h("div", { class: "next" }, h("strong", null, "What to do"),
        h("ul", null, a.next_steps.map(function (s) { return h("li", null, s); }))) : null,
      progress ? h("div", { class: "steps" }, progress.complete ? "Attack completed all " + progress.total + " steps" : "Step " + progress.done + " of " + progress.total, bar) : null,
      details,
      h("div", { class: "actions" },
        a.status === "open"
          ? h("button", { class: "btn", type: "button", onclick: function () { setStatus(a.id, "dismissed"); } }, "Dismiss")
          : h("button", { class: "btn", type: "button", onclick: function () { setStatus(a.id, "open"); } }, "Reopen")));
  }

  function sparkline(activity) {
    const W = 480, H = 80, ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("class", "spark");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "Events checked over the last 24 hours");
    const base = document.createElementNS(ns, "line");
    ["x1", "0", "x2", String(W), "y1", String(H - 4), "y2", String(H - 4)].forEach(function (v, i, a) { if (i % 2 === 0) base.setAttribute(v, a[i + 1]); });
    svg.appendChild(base);
    if (!activity.length) return svg;
    const max = Math.max(1, Math.max.apply(null, activity.map(function (p) { return p.events; })));
    const step = W / Math.max(1, activity.length - 1);
    const pts = activity.map(function (p, i) { return (i * step).toFixed(1) + "," + (H - 4 - (p.events / max) * (H - 14)).toFixed(1); });
    const line = document.createElementNS(ns, "polyline");
    line.setAttribute("points", pts.join(" "));
    svg.appendChild(line);
    activity.forEach(function (p, i) {
      if (!p.alerts) return;
      const dot = document.createElementNS(ns, "circle");
      dot.setAttribute("cx", (i * step).toFixed(1)); dot.setAttribute("cy", "8"); dot.setAttribute("r", "4");
      svg.appendChild(dot);
    });
    return svg;
  }

  function sourceList(o) {
    if (!o.sources.length && !o.blind_spots.length) return h("p", { class: "empty" }, "No sources yet.");
    return h("ul", { class: "plain" },
      o.sources.map(function (s) {
        return h("li", null, s.state === "ok" ? h("span", { class: "ok" }, "✔ ") : h("span", { class: "warn" }, "▲ "), s.name, s.detail && s.state !== "ok" ? " — " + s.detail : "");
      }),
      o.blind_spots.filter(function (b) { return !o.sources.some(function (s) { return b.indexOf(s.name + ":") === 0; }); })
        .map(function (b) { return h("li", null, h("span", { class: "warn" }, "▲ "), "Blind spot: " + b); }));
  }

  // ------------------------------------------------------------------- views
  function viewOverview(o) {
    const st = STATES[o.state] || STATES.stopped;
    const sub = o.open.total + " open " + plural(o.open.total, "alert", "alerts") + " · " + o.events_24h.toLocaleString() + " events checked in the last 24 hours";
    return [
      h("section", { class: "hero state-" + (STATES[o.state] ? o.state : "stopped") },
        h("div", { class: "hero-icon", "aria-hidden": "true" }, st.icon),
        h("div", null, h("h1", null, o.headline), h("p", null, sub))),
      h("div", { class: "grid" },
        h("section", { class: "card span-2" }, h("h2", null, "Needs attention"),
          o.attention.length ? h("div", { class: "stack" }, o.attention.map(alertCard)) : h("p", { class: "empty" }, "Nothing needs your attention."),
          o.open.total > o.attention.length ? h("p", null, h("a", { href: "#/alerts" }, "See all " + o.open.total + " alerts")) : null),
        h("section", { class: "card" }, h("h2", null, "Last 24 hours"), sparkline(o.activity),
          h("div", { class: "numbers" },
            h("div", null, h("strong", null, o.events_24h.toLocaleString()), h("span", null, "events checked")),
            h("div", null, h("strong", null, o.alerts_24h.toLocaleString()), h("span", null, plural(o.alerts_24h, "alert raised", "alerts raised"))))),
        h("section", { class: "card" }, h("h2", null, "What Erinix is watching"), sourceList(o))),
    ];
  }

  function viewAlerts(o) {
    const tabs = [["open", "Open"], ["dismissed", "Dismissed"], ["all", "All"]];
    return [
      h("div", { class: "tabs", role: "group", "aria-label": "Filter alerts" }, tabs.map(function (t) {
        return h("button", { type: "button", "aria-pressed": state.filter === t[0] ? "true" : "false",
          onclick: function () { state.filter = t[0]; state.lastKey = ""; refresh(); } }, t[1]);
      })),
      state.alerts.length ? h("div", { class: "stack" }, state.alerts.map(alertCard))
        : h("div", { class: "card" }, h("p", { class: "empty" }, state.filter === "open" ? "Nothing needs your attention." : "No alerts here.")),
    ];
  }

  function viewSources(o) {
    const rows = o.sources.map(function (s) {
      return h("tr", null, h("td", null, s.name), h("td", null, s.state === "ok" ? h("span", { class: "ok" }, "✔ Watching") : h("span", { class: "warn" }, "▲ Blind")), h("td", null, s.detail || ""));
    });
    const mode = o.demo ? "Demo data (simulated attacks)" : o.mode === "live" ? "Live monitoring" : "Not monitoring";
    return [
      h("section", { class: "card" }, h("h2", null, "Sources"),
        rows.length ? h("table", null, h("thead", null, h("tr", null, h("th", null, "Source"), h("th", null, "Status"), h("th", null, "Details"))), h("tbody", null, rows))
          : h("p", { class: "empty" }, "No sources are configured yet.")),
      h("section", { class: "card", style: null }, h("h2", null, "Blind spots"),
        o.blind_spots.length ? h("ul", { class: "plain" }, o.blind_spots.map(function (b) { return h("li", null, h("span", { class: "warn" }, "▲ "), b); }))
          : h("p", { class: "empty" }, "None reported.")),
      h("section", { class: "card" }, h("h2", null, "About this run"),
        h("dl", { class: "tech" }, techRow("Mode", mode), techRow("Version", o.version), o.since ? techRow("Watching since", when(o.since)) : null)),
    ];
  }

  function viewLocked() {
    const why = state.loginError ? (LOGIN_MESSAGES[state.loginError] || "The sign-in did not work.") : null;
    return h("section", { class: "card lock" }, h("h1", null, "Open Erinix from your terminal"),
      why ? h("p", { class: "warn", role: "alert" }, why) : null,
      h("p", null, "This page needs a private sign-in link. Run:"), h("p", null, h("code", null, "erinix ui")),
      h("p", { class: "empty" }, "The link works once and expires after two minutes."));
  }

  // ------------------------------------------------------------------ render
  function render() {
    const view = currentView();
    document.querySelectorAll("#nav a").forEach(function (a) {
      if (a.getAttribute("data-view") === view) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    const pill = document.getElementById("pill"), banner = document.getElementById("banner"), count = document.getElementById("nav-count");
    document.getElementById("version").textContent = state.version ? "v" + state.version : "";
    const o = state.overview;
    if (state.locked) {
      pill.className = "pill state-stopped"; pill.textContent = "Signed out"; banner.hidden = true; count.hidden = true;
      app.replaceChildren(viewLocked());
      return;
    }
    if (!o) {
      pill.className = "pill state-stopped"; pill.textContent = state.error ? "Offline" : "Connecting…"; banner.hidden = true; count.hidden = true;
      app.replaceChildren(h("section", { class: "card" }, h("p", { class: "empty" }, state.error || "Connecting…")));
      return;
    }
    const st = STATES[o.state] || STATES.stopped;
    pill.className = "pill state-" + (STATES[o.state] ? o.state : "stopped");
    pill.textContent = st.icon + " " + (o.state === "attention" ? o.open.total + " " + plural(o.open.total, "needs attention", "need attention") : st.label);
    banner.hidden = !o.demo;
    banner.textContent = o.demo ? "Showing demo data: these are simulated attacks, not real monitoring." : "";
    count.hidden = !o.open.total;
    count.textContent = String(o.open.total);
    const body = view === "alerts" ? viewAlerts(o) : view === "sources" ? viewSources(o) : viewOverview(o);
    app.replaceChildren.apply(app, [state.error ? h("div", { class: "card", role: "alert" }, state.error) : null].concat(body).filter(Boolean));
  }

  function tick() {
    if (!document.hidden) refresh();
    window.setTimeout(tick, POLL_MS);
  }
  window.addEventListener("hashchange", function () { state.lastKey = ""; consumeLoginFragment().then(refresh); });
  document.addEventListener("visibilitychange", function () { if (!document.hidden) refresh(); });
  // The sign-in link carries its token after "#": that part never travels to the server by itself,
  // so opening the link twice or letting a browser pre-load it cannot use the token up. This page sends it once.
  // Also runs when a link is pasted into a tab that is already open (only the "#" part changes then).
  async function consumeLoginFragment() {
    const m = /^#login=([A-Za-z0-9_-]{20,100})$/.exec(location.hash);
    if (!m) return;
    history.replaceState(null, "", location.pathname + location.search);   // the token never stays in the address bar
    try {
      await request("POST", "/api/login", { token: m[1] });
      state.locked = false; state.loginError = ""; state.csrf = null;
    } catch (err) {
      // another copy of this page (a double open) may have signed in already: check before giving up
      await new Promise(function (resolve) { window.setTimeout(resolve, 400); });
      try { await request("GET", "/api/session"); state.locked = false; state.loginError = ""; }
      catch (err2) { state.loginError = err.code || "invalid"; state.locked = true; }
    }
  }

  async function start() {
    await consumeLoginFragment();
    tick();
  }

  window.__erinix = { state: state, refresh: refresh, render: render };
  start();
})();
