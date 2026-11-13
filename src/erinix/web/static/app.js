"use strict";
/* Erinix dashboard. Plain JavaScript, no libraries, no external requests.
   Safety rule: everything that comes from the server is put on the page with
   textContent / createTextNode, NEVER as HTML, because alert text can contain
   what an attacker typed into a URL, a user name or a user agent. */
(function () {
  const POLL_MS = 1000;           // overview, alerts: once a second
  const FEED_MS = 500;            // the live stream of events: twice a second
  const FEED_KEEP = 300;
  const FEED_SHOWN = { overview: 8, live: 150 };
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

  const state = { overview: null, alerts: [], filter: "open", csrf: null, version: "", locked: false, error: null, open: {}, lastKey: "", loginError: "", renderedView: "",
    feed: { events: [], lastId: 0, paused: false, pausedAt: null, queued: 0, only: false, loaded: false } };
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
  function clock(epoch) { return new Date(epoch * 1000).toTimeString().slice(0, 8); }
  function currentView() {
    const hash = location.hash || "#/";
    if (hash.indexOf("#/live") === 0) return "live";
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
      const view = currentView();
      if (view === "alerts") alerts = (await request("GET", "/api/alerts?status=" + encodeURIComponent(state.filter) + "&limit=100")).alerts;
      else if (view === "live") alerts = (await request("GET", "/api/alerts?status=open&limit=30")).alerts;
      // Counters and the chart change all the time: they are updated in place, never by redrawing the page.
      const stable = Object.assign({}, overview);
      ["heartbeat_age", "events_24h", "alerts_24h", "activity"].forEach(function (k) { delete stable[k]; });
      const key = JSON.stringify([stable, alerts, state.filter, view, view === "live" ? inProgress(alerts).map(function (a) { return a.id; }) : null]);
      state.overview = overview; state.alerts = alerts; state.error = null;
      if (key !== state.lastKey) { state.lastKey = key; render(); }
      updateLive(overview);
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

  function alertCard(a, standalone, compact) {
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
    const fresh = Date.now() / 1000 - a.updated < 4 && a.status === "open";
    return h("article", { class: "alert sev-" + sev(a.severity) + (standalone === true ? " glass" : "") + (compact ? " compact" : "") + (a.status === "dismissed" ? " is-dismissed" : "") + (fresh ? " fresh" : "") },
      h("div", { class: "alert-head" }, badge(a.severity), h("h3", null, a.headline),
        h("time", { datetime: new Date(a.updated * 1000).toISOString(), title: when(a.updated), "data-epoch": a.updated }, timeAgo(a.updated))),
      a.why && !compact ? h("p", { class: "why" }, a.why) : null,
      timelineView(a),
      a.next_steps && a.next_steps.length && !compact ? h("div", { class: "next" }, h("strong", null, "What to do"),
        h("ul", null, a.next_steps.map(function (s) { return h("li", null, s); }))) : null,
      progress && !compact && !(a.steps && a.steps.length) ? h("div", { class: "steps" }, progress.complete ? "Attack completed all " + progress.total + " steps" : "Step " + progress.done + " of " + progress.total, bar) : null,
      compact ? h("p", { class: "tl-more" }, h("a", { href: "#/alerts" }, "Details and what to do")) : details,
      compact ? null : h("div", { class: "actions" },
        a.status === "open"
          ? h("button", { class: "btn", type: "button", onclick: function () { setStatus(a.id, "dismissed"); } }, "Dismiss")
          : h("button", { class: "btn", type: "button", onclick: function () { setStatus(a.id, "open"); } }, "Reopen")));
  }

  // ---------------------------------------------- what happened, step by step
  function timelineView(a) {
    const steps = a.steps || [];
    const now = Date.now() / 1000;
    if (steps.length) {
      return h("div", { class: "timeline-wrap" }, h("strong", { class: "tl-title" }, "What happened, step by step"),
        h("ol", { class: "timeline" }, steps.map(function (s) {
          const state_ = ["done", "current", "pending"].indexOf(s.state) >= 0 ? s.state : "pending";
          const detail = (s.count > 1 ? s.count + " times · last: " : "") + (s.detail || "");
          return h("li", { class: "tl " + state_ + (s.time && now - s.time < 5 ? " fresh" : "") },
            h("span", { class: "tl-dot", "aria-hidden": "true" }, state_ === "done" ? "✔" : ""),
            h("div", { class: "tl-body" },
              h("div", { class: "tl-head" }, h("span", { class: "tl-label" }, s.label),
                s.time ? h("time", null, clock(s.time)) : state_ === "current" ? h("span", { class: "tl-wait" }, "waiting…") : null),
              s.detail ? h("div", { class: "tl-detail mono" }, detail) : null));
        })));
    }
    const seen = (a.timeline || []).slice(-6);
    if (!seen.length) return null;
    return h("div", { class: "timeline-wrap" }, h("strong", { class: "tl-title" }, "What was seen"),
      h("ol", { class: "timeline" }, seen.map(function (e) {
        return h("li", { class: "tl done" + (now - e.time < 5 ? " fresh" : "") }, h("span", { class: "tl-dot", "aria-hidden": "true" }, "✔"),
          h("div", { class: "tl-body" }, h("div", { class: "tl-head" }, h("span", { class: "tl-label" }, e.label), h("time", null, clock(e.time))),
            h("div", { class: "tl-detail mono" }, e.summary)));
      })));
  }

  // --------------------------------------------------------- the live stream
  function visibleEvents() {
    const f = state.feed;
    return f.events.filter(function (e) { return (!f.only || e.alert) && (f.pausedAt === null || e.id <= f.pausedAt); });
  }
  function feedRow(e, entering) {
    return h("li", { class: "ev" + (e.alert ? " flagged sev-" + sev(e.severity) : "") + (entering ? " enter" : ""), "data-id": e.id },
      h("time", null, clock(e.time)), h("span", { class: "ev-label" }, e.label), h("span", { class: "ev-text" }, e.summary),
      e.remote ? h("span", { class: "ev-remote mono" }, e.remote) : null,
      e.alert ? h("span", { class: "ev-tag" }, "Part of an attack") : null);
  }
  function fillFeed(ul, limit) {
    const rows = visibleEvents().slice(-limit).reverse();
    ul.replaceChildren.apply(ul, rows.length ? rows.map(function (e) { return feedRow(e, false); })
      : [h("li", { class: "ev-empty" }, state.feed.only ? "No suspicious events yet." : "Waiting for events…")]);
  }
  function refillFeed() {
    const ul = document.getElementById("feed");
    if (ul) fillFeed(ul, Number(ul.getAttribute("data-limit")) || 100);
  }
  function insertEvents(fresh) {
    const ul = document.getElementById("feed");
    if (!ul) return;
    const limit = Number(ul.getAttribute("data-limit")) || 100;
    const shown = fresh.filter(function (e) { return !state.feed.only || e.alert; });
    if (!shown.length) return;
    const empty = ul.querySelector(".ev-empty");
    if (empty) empty.remove();
    shown.forEach(function (e) { ul.prepend(feedRow(e, true)); });     // newest on top; nothing else is redrawn
    while (ul.children.length > limit) ul.lastElementChild.remove();
  }
  function updateFeedControls() {
    const f = state.feed;
    const pause = document.querySelector('[data-action="pause"]'), only = document.querySelector('[data-action="only"]');
    if (pause) { pause.textContent = f.paused ? "Resume" + (f.queued ? " (" + f.queued + " new)" : "") : "Pause"; pause.setAttribute("aria-pressed", f.paused ? "true" : "false"); }
    if (only) only.setAttribute("aria-pressed", f.only ? "true" : "false");
  }
  function togglePause() {
    const f = state.feed;
    f.paused = !f.paused;
    f.pausedAt = f.paused ? f.lastId : null;
    if (!f.paused) { f.queued = 0; refillFeed(); }
    updateFeedControls();
  }
  function toggleOnly() { state.feed.only = !state.feed.only; refillFeed(); updateFeedControls(); }
  function feedControls() {
    const f = state.feed;
    return h("div", { class: "feed-controls" },
      h("span", { class: "live-pill" }, h("span", { class: "live-dot", "aria-hidden": "true" }), "Live"),
      h("button", { class: "btn small", type: "button", "data-action": "pause", "aria-pressed": f.paused ? "true" : "false", onclick: togglePause }, f.paused ? "Resume" : "Pause"),
      h("button", { class: "btn small", type: "button", "data-action": "only", "aria-pressed": f.only ? "true" : "false", onclick: toggleOnly }, "Only suspicious"));
  }
  function feedCard(limit, full) {
    const ul = h("ul", { id: "feed", class: "feed", "data-limit": limit });
    fillFeed(ul, limit);
    return h("section", { class: "card glass feed-card" + (full ? "" : " compact") },
      h("div", { class: "card-head" }, h("h2", null, "Live activity"), full ? feedControls() : h("a", { class: "more-link", href: "#/live" }, "Open the live view")), ul);
  }
  async function pollFeed() {
    const f = state.feed;
    if (state.locked || !state.csrf) return;
    try {
      const data = await request("GET", "/api/events" + (f.loaded ? "?after=" + f.lastId + "&limit=200" : "?limit=80"));
      if (f.loaded && data.last_id < f.lastId) {            // the store was cleared and started again
        f.events = []; f.lastId = 0; f.loaded = false; f.queued = 0; f.pausedAt = f.paused ? 0 : null;
        refillFeed();
        return;
      }
      const first = !f.loaded;
      f.loaded = true;
      const fresh = data.events.filter(function (e) { return e.id > f.lastId; });
      if (!fresh.length) { if (first) refillFeed(); return; }
      f.lastId = fresh[fresh.length - 1].id;
      f.events = f.events.concat(fresh).slice(-FEED_KEEP);
      if (first) refillFeed();
      else if (f.paused) { f.queued += fresh.length; updateFeedControls(); }
      else insertEvents(fresh);
    } catch (err) { /* the main refresh shows connection problems */ }
  }
  function feedTick() {
    if (!document.hidden) pollFeed();
    window.setTimeout(feedTick, FEED_MS);
  }
  function inProgress(alerts) {
    const now = Date.now() / 1000;
    return alerts.filter(function (a) { return a.status === "open" && now - a.updated < 900; })
      .sort(function (x, y) { return y.updated - x.updated; });
  }
  // numbers, times and the chart move on their own: update them where they are
  function updateLive(o) {
    document.querySelectorAll("[data-live]").forEach(function (el) {
      const v = o[el.getAttribute("data-live")];
      if (typeof v === "number") el.textContent = v.toLocaleString();
    });
    const holder = document.getElementById("spark-holder");
    if (holder) {
      const k = JSON.stringify(o.activity);
      if (holder.getAttribute("data-k") !== k) { holder.setAttribute("data-k", k); holder.replaceChildren(sparkline(o.activity)); }
    }
    document.querySelectorAll("time[data-epoch]").forEach(function (el) { el.textContent = timeAgo(Number(el.getAttribute("data-epoch"))); });
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
    const defs = document.createElementNS(ns, "defs");
    const grad = document.createElementNS(ns, "linearGradient");
    grad.setAttribute("id", "spark-fill"); grad.setAttribute("x1", "0"); grad.setAttribute("y1", "0"); grad.setAttribute("x2", "0"); grad.setAttribute("y2", "1");
    ["spark-stop-a", "spark-stop-b"].forEach(function (cls, i) {
      const stop = document.createElementNS(ns, "stop");
      stop.setAttribute("offset", String(i)); stop.setAttribute("class", cls);
      grad.appendChild(stop);
    });
    defs.appendChild(grad);
    svg.appendChild(defs);
    const area = document.createElementNS(ns, "path");
    area.setAttribute("d", "M0," + (H - 4) + " L" + pts.join(" L") + " L" + W + "," + (H - 4) + " Z");
    area.setAttribute("fill", "url(#spark-fill)");
    svg.appendChild(area);
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
  function statTile(label, value, note, tone, liveKey) {
    return h("div", { class: "stat glass " + tone }, h("span", { class: "stat-label" }, label), h("strong", liveKey ? { "data-live": liveKey } : null, value), note ? h("span", { class: "stat-note" }, note) : null);
  }

  function viewOverview(o) {
    const st = STATES[o.state] || STATES.stopped;
    const n = o.open.total;
    const worst = o.open.critical ? "critical" : o.open.high ? "high" : o.open.medium ? "medium" : o.open.low ? "low" : null;
    const watching = o.sources.filter(function (x) { return x.state === "ok"; }).length;
    const blind = o.sources.length - watching;
    const sub = [n === 0 ? "All quiet. " : n + " open " + plural(n, "alert", "alerts") + " · ", h("span", { "data-live": "events_24h" }, o.events_24h.toLocaleString()),
      " events checked in the last 24 hours" + (n === 0 ? "." : "")];
    return [
      h("section", { class: "hero glass state-" + (STATES[o.state] ? o.state : "stopped") },
        h("div", { class: "hero-body" },
          h("div", { class: "hero-icon", "aria-hidden": "true" }, st.icon),
          h("div", null, h("p", { class: "eyebrow" }, st.label), h("h1", null, o.headline), h("p", { class: "lead" }, sub),
            n ? h("a", { class: "btn primary", href: "#/alerts" }, "Review " + n + " " + plural(n, "alert", "alerts")) : null)),
        h("img", { class: "hero-hog", src: "/static/hedgehog.svg", alt: "" })),
      h("div", { class: "stats" },
        statTile("Open alerts", String(n), worst ? SEVERITY[worst].label + " is the highest level" : "Nothing open", worst ? "sev-" + worst : "sev-low"),
        statTile("Events checked", o.events_24h.toLocaleString(), "in the last 24 hours", "sev-low", "events_24h"),
        statTile("Watching", watching + " of " + o.sources.length, blind ? blind + " " + plural(blind, "blind spot", "blind spots") : "No blind spots", blind ? "sev-medium" : "sev-low")),
      h("div", { class: "grid" },
        h("section", { class: "card glass" }, h("h2", null, "Needs attention"),
          o.attention.length ? h("div", { class: "stack" }, o.attention.map(function (a) { return alertCard(a); })) : h("p", { class: "empty" }, "Nothing needs your attention."),
          o.open.total > o.attention.length ? h("p", null, h("a", { href: "#/alerts" }, "See all " + o.open.total + " alerts")) : null),
        h("div", { class: "side" },
          feedCard(FEED_SHOWN.overview, false),
          h("section", { class: "card glass" }, h("h2", null, "Last 24 hours"), h("div", { id: "spark-holder", "data-k": JSON.stringify(o.activity) }, sparkline(o.activity)),
            h("div", { class: "numbers" },
              h("div", null, h("strong", { "data-live": "events_24h" }, o.events_24h.toLocaleString()), h("span", null, "events checked")),
              h("div", null, h("strong", { "data-live": "alerts_24h" }, o.alerts_24h.toLocaleString()), h("span", null, "alerts raised")))),
          h("section", { class: "card glass" }, h("h2", null, "What Erinix is watching"), sourceList(o)))),
    ];
  }

  function viewLive(o) {
    const active = inProgress(state.alerts);
    return [
      h("div", { class: "live-grid" },
        feedCard(FEED_SHOWN.live, true),
        h("section", { class: "card glass" }, h("h2", null, "Attacks in progress"),
          active.length ? h("div", { class: "stack" }, active.map(function (a) { return alertCard(a, false, true); }))
            : h("p", { class: "empty" }, "No attack in progress. Erinix is watching."))),
    ];
  }

  function viewAlerts(o) {
    const tabs = [["open", "Open"], ["dismissed", "Dismissed"], ["all", "All"]];
    return [
      h("div", { class: "tabs glass", role: "group", "aria-label": "Filter alerts" }, tabs.map(function (t) {
        return h("button", { type: "button", "aria-pressed": state.filter === t[0] ? "true" : "false",
          onclick: function () { state.filter = t[0]; state.lastKey = ""; refresh(); } }, t[1]);
      })),
      state.alerts.length ? h("div", { class: "stack" }, state.alerts.map(function (a) { return alertCard(a, true); }))
        : h("div", { class: "card glass" }, h("p", { class: "empty" }, state.filter === "open" ? "Nothing needs your attention." : "No alerts here.")),
    ];
  }

  function viewSources(o) {
    const rows = o.sources.map(function (s) {
      return h("tr", null, h("td", null, s.name), h("td", null, s.state === "ok" ? h("span", { class: "ok" }, "✔ Watching") : h("span", { class: "warn" }, "▲ Blind")), h("td", null, s.detail || ""));
    });
    const mode = o.demo ? "Demo data (simulated attacks)" : o.mode === "live" ? "Live monitoring" : "Not monitoring";
    return [
      h("section", { class: "card glass" }, h("h2", null, "Sources"),
        rows.length ? h("table", null, h("thead", null, h("tr", null, h("th", null, "Source"), h("th", null, "Status"), h("th", null, "Details"))), h("tbody", null, rows))
          : h("p", { class: "empty" }, "No sources are configured yet.")),
      h("section", { class: "card glass" }, h("h2", null, "Blind spots"),
        o.blind_spots.length ? h("ul", { class: "plain" }, o.blind_spots.map(function (b) { return h("li", null, h("span", { class: "warn" }, "▲ "), b); }))
          : h("p", { class: "empty" }, "None reported.")),
      h("section", { class: "card glass" }, h("h2", null, "About this run"),
        h("dl", { class: "tech" }, techRow("Mode", mode), techRow("Version", o.version), o.since ? techRow("Watching since", when(o.since)) : null)),
    ];
  }

  function viewLocked() {
    const why = state.loginError ? (LOGIN_MESSAGES[state.loginError] || "The sign-in did not work.") : null;
    return h("section", { class: "card glass lock" }, h("img", { class: "lock-hog", src: "/static/hedgehog.svg", alt: "" }), h("h1", null, "Open Erinix from your terminal"),
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
      app.replaceChildren(h("section", { class: "card glass" }, h("p", { class: "empty" }, state.error || "Connecting…")));
      return;
    }
    const st = STATES[o.state] || STATES.stopped;
    pill.className = "pill state-" + (STATES[o.state] ? o.state : "stopped");
    pill.textContent = st.icon + " " + (o.state === "attention" ? o.open.total + " " + plural(o.open.total, "needs attention", "need attention") : st.label);
    banner.hidden = !o.demo;
    banner.textContent = o.demo ? "Showing demo data: these are simulated attacks, not real monitoring." : "";
    count.hidden = !o.open.total;
    count.textContent = String(o.open.total);
    const body = view === "live" ? viewLive(o) : view === "alerts" ? viewAlerts(o) : view === "sources" ? viewSources(o) : viewOverview(o);
    const y = window.scrollY, same = state.renderedView === view;
    app.replaceChildren.apply(app, [state.error ? h("div", { class: "card glass", role: "alert" }, state.error) : null].concat(body).filter(Boolean));
    if (same && y) window.scrollTo(0, y);                       // a redraw never throws you back to the top
    state.renderedView = view;
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
    feedTick();
  }

  window.__erinix = { state: state, refresh: refresh, render: render };
  start();
})();
