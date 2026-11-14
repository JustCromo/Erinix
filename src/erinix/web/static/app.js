"use strict";
/* Erinix dashboard. Plain JavaScript, no libraries, no external requests.
   Safety rule: everything that comes from the server is put on the page with
   textContent / createTextNode, NEVER as HTML, because alert text can contain
   what an attacker typed into a URL, a user name or a user agent. */
(function () {
  const POLL_MS = 1000;           // overview and incidents: once a second
  const FEED_MS = 500;            // the live stream of events: twice a second
  const FEED_KEEP = 300;
  const FEED_SHOWN = { home: 150, live: 150 };
  const SEVERITY = {
    low: { label: "Low", icon: "●" },
    medium: { label: "Medium", icon: "▲" },
    high: { label: "High", icon: "◆" },
    critical: { label: "Critical", icon: "✖" },
  };
  const STATES = {
    protected: { icon: "✔", sprite: "i-check", label: "All quiet" },
    attention: { icon: "▲", sprite: "i-alert", label: "Worth a look" },
    critical: { icon: "✖", sprite: "i-x", label: "Needs you now" },
    stopped: { icon: "■", sprite: "i-pause", label: "Not running" },
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
  const PAGE_NAMES = { home: "Cockpit", incidents: "Incidents", live: "Live", programs: "Programs", network: "Network", sources: "Sources", system: "System" };
  const ROUTINE = ["process.exec", "net.connect", "net.accept", "net.listen"];   // normal life of a machine: hidden in the live view until asked for

  const state = {
    overview: null, incidents: [], detail: null, selected: null, filter: "open", tag: null,
    csrf: null, version: "", locked: false, error: null, open: {}, lastKey: "", loginError: "", renderedView: "",
    feed: { events: [], lastId: 0, paused: false, pausedAt: null, queued: 0, only: false, loaded: false, q: "", routine: false },
    inv: null, q: {}, f: {}, openIncidents: [],
  };
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
  // Icons come from one sprite (/static/icons.svg); the name is only ever taken from our own tables
  function iconEl(name) {
    const ns = "http://www.w3.org/2000/svg", svg = document.createElementNS(ns, "svg"), use = document.createElementNS(ns, "use");
    svg.setAttribute("class", "ico"); svg.setAttribute("aria-hidden", "true");
    use.setAttribute("href", "/static/icons.svg#" + name);
    svg.appendChild(use);
    return svg;
  }
  function sev(name) { return SEVERITY[name] ? name : "low"; }
  function plural(n, one, many) { return n === 1 ? one : many; }
  function fmt(n) { return Number(n || 0).toLocaleString(); }
  // every word typed must appear somewhere in the text: "ssh root" finds rows that mention both
  function matches(text, query) {
    const words = String(query || "").toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) return true;
    const low = String(text).toLowerCase();
    return words.every(function (w) { return low.indexOf(w) >= 0; });
  }
  function searchBox(placeholder, value, onInput) {
    const input = h("input", { type: "search", class: "search", placeholder: placeholder, "aria-label": placeholder, autocomplete: "off", spellcheck: "false", maxlength: "80" });
    input.value = value || "";
    input.addEventListener("input", function () { onInput(input.value.slice(0, 80)); });
    return input;
  }
  function userName(uid) { return uid === 0 ? "root" : "user " + uid; }
  function safeId(id) { return typeof id === "string" && /^[A-Za-z0-9_-]{1,40}$/.test(id) ? id : null; }
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
  function isWide() { return typeof window.matchMedia !== "function" || window.matchMedia("(min-width: 900px)").matches; }
  function route() {
    const hash = location.hash || "#/";
    let m;
    if (hash.indexOf("#/live") === 0) return { view: "live", id: null };
    if (hash.indexOf("#/programs") === 0) return { view: "programs", id: null };
    if (hash.indexOf("#/network") === 0) return { view: "network", id: null };
    if (hash.indexOf("#/sources") === 0) return { view: "sources", id: null };
    if (hash.indexOf("#/system") === 0) return { view: "system", id: null };
    m = /^#\/incidents(?:\/([A-Za-z0-9_-]{1,40}))?/.exec(hash);
    if (m) return { view: "incidents", id: m[1] || null };
    if (hash.indexOf("#/alerts") === 0) return { view: "incidents", id: null };
    return { view: "home", id: null };
  }
  function currentView() { return route().view; }

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

  function activeNow(incidents) {
    const now = Date.now() / 1000;
    return incidents.filter(function (i) { return i.status === "open" && now - i.updated < 600; });
  }

  async function refresh() {
    try {
      if (!state.csrf) {
        const session = await request("GET", "/api/session");
        state.csrf = session.csrf;
        state.version = session.version || "";
      }
      state.locked = false;
      const r = route();
      const overview = await request("GET", "/api/overview");
      let incidents = state.incidents, detail = state.detail, selected = state.selected;
      if (r.view === "incidents") {
        incidents = (await request("GET", "/api/incidents?status=" + encodeURIComponent(state.filter))).incidents;
        selected = r.id || (isWide() && incidents.length ? incidents[0].id : null);
        detail = null;
        if (selected && safeId(selected)) {
          try { detail = await request("GET", "/api/incidents/" + encodeURIComponent(selected)); }
          catch (err) { if (err.message === "locked") throw err; detail = null; }
        }
      } else if (r.view === "live" || r.view === "home") {
        incidents = (await request("GET", "/api/incidents?status=open")).incidents;
      }
      if (["home", "system", "programs", "network", "sources"].indexOf(r.view) >= 0) {
        try { state.inv = await request("GET", "/api/inventory"); }
        catch (err) { if (err.message === "locked") throw err; }
      }
      // Counters and the chart change all the time: they are updated in place, never by redrawing the page.
      const stable = Object.assign({}, overview);
      ["heartbeat_age", "events_24h", "alerts_24h", "activity", "sources"].forEach(function (k) { delete stable[k]; });   // these change all the time: updated in place
      const key = JSON.stringify([stable, incidents, detail, state.filter, state.tag, r, selected,
        r.view === "live" ? activeNow(incidents).map(function (i) { return i.id; }) : null, r.view === "home" ? incidents : null, [overview.sources.length, overview.sources.filter(function (x) { return x.state === "ok"; }).length]]);
      state.overview = overview; state.incidents = incidents; state.detail = detail; state.selected = selected; state.error = null;
      if (key !== state.lastKey) { state.lastKey = key; render(); }
      updateLive(overview);
      updateInventory();
    } catch (err) {
      state.error = err.message === "locked" ? null : "Cannot reach Erinix. Is it running? Try: erinix ui";
      state.lastKey = "";
      render();
    }
  }

  async function setIncident(id, status) {
    try { await request("POST", "/api/incidents/" + encodeURIComponent(id) + "/status", { status: status }); }
    catch (err) { state.error = "That did not work. Please try again."; }
    state.lastKey = "";
    refresh();
  }

  async function chooseTheme(name) {
    try { await request("POST", "/api/settings", { theme: name }); applyTheme(name); }
    catch (err) { state.error = "That did not work. Please try again."; }
    state.lastKey = "";
    refresh();
  }
  // "auto" leaves the attribute off, so the system decides (light by day, dark at night); "light" and "dark" force one
  function applyTheme(name) {
    const known = state.overview && state.overview.themes && state.overview.themes.some(function (p) { return p.name === name; });
    if (!known) return;
    const root = document.documentElement;
    if (name === "auto") root.removeAttribute("data-theme");
    else if (root.getAttribute("data-theme") !== name) root.setAttribute("data-theme", name);
  }

  // one button: sun in the dark theme, moon in the light one; it flips between the two (the system chooses until you click)
  function effectiveTheme() {
    const t = state.overview && state.overview.theme;
    if (t === "light" || t === "dark") return t;
    return typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function updateThemeButton() {
    const b = document.getElementById("theme-toggle");
    if (!b) return;
    const dark = effectiveTheme() === "dark", label = dark ? "Switch to light theme" : "Switch to dark theme";
    b.setAttribute("aria-label", label); b.setAttribute("title", label);
    const use = b.querySelector("use");
    if (use) use.setAttribute("href", "/static/icons.svg#" + (dark ? "i-sun" : "i-moon"));
  }
  const themeButton = document.getElementById("theme-toggle");
  if (themeButton) themeButton.addEventListener("click", function () { if (state.overview) chooseTheme(effectiveTheme() === "dark" ? "light" : "dark"); });

  // ------------------------------------------------------------------ pieces
  function badge(name) {
    const s = SEVERITY[sev(name)];
    return h("span", { class: "badge sev-" + sev(name) }, h("span", { "aria-hidden": "true" }, s.icon), s.label);
  }
  function tagList(tags, max) {
    const list = (tags || []).filter(function (t) { return typeof t === "string" && t; });
    if (!list.length) return null;
    return h("div", { class: "tags" }, list.slice(0, max).map(function (t) { return h("span", { class: "tag" }, t); }),
      list.length > max ? h("span", { class: "tag" }, "+" + (list.length - max)) : null);
  }
  function techRow(label, value) { return [h("dt", null, label), h("dd", null, value)]; }
  function pageHead(title, sub) { return h("div", { class: "page-head" }, h("h1", null, title), sub ? h("p", null, sub) : null); }
  function section(title, body) { return h("section", { class: "d-sec" }, h("h3", null, title), body); }

  function incidentRow(i, mode) {
    const id = safeId(i.id);
    const cls = "inc sev-" + sev(i.severity) + (i.status === "closed" ? " closed" : "") + (mode === "list" && state.selected === i.id ? " selected" : "");
    return h("a", { class: cls, href: id ? "#/incidents/" + id : "#/incidents" },
      h("div", { class: "inc-top" }, badge(i.severity), h("span", { class: "inc-who mono" }, i.who),
        h("time", { datetime: new Date(i.updated * 1000).toISOString(), title: when(i.updated), "data-epoch": i.updated }, timeAgo(i.updated))),
      h("h3", { class: "inc-title" }, i.headline),
      tagList(i.tags, 4),
      mode === "home" ? h("span", { class: "inc-go" }, "See what happened →") : null);
  }

  // ---------------------------------------------- what happened, step by step
  function timelineView(a, title) {
    const steps = a.steps || [];
    const now = Date.now() / 1000;
    if (!steps.length) return null;
    return h("div", { class: "timeline-wrap" }, h("strong", { class: "tl-title" }, title || "What happened, step by step"),
      h("ol", { class: "timeline" }, steps.map(function (s) {
        const st = ["done", "current", "pending"].indexOf(s.state) >= 0 ? s.state : "pending";
        const detail = (s.count > 1 ? s.count + " times · last: " : "") + (s.detail || "");
        return h("li", { class: "tl " + st + (s.time && now - s.time < 5 ? " fresh" : "") },
          h("span", { class: "tl-dot", "aria-hidden": "true" }, st === "done" ? "✔" : ""),
          h("div", { class: "tl-body" },
            h("div", { class: "tl-head" }, h("span", { class: "tl-label" }, s.label),
              s.time ? h("time", null, clock(s.time)) : st === "current" ? h("span", { class: "tl-wait" }, "waiting…") : null),
            s.detail ? h("div", { class: "tl-detail mono" }, detail) : null));
      })));
  }

  function technical(a) {
    const t = a.technical || {};
    return h("dl", { class: "tech" },
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
      t.detail ? techRow("Details", t.detail) : null);
  }

  function attackCard(a) {
    const details = h("details", { class: "more" }, h("summary", null, "Technical details"), technical(a));
    details.open = !!state.open[a.id];
    details.addEventListener("toggle", function () { state.open[a.id] = details.open; });
    return h("article", { class: "attack sev-" + sev(a.severity) },
      h("div", { class: "attack-head" }, badge(a.severity), a.tag ? h("span", { class: "tag" }, a.tag) : null, h("h4", null, a.headline)),
      timelineView(a, "Steps"),
      details);
  }

  function storyView(d) {
    const rows = (d.timeline || []).map(function (e) {
      return h("li", null, h("time", null, clock(e.time)),
        h("div", { class: "what" }, e.tag ? h("span", { class: "tag" }, e.tag) : null, e.label + ": " + e.summary));
    });
    (d.alerts || []).forEach(function (a) {
      (a.steps || []).filter(function (s) { return s.state === "current"; }).forEach(function (s) {
        rows.push(h("li", { class: "waiting" }, h("time", null, "next"), h("div", { class: "what" }, h("span", { class: "tl-wait" }, "Possible next step: " + s.label + " — waiting…"))));
      });
    });
    return rows.length ? h("ol", { class: "story" }, rows) : h("p", { class: "empty" }, "No events recorded for this incident yet.");
  }

  function incidentDetail(d) {
    const closed = d.status === "closed";
    return h("article", { class: "detail card sev-" + sev(d.severity) },
      h("a", { class: "back", href: "#/incidents" }, "← All incidents"),
      h("div", { class: "d-head" },
        h("div", null, badge(d.severity), h("h2", { class: "d-who mono" }, d.who), h("p", { class: "d-title" }, d.headline)),
        h("button", { class: "btn", type: "button", "data-action": "incident-status", onclick: function () { setIncident(d.id, closed ? "open" : "closed"); } }, closed ? "Reopen" : "Close incident")),
      h("p", { class: "d-meta" }, "First seen " + when(d.first_seen) + " · last activity ", h("span", { "data-epoch": d.updated }, timeAgo(d.updated)), " · " + d.alert_count + " " + plural(d.alert_count, "attack", "attacks")),
      h("p", { class: "d-why" }, d.summary),
      tagList(d.tags, 12),
      d.next_steps && d.next_steps.length ? section("What to do", h("ul", { class: "todo" }, d.next_steps.map(function (s) { return h("li", null, s); }))) : null,
      section("What happened, in order", storyView(d)),
      section("The attacks in this incident", h("div", { class: "stack" }, (d.alerts || []).map(attackCard))));
  }

  // --------------------------------------------------------- the live stream
  function visibleEvents() {
    const f = state.feed;
    return f.events.filter(function (e) { return (!f.only || e.alert) && (f.routine || !isRoutine(e)) && (f.pausedAt === null || e.id <= f.pausedAt) && matches(eventText(e), f.q); });
  }
  function isRoutine(e) { return !e.alert && ROUTINE.indexOf(e.kind) >= 0; }
  function eventText(e) { return [e.label, e.summary, e.remote, e.tag].join(" "); }
  function feedRow(e, entering) {
    const id = safeId(e.incident);
    const tag = e.alert ? (e.tag ? (id ? h("a", { class: "tag", href: "#/incidents/" + id }, e.tag) : h("span", { class: "tag" }, e.tag)) : h("span", { class: "tag" }, "Part of an attack")) : null;
    return h("li", { class: "ev" + (e.alert ? " flagged sev-" + sev(e.severity) : "") + (entering ? " enter" : ""), "data-id": e.id },
      h("time", null, clock(e.time)),
      h("div", { class: "ev-main" }, h("span", { class: "ev-label" }, e.label), e.summary),
      e.remote ? h("span", { class: "ev-remote mono" }, e.remote) : h("span"),
      tag ? h("div", { class: "ev-tags" }, tag) : null);
  }
  function fillFeed(ul, limit) {
    const rows = visibleEvents().slice(-limit).reverse();
    ul.replaceChildren.apply(ul, rows.length ? rows.map(function (e) { return feedRow(e, false); })
      : [h("li", { class: "ev-empty" }, state.feed.q ? "No event matches your search." : state.feed.only ? "No suspicious events yet."
        : !state.feed.routine && state.feed.events.length ? "Only routine activity so far. Turn on “Show routine activity” to see it." : "Waiting for events…")]);
  }
  function refillFeed() {
    const ul = document.getElementById("feed");
    if (ul) fillFeed(ul, Number(ul.getAttribute("data-limit")) || 100);
  }
  function insertEvents(fresh) {
    const ul = document.getElementById("feed");
    if (!ul) return;
    const limit = Number(ul.getAttribute("data-limit")) || 100;
    const shown = fresh.filter(function (e) { return (!state.feed.only || e.alert) && (state.feed.routine || !isRoutine(e)) && matches(eventText(e), state.feed.q); });
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
    const routine = document.querySelector('[data-action="routine"]');
    if (routine) routine.setAttribute("aria-pressed", f.routine ? "true" : "false");
  }
  function toggleRoutine() { state.feed.routine = !state.feed.routine; refillFeed(); updateFeedControls(); }
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
      searchBox("Search events…", f.q, function (v) { state.feed.q = v; refillFeed(); }),
      h("button", { class: "btn small", type: "button", "data-action": "pause", "aria-pressed": f.paused ? "true" : "false", onclick: togglePause }, f.paused ? "Resume" : "Pause"),
      h("button", { class: "btn small", type: "button", "data-action": "only", "aria-pressed": f.only ? "true" : "false", onclick: toggleOnly }, "Only suspicious"),
      h("button", { class: "btn small", type: "button", "data-action": "routine", "aria-pressed": f.routine ? "true" : "false", onclick: toggleRoutine }, "Show routine activity"));
  }
  function feedList(limit) {
    const ul = h("ul", { id: "feed", class: "feed scroll", "data-limit": limit });
    fillFeed(ul, limit);
    return ul;
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
  // numbers, times, the chart and the appearance move on their own: update them where they are
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
    document.querySelectorAll("[data-epoch]").forEach(function (el) { el.textContent = timeAgo(Number(el.getAttribute("data-epoch"))); });
    if (o.theme) applyTheme(o.theme);
  }

  function sparkline(activity) {
    const W = 480, H = 80, ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("class", "spark");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "Events checked over the last 24 hours");
    const base = document.createElementNS(ns, "line");
    base.setAttribute("x1", "0"); base.setAttribute("x2", String(W)); base.setAttribute("y1", String(H - 4)); base.setAttribute("y2", String(H - 4));
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

  // ------------------------------------------------------------------- views
  // ------------------------------------------------- panels: a short summary on the cockpit, a full table on its own page
  function sourceRow(x) {
    const ok = x.state === "ok";
    return h("li", { class: "row src" + (ok ? "" : " bad") },
      h("span", { class: ok ? "ok" : "warn", "aria-hidden": "true" }, ok ? "✔" : "▲"),
      h("div", { class: "row-main" }, h("strong", null, x.name), h("span", { class: "row-sub" }, x.detail || (ok ? "Watching" : "Blind"))));
  }
  function programRow(p) {
    return h("li", { class: "row prog" }, h("span", { class: "row-key mono" }, String(p.pid)),
      h("div", { class: "row-main" }, h("strong", null, p.name), h("span", { class: "row-sub mono" }, p.command)),
      h("span", { class: "row-aside" }, userName(p.uid)));
  }
  function portRow(p) {
    return h("li", { class: "row port" + (p.exposed ? " exposed" : "") }, h("span", { class: "row-key mono" }, String(p.port)),
      h("div", { class: "row-main" }, h("strong", null, p.program || "unknown program"), h("span", { class: "row-sub mono" }, p.local)),
      h("span", { class: "tag" + (p.exposed ? " flag" : "") }, p.exposed ? "Open to network" : "This machine only"));
  }
  function connRow(c) {
    return h("li", { class: "row conn" }, h("span", { class: "row-key mono" }, c.pid ? String(c.pid) : "?"),
      h("div", { class: "row-main" }, h("strong", null, c.program || "unknown program"), h("span", { class: "row-sub mono" }, c.local + " → " + c.remote)),
      h("span", { class: "tag" + (c.external ? " flag" : "") }, c.external ? "Internet" : "Local network"));
  }
  function stateCell(x) { return h("span", { class: x.state === "ok" ? "ok" : "warn" }, x.state === "ok" ? "✔ Watching" : "▲ Blind"); }
  function activityText(x) {
    return typeof x.lines === "number" ? fmt(x.lines) + " read · " + fmt(x.understood) + " understood" + (x.ignored ? " · " + fmt(x.ignored) + " ignored" : "") : "—";
  }
  function reachTag(flag, yes, no) { return h("span", { class: "tag" + (flag ? " flag" : "") }, flag ? yes : no); }
  const PANELS = {
    incidents: { title: "Incidents", page: "#/incidents", limit: 4, stack: true, empty: "Nothing needs your attention.",
      rows: function () { return state.incidents.filter(function (i) { return i.status === "open"; }); },
      text: function (i) { return [i.who, i.headline, (i.tags || []).join(" ")].join(" "); }, row: function (i) { return incidentRow(i, "panel"); } },
    sources: { title: "Sources", page: "#/sources", limit: 6, search: "Search sources…", toggle: "Problems only", empty: "No sources are configured yet. Run: erinix watch",
      rows: function () { return state.overview ? state.overview.sources : []; }, rank: function (x) { return x.state === "ok" ? 1 : 0; },
      keep: function (x) { return x.state !== "ok"; }, text: function (x) { return x.name + " " + (x.detail || ""); }, row: sourceRow, flag: function (x) { return x.state !== "ok"; },
      cols: [{ h: "Status", c: stateCell }, { h: "Source", c: function (x) { return h("strong", null, x.name); } }, { h: "Details", c: function (x) { return x.detail || ""; } }, { h: "Activity", c: activityText }] },
    programs: { title: "Programs", page: "#/programs", limit: 6, search: "Search programs…", empty: "Waiting for the agent. Run: erinix watch",
      rows: function () { return state.inv ? state.inv.processes : []; },
      text: function (p) { return [p.pid, p.name, p.command, userName(p.uid)].join(" "); }, row: programRow,
      cols: [{ h: "PID", c: function (p) { return h("span", { class: "mono" }, String(p.pid)); } }, { h: "Program", c: function (p) { return h("strong", null, p.name); } },
        { h: "Command", c: function (p) { return h("span", { class: "mono" }, p.command); } }, { h: "User", c: function (p) { return userName(p.uid); } }] },
    ports: { title: "Listening ports", page: "#/network", limit: 6, search: "Search ports…", toggle: "Open to network", empty: "Waiting for the agent. Run: erinix watch",
      rows: function () { return state.inv ? state.inv.listening : []; }, rank: function (p) { return p.exposed ? 0 : 1; },
      keep: function (p) { return p.exposed; }, text: function (p) { return [p.port, p.program, p.local].join(" "); }, row: portRow, flag: function (p) { return p.exposed; },
      cols: [{ h: "Port", c: function (p) { return h("span", { class: "mono" }, String(p.port)); } }, { h: "Program", c: function (p) { return h("strong", null, p.program || "unknown program"); } },
        { h: "Address", c: function (p) { return h("span", { class: "mono" }, p.local); } }, { h: "Reachable from", c: function (p) { return reachTag(p.exposed, "Open to network", "This machine only"); } }] },
    connections: { title: "Connections", page: "#/network", limit: 6, search: "Search connections…", toggle: "Internet only", empty: "No connection seen yet.",
      rows: function () { return state.inv ? state.inv.connections : []; }, rank: function (c) { return c.external ? 0 : 1; },
      keep: function (c) { return c.external; }, text: function (c) { return [c.program, c.local, c.remote, c.pid].join(" "); }, row: connRow,
      cols: [{ h: "PID", c: function (c) { return h("span", { class: "mono" }, c.pid ? String(c.pid) : "?"); } }, { h: "Program", c: function (c) { return h("strong", null, c.program || "unknown program"); } },
        { h: "From", c: function (c) { return h("span", { class: "mono" }, c.local); } }, { h: "To", c: function (c) { return h("span", { class: "mono" }, c.remote); } },
        { h: "Where", c: function (c) { return reachTag(c.external, "Internet", "Local network"); } }] },
  };
  Object.keys(PANELS).forEach(function (k) { PANELS[k].id = k; });
  function tableOf(spec, rows) {
    return h("div", { class: "table t-" + spec.id, role: "table", "aria-label": spec.title },
      h("div", { class: "trow thead", role: "row" }, spec.cols.map(function (c) { return h("span", { role: "columnheader" }, c.h); })),
      rows.map(function (r) {
        return h("div", { class: "trow" + (spec.flag && spec.flag(r) ? " flagged" : ""), role: "row" }, spec.cols.map(function (c) { return h("span", { role: "cell" }, c.c(r)); }));
      }));
  }
  function fillPanel(id) {
    const spec = PANELS[id], body = document.getElementById("p-" + id);
    if (!spec || !body) return;
    const compact = body.getAttribute("data-mode") === "compact";
    const all = spec.rows(), q = compact ? "" : state.q[id] || "", only = compact ? false : !!state.f[id];
    let rows = all.filter(function (r) { return (!only || spec.keep(r)) && matches(spec.text(r), q); });
    const total = rows.length;
    if (compact) {                                                   // the notable rows first, and only a few
      if (spec.rank) rows = rows.map(function (r, i) { return [spec.rank(r), i, r]; }).sort(function (a, b) { return a[0] - b[0] || a[1] - b[1]; }).map(function (x) { return x[2]; });
      rows = rows.slice(0, spec.limit);
    }
    const count = document.querySelector('[data-count="' + id + '"]');
    if (count) count.textContent = compact || total === all.length ? String(all.length) : total + " / " + all.length;
    const key = JSON.stringify([rows, q, only, compact]);
    if (body.getAttribute("data-k") === key) return;               // nothing changed: leave the scroll position alone
    body.setAttribute("data-k", key);
    let content;
    if (!rows.length) content = h("p", { class: "empty pad" }, all.length ? "Nothing matches." : spec.empty);
    else if (compact) content = spec.stack ? h("div", { class: "stack" }, rows.map(spec.row)) : h("ul", { class: "rows" }, rows.map(spec.row));
    else content = tableOf(spec, rows);
    body.replaceChildren(content);
  }
  function panelHead(title, id, controls) {
    return h("div", { class: "panel-head" }, h("h2", null, title), id ? h("span", { class: "panel-count", "data-count": id }, "") : null, controls);
  }
  function panel(id, cls, compact) {
    const spec = PANELS[id];
    const controls = compact ? (spec.page ? h("a", { class: "more", href: spec.page }, "See all →") : null) : h("div", { class: "panel-tools" },
      spec.toggle ? h("button", { class: "btn small", type: "button", "aria-pressed": state.f[id] ? "true" : "false", onclick: function (ev) {
        state.f[id] = !state.f[id]; ev.currentTarget.setAttribute("aria-pressed", state.f[id] ? "true" : "false"); fillPanel(id); } }, spec.toggle) : null,
      spec.search ? searchBox(spec.search, state.q[id], function (v) { state.q[id] = v; fillPanel(id); }) : null);
    return h("section", { class: "panel card " + (compact ? "compact " : "") + (cls || ""), "aria-label": spec.title }, panelHead(spec.title, id, controls),
      h("div", { id: "p-" + id, class: "panel-body scroll", "data-mode": compact ? "compact" : "full" }));
  }
  function tile(label, value, attrs, tone, href) {
    return h(href ? "a" : "div", href ? { class: "tile" + (tone ? " " + tone : ""), href: href } : { class: "tile" + (tone ? " " + tone : "") }, h("strong", attrs, value), h("span", null, label));
  }
  function machineRows(o) {
    const inv = state.inv || {}, host = inv.host || {};
    return [["Name", host.name], ["System", host.system], ["Hardware", host.machine],
      ["Agent runs as", host.user ? host.user + (host.root ? " (root: sees every user)" : " (sees only its own programs)") : null],
      ["Mode", o.demo ? "Demo data (simulated)" : o.mode === "live" ? "Live monitoring" : "Not monitoring"], ["Watching since", o.since ? when(o.since) : null], ["Version", o.version]]
      .filter(function (r) { return r[1]; });
  }
  function machinePanel() {
    return h("section", { class: "panel card compact c-machine", "aria-label": "This machine" }, panelHead("This machine", null, h("a", { class: "more", href: "#/system" }, "Details →")), h("div", { id: "p-machine", class: "panel-body scroll" }));
  }
  function fillMachine(o) {
    const body = document.getElementById("p-machine");
    if (!body) return;
    const rows = machineRows(o), key = JSON.stringify(rows);
    if (body.getAttribute("data-k") === key) return;
    body.setAttribute("data-k", key);
    body.replaceChildren(h("dl", { class: "tech flat" }, rows.map(function (r) { return techRow(r[0], r[1]); })));
  }
  function updateInventory() {
    Object.keys(PANELS).forEach(fillPanel);
    if (state.overview) fillMachine(state.overview);
    const inv = state.inv;
    document.querySelectorAll("[data-inv]").forEach(function (el) {
      if (!inv) return;
      const k = el.getAttribute("data-inv");
      el.textContent = fmt(k === "process_total" ? inv.process_total : (inv[k] || []).length);
    });
  }

  function viewHome(o) {
    const top = (o.incidents && o.incidents.top) || [], n = o.incidents ? o.incidents.open : 0;
    const st = STATES[o.state] || STATES.stopped;
    const total = o.sources.length, watching = o.sources.filter(function (x) { return x.state === "ok"; }).length, blind = total - watching;
    let headline, lead;
    if (o.state === "stopped") { headline = "Erinix is not watching"; lead = "Nothing is being checked right now. Run  erinix watch  to start, or  erinix demo  to look around."; }
    else if (!top.length) { headline = "All quiet"; lead = "Nothing suspicious is happening." + (total ? " Erinix is watching " + watching + " of " + total + " sources." : ""); }
    else { headline = top[0].headline; lead = top[0].summary; }
    const first = top.length ? safeId(top[0].id) : null;
    return [
      h("section", { class: "hero card state-" + (STATES[o.state] ? o.state : "stopped") },
        h("div", { class: "hero-body" },
          h("div", { class: "hero-icon", "aria-hidden": "true" }, iconEl(st.sprite)),
          h("div", { class: "hero-text" }, h("p", { class: "eyebrow" }, st.label), h("h1", null, headline), h("p", { class: "lead" }, lead),
            first ? h("div", { class: "hero-actions" }, h("a", { class: "btn primary", href: "#/incidents/" + first }, "See what happened")) : null)),
        h("div", { class: "tiles" },
          tile("open incidents", fmt(n), null, n ? "hot" : "", "#/incidents"),
          tile("events today", fmt(o.events_24h), { "data-live": "events_24h" }, "", "#/live"),
          tile("alerts today", fmt(o.alerts_24h), { "data-live": "alerts_24h" }, "", "#/incidents"),
          tile("sources watching", watching + "/" + total, null, blind ? "cool" : "", "#/sources"),
          tile("programs seen", state.inv ? fmt(state.inv.process_total) : "–", { "data-inv": "process_total" }, "", "#/programs"),
          tile("listening ports", state.inv ? fmt(state.inv.listening.length) : "–", { "data-inv": "listening" }, "", "#/network"))),
      h("div", { class: "cockpit" },
        panel("incidents", "c-incidents", true),
        h("section", { class: "panel card c-live", "aria-label": "Live activity" },
          panelHead("Live activity", null, h("a", { class: "more", href: "#/live" }, "Open live →")), feedControls(), feedList(FEED_SHOWN.home)),
        panel("sources", "c-sources", true),
        panel("ports", "c-ports", true),
        panel("connections", "c-conns", true),
        h("section", { class: "panel card compact c-chart", "aria-label": "Activity" }, panelHead("Last 24 hours"),
          h("div", { id: "spark-holder", class: "panel-body", "data-k": JSON.stringify(o.activity) }, sparkline(o.activity))),
        machinePanel()),
    ];
  }

  // ---------------------------------------------------- pages with a full table
  function viewPrograms() {
    return [pageHead("Programs", "Everything running on this machine, newest first."), h("div", { class: "fill" }, panel("programs", ""))];
  }
  function viewNetwork() {
    return [pageHead("Network", "What this machine offers to the network, and who it talks to."), h("div", { class: "fill two" }, panel("ports", ""), panel("connections", ""))];
  }
  function viewSources(o) {
    return [pageHead("Sources", "Where Erinix reads from, and whether it can."), h("div", { class: "fill" }, panel("sources", "")),
      o.blind_spots.length ? h("section", { class: "card" }, h("h2", null, "Blind spots"),
        h("ul", { class: "plain" }, o.blind_spots.map(function (b) { return h("li", null, h("span", { class: "warn" }, "▲ "), b); }))) : null];
  }

  function incidentTypes() {
    const counts = {};
    state.incidents.forEach(function (i) { (i.tags || []).forEach(function (t) { counts[t] = (counts[t] || 0) + 1; }); });
    return { counts: counts, names: Object.keys(counts).sort(function (a, b) { return a.localeCompare(b); }) };
  }
  // the list and the type filter are refilled where they are, so typing in a search box never loses its place
  function fillIncidentList() {
    const box = document.getElementById("inc-list");
    if (!box) return;
    const list = state.incidents.filter(function (i) {
      return (!state.tag || (i.tags || []).indexOf(state.tag) >= 0) && matches([i.who, i.headline, (i.tags || []).join(" ")].join(" "), state.q.inc);
    });
    const count = document.querySelector('[data-count="inc"]');
    if (count) count.textContent = list.length === state.incidents.length ? String(list.length) : list.length + " / " + state.incidents.length;
    box.replaceChildren.apply(box, list.length ? list.map(function (i) { return incidentRow(i, "list"); })
      : [h("p", { class: "empty pad" }, state.q.inc || state.tag ? "Nothing matches." : state.filter === "open" ? "Nothing needs your attention." : "No incidents here.")]);
  }
  function fillTypeChips() {
    const box = document.getElementById("tag-chips");
    if (!box) return;
    const t = incidentTypes();
    const shown = t.names.filter(function (n) { return matches(n, state.q.types); });
    box.replaceChildren.apply(box, [h("button", { type: "button", "aria-pressed": state.tag === null ? "true" : "false", onclick: function () { state.tag = null; fillTypeChips(); fillIncidentList(); } }, "All types")]
      .concat(shown.map(function (n) {
        return h("button", { type: "button", "aria-pressed": state.tag === n ? "true" : "false", onclick: function () { state.tag = state.tag === n ? null : n; fillTypeChips(); fillIncidentList(); } }, n + " " + t.counts[n]);
      })));
  }
  function viewIncidents(o) {
    const r = route();
    const tabs = [["open", "Open"], ["closed", "Closed"], ["all", "All"]];
    const types = incidentTypes();
    const left = h("section", { class: "list-pane card" },
      h("div", { class: "panel-head" }, h("h2", null, "Incidents"), h("span", { class: "panel-count", "data-count": "inc" }, "")),
      h("div", { class: "tabs", role: "group", "aria-label": "Filter incidents" }, tabs.map(function (t) {
        return h("button", { type: "button", "aria-pressed": state.filter === t[0] ? "true" : "false",
          onclick: function () { state.filter = t[0]; state.lastKey = ""; refresh(); } }, t[1]);
      })),
      searchBox("Search incidents…", state.q.inc, function (v) { state.q.inc = v; fillIncidentList(); }),
      types.names.length ? h("div", { class: "type-filter" },
        types.names.length > 6 ? searchBox("Search attack types…", state.q.types, function (v) { state.q.types = v; fillTypeChips(); }) : null,
        h("div", { id: "tag-chips", class: "chips scroll", role: "group", "aria-label": "Filter by type of attack" })) : null,
      h("div", { id: "inc-list", class: "stack inc-list scroll" }));
    const right = h("div", { class: "detail-pane scroll", id: "detail" },
      state.detail ? incidentDetail(state.detail)
        : h("section", { class: "card" }, h("p", { class: "empty" }, r.id ? "This incident is not available any more." : "Pick an incident on the left to see what happened.")));
    return [h("div", { class: "split" + (r.id ? " has-detail" : "") }, left, right)];
  }

  function viewLive(o) {
    const active = activeNow(state.incidents);
    return [
      pageHead("Live", "Everything Erinix sees, as it happens. Attack events are highlighted."),
      h("section", { class: "card feed-card" },
        h("div", { class: "card-head" }, h("h2", null, "Live activity"), feedControls()),
        h("div", { class: "now-strip" }, h("span", null, "Active now"),
          active.length ? active.map(function (i) {
            const id = safeId(i.id);
            return h("a", { class: "now-chip sev-" + sev(i.severity), href: id ? "#/incidents/" + id : "#/incidents" }, h("span", { "aria-hidden": "true" }, SEVERITY[sev(i.severity)].icon), i.who + (i.tags && i.tags[0] ? " · " + i.tags[0] : ""));
          }) : h("em", { class: "empty" }, "No attack in progress. Erinix is watching.")),
        feedList(FEED_SHOWN.live)),
    ];
  }

  function viewSystem(o) {
    const mode = o.demo ? "Demo data (simulated attacks)" : o.mode === "live" ? "Live monitoring" : "Not monitoring";
    return [
      pageHead("System", "This machine, Erinix itself, and what is coming."),
      h("div", { class: "two-cols" },
        h("section", { class: "card" }, h("h2", null, "Erinix"),
          h("dl", { class: "tech" }, techRow("State", (STATES[o.state] || STATES.stopped).label), techRow("Mode", mode), o.since ? techRow("Watching since", when(o.since)) : null, techRow("Version", o.version))),
        h("section", { class: "card" }, h("h2", null, "This machine"),
          h("dl", { class: "tech", id: "sys-machine" }, machineRows(o).filter(function (r) { return ["Name", "System", "Hardware", "Agent runs as"].indexOf(r[0]) >= 0; }).map(function (r) { return techRow(r[0], r[1]); })))),
      h("section", { class: "card" }, h("h2", null, "Last 24 hours"), h("div", { id: "spark-holder", "data-k": JSON.stringify(o.activity) }, sparkline(o.activity)),
        h("p", { class: "facts" }, h("span", null, h("strong", { "data-live": "events_24h" }, fmt(o.events_24h)), " events checked"),
          h("span", null, h("strong", { "data-live": "alerts_24h" }, fmt(o.alerts_24h)), " alerts raised"))),
      h("section", { class: "card" }, h("h2", null, "Assessment"),
        h("div", { class: "soon" }, h("span", { class: "tag" }, "Coming soon"), h("span", null, "A vulnerability and risk assessment of this machine will live here."))),
    ];
  }

  function viewLocked() {
    const why = state.loginError ? (LOGIN_MESSAGES[state.loginError] || "The sign-in did not work.") : null;
    return h("section", { class: "card lock" }, h("img", { class: "lock-hog", src: "/static/hedgehog.svg", alt: "" }), h("h1", null, "Open Erinix from your terminal"),
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
    document.title = "Erinix · " + (PAGE_NAMES[view] || "Home");
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
    pill.textContent = st.icon + " " + st.label;
    banner.hidden = !o.demo;
    banner.textContent = o.demo ? "Showing demo data: these are simulated attacks, not real monitoring." : "";
    const open = o.incidents ? o.incidents.open : 0;
    count.hidden = !open;
    count.textContent = String(open);
    applyTheme(o.theme);
    updateThemeButton();
    const views = { live: viewLive, incidents: viewIncidents, system: viewSystem, programs: viewPrograms, network: viewNetwork, sources: viewSources };
    const body = (views[view] || viewHome)(o);
    const y = window.scrollY, same = state.renderedView === view;
    const focus = document.activeElement && document.activeElement.classList && document.activeElement.classList.contains("search") ? document.activeElement : null;
    const focusKey = focus ? focus.getAttribute("aria-label") : null, caret = focus ? focus.selectionStart : 0;
    app.replaceChildren.apply(app, [state.error ? h("div", { class: "card", role: "alert" }, state.error) : null].concat(body).filter(Boolean));
    fillIncidentList(); fillTypeChips();
    updateInventory();
    if (same && y) window.scrollTo(0, y);                       // a redraw never throws you back to the top
    state.renderedView = view;
    if (focusKey) {
      const again = Array.prototype.find.call(document.querySelectorAll("input.search"), function (el) { return el.getAttribute("aria-label") === focusKey; });
      if (again) { again.focus(); try { again.setSelectionRange(caret, caret); } catch (e) { /* not every input type allows it */ } }
    }
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
