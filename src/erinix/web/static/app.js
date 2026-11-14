"use strict";
/* Erinix dashboard. Plain JavaScript, no libraries, no external requests.
   Safety rule: everything that comes from the server is put on the page with
   textContent / createTextNode, NEVER as HTML, because alert text can contain
   what an attacker typed into a URL, a user name or a user agent. */
(function () {
  const POLL_MS = 1000;           // overview and incidents: once a second
  const FEED_MS = 500;            // the live stream of events: twice a second
  const FEED_KEEP = 300;
  const FEED_SHOWN = { home: 6, live: 150 };
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
  const PAGE_NAMES = { home: "Home", incidents: "Incidents", live: "Live", system: "System" };

  const state = {
    overview: null, incidents: [], detail: null, selected: null, filter: "open", tag: null,
    csrf: null, version: "", locked: false, error: null, open: {}, lastKey: "", loginError: "", renderedView: "",
    feed: { events: [], lastId: 0, paused: false, pausedAt: null, queued: 0, only: false, loaded: false },
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
    if (hash.indexOf("#/system") === 0 || hash.indexOf("#/sources") === 0) return { view: "system", id: null };
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
      } else if (r.view === "live") {
        incidents = (await request("GET", "/api/incidents?status=open")).incidents;
      }
      // Counters and the chart change all the time: they are updated in place, never by redrawing the page.
      const stable = Object.assign({}, overview);
      ["heartbeat_age", "events_24h", "alerts_24h", "activity"].forEach(function (k) { delete stable[k]; });
      const key = JSON.stringify([stable, incidents, detail, state.filter, state.tag, r, selected,
        r.view === "live" ? activeNow(incidents).map(function (i) { return i.id; }) : null]);
      state.overview = overview; state.incidents = incidents; state.detail = detail; state.selected = selected; state.error = null;
      if (key !== state.lastKey) { state.lastKey = key; render(); }
      updateLive(overview);
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
    return f.events.filter(function (e) { return (!f.only || e.alert) && (f.pausedAt === null || e.id <= f.pausedAt); });
  }
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
  function feedList(limit) {
    const ul = h("ul", { id: "feed", class: "feed", "data-limit": limit });
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
  function viewHome(o) {
    const top = (o.incidents && o.incidents.top) || [], n = o.incidents ? o.incidents.open : 0;
    const st = STATES[o.state] || STATES.stopped;
    const total = o.sources.length, watching = o.sources.filter(function (x) { return x.state === "ok"; }).length, blind = total - watching;
    let headline, lead;
    if (o.state === "stopped") { headline = "Erinix is not watching"; lead = "Nothing is being checked right now. Start the agent, or load demo data to look around."; }
    else if (!top.length) { headline = "Everything looks fine"; lead = "Nothing suspicious is happening." + (total ? " Erinix is watching " + watching + " of " + total + " sources." : ""); }
    else { headline = top[0].headline; lead = top[0].summary; }
    const first = top.length ? safeId(top[0].id) : null;
    return [
      h("section", { class: "hero card state-" + (STATES[o.state] ? o.state : "stopped") },
        h("div", { class: "hero-body" },
          h("div", { class: "hero-icon", "aria-hidden": "true" }, iconEl(st.sprite)),
          h("div", null, h("p", { class: "eyebrow" }, st.label), h("h1", null, headline), h("p", { class: "lead" }, lead),
            h("div", { class: "hero-actions" },
              first ? h("a", { class: "btn primary", href: "#/incidents/" + first }, "See what happened") : null,
              h("a", { class: "btn", href: "#/live" }, "Watch live")))),
        h("img", { class: "hero-hog", src: "/static/hedgehog.svg", alt: "" })),
      h("section", { class: "card" }, h("h2", null, "What needs you"),
        top.length ? h("div", { class: "stack" }, top.map(function (i) { return incidentRow(i, "home"); })) : h("p", { class: "empty" }, "Nothing needs your attention."),
        n > top.length ? h("p", null, h("a", { href: "#/incidents" }, "See all " + n + " incidents")) : null),
      h("section", { class: "card feed-card compact" },
        h("div", { class: "card-head" }, h("h2", null, "Happening now"), h("a", { class: "more-link", href: "#/live" }, "Open the live view")),
        feedList(FEED_SHOWN.home)),
      h("p", { class: "facts" },
        h("span", { class: blind ? "warn" : "ok" }, (blind ? "▲ " : "✔ ") + "Watching " + watching + " of " + total + " sources"),
        h("span", null, h("strong", { "data-live": "events_24h" }, fmt(o.events_24h)), " events checked today"),
        h("span", null, h("strong", { "data-live": "alerts_24h" }, fmt(o.alerts_24h)), " " + plural(o.alerts_24h, "alert", "alerts") + " raised"),
        blind ? h("a", { href: "#/system" }, blind + " " + plural(blind, "blind spot", "blind spots")) : null),
    ];
  }

  function viewIncidents(o) {
    const r = route();
    const tabs = [["open", "Open"], ["closed", "Closed"], ["all", "All"]];
    const counts = {};
    state.incidents.forEach(function (i) { (i.tags || []).forEach(function (t) { counts[t] = (counts[t] || 0) + 1; }); });
    const names = Object.keys(counts).sort(function (a, b) { return a.localeCompare(b); });
    const list = state.incidents.filter(function (i) { return !state.tag || (i.tags || []).indexOf(state.tag) >= 0; });
    const left = h("section", { class: "list-pane card" },
      h("div", { class: "tabs", role: "group", "aria-label": "Filter incidents" }, tabs.map(function (t) {
        return h("button", { type: "button", "aria-pressed": state.filter === t[0] ? "true" : "false",
          onclick: function () { state.filter = t[0]; state.lastKey = ""; refresh(); } }, t[1]);
      })),
      names.length ? h("div", { class: "chips", role: "group", "aria-label": "Filter by type of attack" },
        h("button", { type: "button", "aria-pressed": state.tag === null ? "true" : "false", onclick: function () { state.tag = null; state.lastKey = ""; render(); } }, "All types"),
        names.map(function (t) {
          return h("button", { type: "button", "aria-pressed": state.tag === t ? "true" : "false", onclick: function () { state.tag = state.tag === t ? null : t; state.lastKey = ""; render(); } }, t + " " + counts[t]);
        })) : null,
      list.length ? h("div", { class: "stack" }, list.map(function (i) { return incidentRow(i, "list"); }))
        : h("p", { class: "empty" }, state.filter === "open" ? "Nothing needs your attention." : "No incidents here."));
    const right = h("div", { class: "detail-pane", id: "detail" },
      state.detail ? incidentDetail(state.detail)
        : h("section", { class: "card" }, h("p", { class: "empty" }, r.id ? "This incident is not available any more." : "Pick an incident on the left to see what happened.")));
    return [pageHead("Incidents", "Everything suspicious, grouped by who is behind it."), h("div", { class: "split" + (r.id ? " has-detail" : "") }, left, right)];
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

  function swatch(color) {
    const dot = h("i");
    if (/^#[0-9a-fA-F]{6}$/.test(color)) dot.style.background = color;
    return dot;
  }
  function viewSystem(o) {
    const mode = o.demo ? "Demo data (simulated attacks)" : o.mode === "live" ? "Live monitoring" : "Not monitoring";
    const rows = o.sources.map(function (s) {
      return h("tr", null, h("td", null, s.name), h("td", null, s.state === "ok" ? h("span", { class: "ok" }, "✔ Watching") : h("span", { class: "warn" }, "▲ Blind")), h("td", null, s.detail || ""));
    });
    return [
      pageHead("System", "What Erinix watches, how it looks, and what is coming."),
      h("section", { class: "card" }, h("h2", null, "Status"),
        h("dl", { class: "tech" }, techRow("State", (STATES[o.state] || STATES.stopped).label), techRow("Mode", mode), o.since ? techRow("Watching since", when(o.since)) : null, techRow("Version", o.version))),
      h("section", { class: "card" }, h("h2", null, "What Erinix watches"),
        rows.length ? h("table", null, h("thead", null, h("tr", null, h("th", null, "Source"), h("th", null, "Status"), h("th", null, "Details"))), h("tbody", null, rows))
          : h("p", { class: "empty" }, "No sources are configured yet."),
        o.blind_spots.length ? h("ul", { class: "plain" }, o.blind_spots.map(function (b) { return h("li", null, h("span", { class: "warn" }, "▲ "), "Blind spot: " + b); })) : null),
      h("section", { class: "card" }, h("h2", null, "Last 24 hours"), h("div", { id: "spark-holder", "data-k": JSON.stringify(o.activity) }, sparkline(o.activity)),
        h("p", { class: "facts" }, h("span", null, h("strong", { "data-live": "events_24h" }, fmt(o.events_24h)), " events checked"),
          h("span", null, h("strong", { "data-live": "alerts_24h" }, fmt(o.alerts_24h)), " alerts raised"))),
      h("section", { class: "card" }, h("h2", null, "Appearance"),
        h("div", { class: "palettes", role: "group", "aria-label": "Appearance" }, (o.themes || []).map(function (p) {
          return h("button", { class: "pal", type: "button", "data-theme": p.name, "aria-pressed": o.theme === p.name ? "true" : "false", onclick: function () { chooseTheme(p.name); } },
            h("span", { class: "swatches" }, (p.swatch || []).map(swatch)), h("strong", null, p.label), h("span", { class: "blurb" }, p.blurb));
        }))),
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
    const body = view === "live" ? viewLive(o) : view === "incidents" ? viewIncidents(o) : view === "system" ? viewSystem(o) : viewHome(o);
    const y = window.scrollY, same = state.renderedView === view;
    app.replaceChildren.apply(app, [state.error ? h("div", { class: "card", role: "alert" }, state.error) : null].concat(body).filter(Boolean));
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
