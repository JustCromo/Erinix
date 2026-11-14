// Runs the real dashboard script (app.js) in jsdom with a fake server and prints a JSON report.
// Usage: node dashboard_check.mjs <static dir>      (needs the "jsdom" npm package)
import { createRequire } from "module";
import fs from "fs";
const require = createRequire(import.meta.url);
const { JSDOM } = require("jsdom");
const dir = process.argv[2];
const html = fs.readFileSync(dir + "/index.html", "utf8").replace(/<script[^>]*><\/script>/, "").replace(/<link rel="stylesheet"[^>]*>/g, "");
const script = fs.readFileSync(dir + "/app.js", "utf8");
const sleep = ms => new Promise(r => setTimeout(r, ms));
const now = () => Date.now() / 1000;

// ------------------------------------------------------------------ fixtures
const alertObj = (over = {}) => ({
  id: "a".repeat(32), tag: "SQL injection", area: "website", headline: "Someone tried to attack the database from 192.168.50.31", why: "Database commands in a request.",
  next_steps: ["Check the logs"], severity: "high", status: "open", first_seen: now() - 600, updated: now() - 60, remote: "192.168.50.31", progress: null,
  technical: { rule: "web-sqli-attempt", kind: "indicator", description: "d", response: "report_only", step: "s", mitre: ["T1190"], anchor_pid: null, revision: 1, evidence: [["s", ["e1"]]], detail: "" },
  steps: [], timeline: [], ...over });
const incident = (over = {}) => ({
  id: "iabc123def4", who: "192.168.50.31", local: false, severity: "high", status: "open", headline: "Someone at 192.168.50.31 tried 2 different attacks on your website",
  summary: "Most serious: Someone tried to attack the database. Database commands in a request.", tags: ["SQL injection", "Scanning"], area: "website",
  alert_count: 2, open_alerts: 2, first_seen: now() - 600, updated: now() - 60, ...over });
const detailOf = (inc, over = {}) => ({ ...inc, alerts: [alertObj()], timeline: [
    { id: 1, time: now() - 100, label: "Web request", summary: "GET /admin → 404", remote: "192.168.50.31", step: "s", severity: "low", tag: "Scanning", alert: "a".repeat(32), attack: "x" },
    { id: 2, time: now() - 50, label: "Web request", summary: "GET /p?id=1 UNION SELECT → 200", remote: "192.168.50.31", step: "s", severity: "high", tag: "SQL injection", alert: "a".repeat(32), attack: "x" }],
  next_steps: ["Check the web app logs", "Consider blocking 192.168.50.31"], ...over });
const THEMES = ["auto", "light", "dark"].map(n => ({ name: n, label: n.toUpperCase(), blurb: "About " + n, swatch: ["#101010", "#e8a66a", "#a9c98a", "#d9b48b"] }));
const SOURCES = [{ name: "SSH logins", state: "ok" }, { name: "Web log", state: "ok" }, { name: "Programs", state: "ok" }, { name: "Kernel", state: "blind", detail: "need root" }];
const overview = (over = {}) => {
  const { top: given, ...rest } = over;
  const top = given || [incident(), incident({ id: "iccc", who: "203.0.113.50", severity: "critical", tags: ["Password guessing"], headline: "Someone is guessing SSH passwords from 203.0.113.50" }), incident({ id: "iddd", who: "This machine", local: true, tags: ["Remote control"], headline: "A web program started a command line" })];
  return { state: "critical", headline: "x", demo: false, mode: "live", since: now() - 3600, heartbeat_age: 1, open: { total: top.length, low: 0, medium: 0, high: top.length, critical: 0 },
    dismissed: 0, attention: [], events_24h: 1234, alerts_24h: 3, activity: Array.from({ length: 48 }, (_, i) => ({ t: i * 1800, events: 10 + (i % 7), alerts: i === 40 ? 1 : 0 })),
    sources: SOURCES, blind_spots: ["Kernel: need root"], version: "9.9.9", incidents: { open: top.length, top }, theme: "auto", themes: THEMES, ...rest };
};
const mkEvent = (id, o = {}) => ({ id, time: now() - 10 + id / 100, kind: "web.request", label: "Web request", summary: "GET /p" + id + " → 200", remote: "10.0.0.1", alert: null, step: null, severity: null, tag: "", incident: null, ...o });

async function run({ hash = "#/", data = {}, status = 200, reject = false, needsLogin = false, login = "ok", preSignedIn = false, wait = 250 } = {}) {
  const dom = new JSDOM(html, { url: "http://127.0.0.1:8421/" + hash, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window, calls = [];
  const inc1 = incident();
  const live = { overview: overview(), incidents: [inc1, incident({ id: "iccc", who: "203.0.113.50", severity: "critical", tags: ["Password guessing"] })], details: {}, ...data };
  live.details = { [inc1.id]: detailOf(inc1), ...(data.details || {}) };
  let signedIn = !needsLogin || preSignedIn;
  w.fetch = async (path, opts = {}) => {
    calls.push({ path, method: opts.method || "GET", headers: opts.headers || {}, body: opts.body });
    if (reject) throw new TypeError("network down");
    const ok = (body, st = 200) => ({ ok: st < 400, status: st, json: async () => body });
    if (path === "/api/login") {
      if (login === "ok") { signedIn = true; return ok({ ok: true }); }
      return ok({ error: login }, login === "unavailable" ? 503 : 403);
    }
    if (status === 401 || !signedIn) return ok({ error: "locked" }, 401);
    if (path.startsWith("/api/session")) return ok({ csrf: "tok", version: "9.9.9" });
    if (path.startsWith("/api/overview")) return ok(live.overview);
    if (path.startsWith("/api/events")) {
      const q = new URL(path, "http://x").searchParams, all = live.events || [], limit = Number(q.get("limit") || 100);
      const list = q.has("after") ? all.filter(e => e.id > Number(q.get("after"))).slice(0, limit) : all.slice(-limit);
      return ok({ events: list, last_id: live.lastId !== undefined ? live.lastId : (all.length ? all[all.length - 1].id : 0) });
    }
    if (path.startsWith("/api/incidents/") && path.endsWith("/status")) return ok({ ok: true, changed: 1 });
    if (path.startsWith("/api/incidents/")) { const d = live.details[decodeURIComponent(path.slice(15))]; return d ? ok(d) : ok({ error: "Not Found" }, 404); }
    if (path.startsWith("/api/incidents")) {
      const st = new URL(path, "http://x").searchParams.get("status") || "open";
      return ok({ incidents: live.incidents.filter(i => st === "all" || (st === "open" ? i.status === "open" : i.status === "closed")) });
    }
    if (path === "/api/settings") { live.themePosted = JSON.parse(opts.body).theme; live.overview = { ...live.overview, theme: live.themePosted }; return ok({ ok: true }); }   // the server remembers it
    return ok({}, 404);
  };
  w.eval(script);
  await sleep(wait);
  return { w, doc: w.document, calls, live, close: () => w.close() };
}
const checks = {};
const text = (w, sel) => (w.document.querySelector(sel) || {}).textContent || "";

// ------------------------------------------------------------------- HOME
{
  const t = await run();
  const d = t.doc, rows = [...d.querySelectorAll(".inc")];
  checks.home_hero_says_the_top_incident = text(t.w, ".hero h1") === "Someone at 192.168.50.31 tried 2 different attacks on your website" && text(t.w, ".hero .eyebrow") === "Needs you now" && text(t.w, ".hero .lead").startsWith("Most serious");
  checks.home_lists_three_incidents = rows.length === 3 && rows[0].querySelector(".inc-who").textContent === "192.168.50.31" && rows[0].textContent.includes("SQL injection") && rows[0].textContent.includes("See what happened →");
  checks.home_links_open_the_incident = rows[0].getAttribute("href") === "#/incidents/iabc123def4" && d.querySelector(".hero .btn.primary").getAttribute("href") === "#/incidents/iabc123def4";
  checks.home_facts = text(t.w, ".facts").includes("Watching 3 of 4 sources") && text(t.w, ".facts").includes("events checked today") && !!d.querySelector('.facts a[href="#/system"]');
  checks.home_has_a_small_live_feed = !!d.querySelector("#feed") && d.querySelector("#feed").getAttribute("data-limit") === "6" && !!d.querySelector('.feed-card a[href="#/live"]');
  checks.home_has_no_duplicate_counters = d.querySelectorAll(".stat").length === 0 && !text(t.w, ".hero").includes("open alerts");
  checks.pill_and_nav = text(t.w, "#pill") === "✖ Needs you now" && text(t.w, "#nav-count") === "3" && !d.getElementById("nav-count").hidden && d.querySelectorAll("#nav a").length === 4;
  checks.nav_marks_the_page = d.querySelector('#nav a[data-view="home"]').getAttribute("aria-current") === "page" && d.title === "Erinix · Home";
  checks.footer_version = text(t.w, "#version") === "v9.9.9";
  t.close();
  const q = await run({ data: { overview: overview({ state: "protected", top: [] }) } });
  checks.home_quiet = text(q.w, ".hero h1") === "Everything looks fine" && text(q.w, "#pill") === "✔ All quiet" && !q.doc.querySelector(".hero .btn.primary") && text(q.w, ".card .empty").includes("Nothing needs your attention") && q.doc.getElementById("nav-count").hidden;
  q.close();
  const s = await run({ data: { overview: overview({ state: "stopped", top: [], sources: [] }) } });
  checks.home_stopped = text(s.w, ".hero h1") === "Erinix is not watching" && text(s.w, "#pill") === "■ Not running";
  s.close();
  const a = await run({ data: { overview: overview({ state: "attention", demo: true }) } });
  checks.pill_attention_and_demo_banner = text(a.w, "#pill") === "▲ Worth a look" && !a.doc.getElementById("banner").hidden && text(a.w, "#banner").includes("demo data");
  a.close();
}

// -------------------------------------------------------------- INCIDENTS
{
  const t = await run({ hash: "#/incidents", wait: 500 });
  const d = t.doc;
  checks.incidents_list_and_detail = d.querySelectorAll(".list-pane .inc").length === 2 && d.querySelector(".list-pane .inc").className.includes("selected") && !!d.querySelector(".detail") && t.calls.some(c => c.path === "/api/incidents/iabc123def4");
  checks.incidents_detail_content = text(t.w, ".d-who") === "192.168.50.31" && text(t.w, ".d-why").startsWith("Most serious") && d.querySelectorAll(".todo li").length === 2 && d.querySelectorAll(".story li").length === 2 && d.querySelectorAll(".attack").length === 1;
  checks.incidents_story_tags_events = text(t.w, ".story li:first-child").includes("Scanning") && text(t.w, ".story li:first-child").includes("GET /admin → 404");
  checks.incidents_tabs_and_chips = d.querySelectorAll(".tabs button").length === 3 && [...d.querySelectorAll(".chips button")].map(b => b.textContent).join("|") === "All types|Password guessing 1|Scanning 1|SQL injection 1";
  d.querySelectorAll(".chips button")[3].click();
  await sleep(50);
  checks.incidents_chip_filters = d.querySelectorAll(".list-pane .inc").length === 1 && d.querySelectorAll(".chips button[aria-pressed='true']").length === 1;
  d.querySelectorAll(".chips button")[0].click();
  await sleep(50);
  checks.incidents_chip_clears = d.querySelectorAll(".list-pane .inc").length === 2;
  d.querySelectorAll(".tabs button")[1].click();
  await sleep(1300);
  checks.incidents_closed_tab_asks_the_server = t.calls.some(c => c.path === "/api/incidents?status=closed") && text(t.w, ".list-pane .empty") === "No incidents here.";
  t.close();

  const c = await run({ hash: "#/incidents/iabc123def4", wait: 500 });
  checks.incident_route_has_back_link = c.doc.querySelector(".split").className.includes("has-detail") && c.doc.querySelector(".back").getAttribute("href") === "#/incidents";
  c.doc.querySelector('[data-action="incident-status"]').click();
  await sleep(100);
  const post = c.calls.find(x => x.method === "POST");
  checks.incident_close_request = !!post && post.path === "/api/incidents/iabc123def4/status" && post.headers["X-Erinix-CSRF"] === "tok" && post.body === '{"status":"closed"}';
  c.close();

  const r = await run({ hash: "#/incidents/iabc123def4", data: { details: { iabc123def4: detailOf(incident({ status: "closed" })) }, incidents: [incident({ status: "closed" })] }, wait: 500 });
  checks.incident_reopen_button = text(r.w, '[data-action="incident-status"]') === "Reopen";
  r.close();

  const gone = await run({ hash: "#/incidents/inope", wait: 500 });
  checks.incident_not_available = text(gone.w, ".detail-pane .empty") === "This incident is not available any more.";
  gone.close();

  const open = await run({ hash: "#/incidents", wait: 500 });
  const det = open.doc.querySelector("details.more");
  det.open = true; det.dispatchEvent(new open.w.Event("toggle"));
  open.live.details.iabc123def4 = detailOf(incident(), { next_steps: ["Check the web app logs", "A new piece of advice"] });
  await sleep(1400);
  checks.incident_details_stay_open_while_it_updates = open.doc.querySelectorAll(".todo li").length === 2 && text(open.w, ".todo li:last-child") === "A new piece of advice" && open.doc.querySelector("details.more").open === true;
  open.close();
}
{ // steps of an attack in progress
  const steps = [
    { index: 1, label: "A web program starts a command line", state: "done", time: now() - 2, detail: "bash (user 33)", count: 1 },
    { index: 2, label: "The command line connects <b>out</b>", state: "current", time: null, detail: "", count: 0 },
    { index: 3, label: "It gains full control (root)", state: "pending", time: null, detail: "", count: 0 }];
  const inc = incident();
  const t = await run({ hash: "#/incidents", data: { details: { [inc.id]: detailOf(inc, { alerts: [alertObj({ steps, progress: { done: 1, total: 3, complete: false }, technical: { ...alertObj().technical, kind: "chain" } })] }) } }, wait: 500 });
  checks.steps_states = t.doc.querySelectorAll(".tl.done").length === 1 && t.doc.querySelectorAll(".tl.current").length === 1 && t.doc.querySelectorAll(".tl.pending").length === 1;
  checks.steps_content = text(t.w, ".tl.done .tl-label") === "A web program starts a command line" && text(t.w, ".tl.done .tl-detail") === "bash (user 33)" && text(t.w, ".tl.current .tl-wait") === "waiting…" && /\d\d:\d\d:\d\d/.test(text(t.w, ".tl.done time"));
  checks.steps_fresh_marked = t.doc.querySelector(".tl.done").className.includes("fresh") && !t.doc.querySelector(".tl.pending").className.includes("fresh");
  checks.steps_hostile_label = text(t.w, ".tl.current .tl-label") === "The command line connects <b>out</b>" && t.doc.querySelectorAll(".timeline b").length === 0;
  checks.story_shows_the_possible_next_step = text(t.w, ".story .waiting").includes("Possible next step: The command line connects <b>out</b>");
  t.close();
  const many = alertObj({ steps: [{ index: 1, label: "Many failed logins", state: "done", time: now() - 60, detail: "POST /login → 401", count: 8 }] });
  const c = await run({ hash: "#/incidents", data: { details: { [inc.id]: detailOf(inc, { alerts: [many] }) } }, wait: 500 });
  checks.steps_count_repeats = text(c.w, ".tl-detail") === "8 times · last: POST /login → 401";
  c.close();
}
{ // hostile text everywhere
  const evil = '<img src=x onerror="window.__pwned=1">';
  const inc = incident({ who: evil, headline: evil, summary: "</script><script>window.__pwned=1</script>", tags: [evil, "<b>x</b>"], severity: '"><script>x</script>' });
  const alert = alertObj({ headline: evil, tag: evil, why: evil, next_steps: [evil], remote: "<i>x</i>", severity: '"><x>', technical: { ...alertObj().technical, rule: "<svg onload=window.__pwned=1>", detail: "<iframe src=//evil>" } });
  const det = detailOf(inc, { alerts: [alert], next_steps: ["<b>bold</b>"], timeline: [{ id: 1, time: now(), label: evil, summary: evil, remote: evil, step: "s", severity: "high", tag: evil, alert: "a" }] });
  for (const hash of ["#/", "#/incidents"]) {
    const t = await run({ hash, data: { overview: overview({ top: [inc] }), incidents: [inc], details: { [inc.id]: det } }, wait: 500 });
    const d = t.doc;
    d.querySelectorAll("details.more").forEach(x => { x.open = true; });
    const imgs = [...d.querySelectorAll("img")];
    checks["hostile_no_execution" + hash] = t.w.__pwned === undefined;
    checks["hostile_only_our_own_images" + hash] = imgs.every(i => i.getAttribute("src").startsWith("/static/")) && d.querySelectorAll("iframe, svg[onload], b, i, script").length === 0;
    checks["hostile_shown_as_text" + hash] = text(t.w, ".inc-title").includes(evil) && text(t.w, ".inc-who") === evil;
    checks["hostile_severity_falls_back" + hash] = d.querySelector(".inc").className.includes("sev-low") && !d.querySelector(".inc").className.includes("<");
    checks["hostile_no_scripts_added" + hash] = d.scripts.length === 0;
    t.close();
  }
}

// ------------------------------------------------------------------- LIVE
{
  const events = [mkEvent(1), mkEvent(2), mkEvent(3, { alert: "a".repeat(32), step: "s", severity: "high", label: "Program started", summary: "bash (user 33)", tag: "Remote control", incident: "iabc123def4" })];
  const t = await run({ hash: "#/live", data: { events }, wait: 900 });
  const d = t.doc, rows = () => [...d.querySelectorAll("#feed li.ev")];
  checks.feed_initial = rows().length === 3 && rows()[0].dataset.id === "3" && rows()[2].dataset.id === "1";
  checks.feed_flagged_row = rows()[0].className.includes("flagged") && rows()[0].className.includes("sev-high") && !rows()[1].className.includes("flagged");
  checks.feed_flagged_row_links_to_its_incident = rows()[0].querySelector("a.tag").textContent === "Remote control" && rows()[0].querySelector("a.tag").getAttribute("href") === "#/incidents/iabc123def4";
  checks.live_active_strip = d.querySelectorAll(".now-chip").length === 2 && text(t.w, ".now-strip").includes("Active now") && text(t.w, ".now-chip").includes("192.168.50.31");
  const firstNode = rows()[0], card = d.querySelector(".now-chip");
  t.live.events.push(mkEvent(4), mkEvent(5));
  await sleep(900);
  checks.feed_appends = rows().length === 5 && rows()[0].dataset.id === "5" && rows().includes(firstNode);
  checks.feed_requests_only_newer = t.calls.some(c => c.path.startsWith("/api/events?after=3"));
  checks.feed_no_redraw = d.querySelector(".now-chip") === card;
  d.querySelector('[data-action="pause"]').click();
  t.live.events.push(mkEvent(6));
  await sleep(900);
  checks.feed_pause_holds = rows().length === 5 && d.querySelector('[data-action="pause"]').textContent === "Resume (1 new)";
  d.querySelector('[data-action="pause"]').click();
  checks.feed_resume_shows = rows().length === 6 && rows()[0].dataset.id === "6" && d.querySelector('[data-action="pause"]').textContent === "Pause";
  d.querySelector('[data-action="only"]').click();
  checks.feed_only_suspicious = rows().length === 1 && rows()[0].dataset.id === "3" && d.querySelector('[data-action="only"]').getAttribute("aria-pressed") === "true";
  t.live.events.push(mkEvent(7));
  await sleep(900);
  checks.feed_filter_keeps_filtering = rows().length === 1;
  d.querySelector('[data-action="only"]').click();
  checks.feed_filter_off = rows().length === 7;
  t.live.events.length = 0; t.live.lastId = 0;
  await sleep(900);
  checks.feed_store_cleared = rows().length === 0 && !!d.querySelector(".ev-empty");
  checks.feed_polls_twice_a_second = t.calls.filter(c => c.path.startsWith("/api/events")).length >= 5;
  t.close();

  const evil = '<img src=x onerror="window.__pwned=1">';
  const many = Array.from({ length: 400 }, (_, i) => mkEvent(i + 1));
  many[399] = mkEvent(400, { label: evil, summary: evil, remote: evil, alert: "b".repeat(32), step: evil, severity: '"><script>x</script>', tag: evil, incident: "../../x" });
  const h = await run({ hash: "#/live", data: { events: many }, wait: 900 });
  const hd = h.doc, hrows = () => [...hd.querySelectorAll("#feed li.ev")];
  checks.feed_hostile_is_text = h.w.__pwned === undefined && hrows()[0].textContent.includes(evil) && hd.querySelectorAll("#feed img, #feed script").length === 0;
  checks.feed_hostile_severity_falls_back = hrows()[0].className === "ev flagged sev-low";
  checks.feed_unsafe_incident_id_is_not_a_link = !hrows()[0].querySelector("a") && hrows()[0].querySelector(".tag").textContent === evil;
  checks.feed_first_fill_is_bounded = hrows().length <= 80;
  for (let i = 401; i <= 700; i++) h.live.events.push(mkEvent(i));
  await sleep(1700);
  checks.feed_flood_is_bounded = hrows().length <= 150 && hrows()[0].dataset.id === "700";
  h.close();

  const quiet = await run({ hash: "#/live", data: { incidents: [incident({ updated: now() - 3600 })] }, wait: 400 });
  checks.live_quiet = text(quiet.w, ".now-strip").includes("No attack in progress") && quiet.doc.querySelectorAll(".now-chip").length === 0;
  quiet.close();
}

// ----------------------------------------------------------------- SYSTEM
{
  const t = await run({ hash: "#/system", wait: 400 });
  const d = t.doc;
  checks.system_sources_and_blind_spots = d.querySelectorAll("table tbody tr").length === 4 && text(t.w, "table").includes("Blind") && text(t.w, ".plain").includes("Blind spot: Kernel: need root");
  checks.system_status = text(t.w, "#app").includes("Live monitoring") && text(t.w, "#app").includes("9.9.9") && text(t.w, "#app").includes("Coming soon");
  const pals = [...d.querySelectorAll(".pal")];
  checks.system_theme_picker = pals.length === 3 && pals[0].getAttribute("aria-pressed") === "true" && pals[1].getAttribute("aria-pressed") === "false" && pals[0].querySelectorAll("i").length === 4;
  checks.system_swatches_use_the_given_colour = pals[0].querySelector("i").style.background !== "";
  checks.system_auto_leaves_the_system_in_charge = !d.documentElement.hasAttribute("data-theme");
  pals[2].click();
  await sleep(1300);
  const post = t.calls.find(c => c.path === "/api/settings");
  checks.system_theme_request = !!post && post.method === "POST" && post.body === '{"theme":"dark"}' && post.headers["X-Erinix-CSRF"] === "tok";
  checks.system_theme_applies_at_once = d.documentElement.getAttribute("data-theme") === "dark";
  [...d.querySelectorAll(".pal")][0].click();
  await sleep(1300);
  checks.system_auto_again_removes_the_forced_theme = !d.documentElement.hasAttribute("data-theme");
  t.close();

  const o = await run({ hash: "#/", data: { overview: overview({ theme: "dark" }) }, wait: 400 });
  checks.theme_from_the_store_is_applied = o.doc.documentElement.getAttribute("data-theme") === "dark";
  o.live.overview = overview({ theme: "x'; } body{display:none" });
  await o.w.__erinix.refresh();
  checks.unknown_theme_is_ignored = o.doc.documentElement.getAttribute("data-theme") === "dark";
  o.close();

  const evil = overview({ themes: [{ name: "auto", label: "<b>L</b>", blurb: "<i>b</i>", swatch: ["red; background:url(http://evil/x)", "#e8a66a", "not a colour", "#a9c98a"] }] });
  const e = await run({ hash: "#/system", data: { overview: evil }, wait: 400 });
  const dots = [...e.doc.querySelectorAll(".pal i")];
  checks.theme_swatches_are_checked = dots.length === 4 && dots[0].style.background === "" && dots[2].style.background === "" && dots[1].style.background !== "" && e.doc.querySelectorAll(".pal b, .pal i b").length === 0;
  e.close();
}

// ------------------------------------------------------------ counters etc.
{
  const o = await run({ hash: "#/" });
  const od = o.doc, row = od.querySelector(".inc"), base = o.live.overview;
  const same = extra => overview({ top: base.incidents.top, since: base.since, ...extra });
  o.live.overview = same({ events_24h: 1299, alerts_24h: 9 });
  await o.w.__erinix.refresh();
  checks.counters_update_in_place = [...od.querySelectorAll('[data-live="events_24h"]')].length >= 1 && [...od.querySelectorAll('[data-live="events_24h"]')].every(el => /1.?299/.test(el.textContent)) && od.querySelector(".inc") === row;
  o.live.overview = same({ events_24h: 1299, alerts_24h: 9, activity: Array.from({ length: 48 }, (_, i) => ({ t: i * 1800, events: 50 + i, alerts: 0 })) });
  await o.w.__erinix.refresh();
  checks.chart_and_counters_never_redraw_the_page = od.querySelector(".inc") === row;
  o.live.overview = same({ headline: "x", state: "critical", incidents: { open: 4, top: base.incidents.top } });
  await o.w.__erinix.refresh();
  checks.real_changes_still_redraw = od.querySelector(".inc") !== row && text(o.w, "#nav-count") === "4";
  o.close();
}

// ------------------------------------------------------- signed out, offline
{
  const t = await run({ status: 401 });
  checks.locked_screen = text(t.w, ".lock").includes("erinix ui") && text(t.w, "#pill") === "Signed out";
  t.close();
  const o = await run({ reject: true });
  checks.offline_message = text(o.w, "#app").includes("Cannot reach Erinix") && text(o.w, "#pill") === "Offline";
  o.close();
}

// ----------------------------------------------------------------- sign-in
{
  const token = "T".repeat(43);
  const t = await run({ hash: "#login=" + token, needsLogin: true });
  const logins = t.calls.filter(c => c.path === "/api/login");
  checks.login_sent_once = logins.length === 1 && logins[0].method === "POST" && logins[0].body === JSON.stringify({ token }) && logins[0].headers["Content-Type"] === "application/json";
  checks.login_token_removed_from_address = t.w.location.hash === "" && !t.w.location.href.includes(token);
  checks.login_token_never_in_urls = t.calls.every(c => !c.path.includes(token));
  checks.login_then_dashboard = text(t.w, ".hero h1") !== "" && !t.doc.querySelector(".lock");
  t.close();
  const d = await run({ hash: "#login=" + token, needsLogin: true, login: "invalid", preSignedIn: true, wait: 900 });
  checks.login_duplicate_open_still_works = !!d.doc.querySelector(".hero") && !d.doc.querySelector(".lock");
  d.close();
  for (const [code, words] of [["invalid", "already used"], ["expired", "expired"], ["unavailable", "could not read"]]) {
    const f = await run({ hash: "#login=" + token, needsLogin: true, login: code, wait: 900 });
    checks["login_" + code + "_message"] = text(f.w, ".lock .warn").includes(words) && text(f.w, ".lock").includes("erinix ui") && f.w.location.hash === "";
    f.close();
  }
  const p = await run({ needsLogin: true });
  checks.locked_before_paste = !!p.doc.querySelector(".lock");
  p.w.location.hash = "#login=" + token;
  await sleep(500);
  checks.login_by_pasting_into_open_tab = !!p.doc.querySelector(".hero") && p.w.location.hash === "" && p.calls.filter(c => c.path === "/api/login").length === 1;
  p.close();
  for (const bad of ["#login=short", "#login=" + "x".repeat(200), "#login=" + "a".repeat(30) + "<b>", "#login="]) {
    const b = await run({ hash: bad, needsLogin: true });
    checks["login_ignores_" + bad.slice(0, 18)] = b.calls.every(c => c.path !== "/api/login") && !!b.doc.querySelector(".lock");
    b.close();
  }
}
console.log(JSON.stringify({ checks }));
process.exit(0);
