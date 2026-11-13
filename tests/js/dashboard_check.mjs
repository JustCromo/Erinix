// Runs the real dashboard script (app.js) in jsdom with a fake server and prints a JSON report.
// Usage: node dashboard_check.mjs <static dir>      (needs the "jsdom" npm package)
import { createRequire } from "module";
import fs from "fs";
const require = createRequire(import.meta.url);
const { JSDOM } = require("jsdom");
const dir = process.argv[2];
const html = fs.readFileSync(dir + "/index.html", "utf8").replace(/<script[^>]*><\/script>/, "").replace(/<link rel="stylesheet"[^>]*>/, "");
const script = fs.readFileSync(dir + "/app.js", "utf8");

const alert = (over = {}) => ({
  id: "a".repeat(32), headline: "Someone is guessing SSH passwords from 203.0.113.50", why: "Many failed logins.", next_steps: ["Change the password"],
  severity: "high", status: "open", first_seen: Date.now() / 1000 - 600, updated: Date.now() / 1000 - 60, remote: "203.0.113.50",
  progress: { done: 2, total: 3, complete: false },
  technical: { rule: "ssh-bruteforce-success", kind: "chain", description: "d", response: "report_only", step: "s", mitre: ["T1110.001"], anchor_pid: null, revision: 2, evidence: [["s", ["e1"]]], detail: "" }, ...over });
const overview = (over = {}) => ({
  state: "attention", headline: "1 thing needs attention", demo: false, mode: "live", since: Date.now() / 1000 - 3600, heartbeat_age: 1,
  open: { total: 1, low: 0, medium: 0, high: 1, critical: 0 }, dismissed: 0, attention: [alert()], events_24h: 1234, alerts_24h: 3,
  activity: Array.from({ length: 48 }, (_, i) => ({ t: i * 1800, events: 10 + (i % 7), alerts: i === 40 ? 1 : 0 })),
  sources: [{ name: "SSH logins", state: "ok" }, { name: "Caddy log", state: "missing", detail: "not set up" }],
  blind_spots: ["Caddy log: not set up"], version: "9.9.9", ...over });

async function run({ hash = "#/", data = {}, status = 200, reject = false, needsLogin = false, login = "ok", preSignedIn = false, wait = 150 } = {}) {
  const dom = new JSDOM(html, { url: "http://127.0.0.1:8421/" + hash, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window, calls = [];
  const live = { overview: overview(), alerts: [alert()], ...data };
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
    if (path.startsWith("/api/alerts/") && path.endsWith("/status")) return ok({ ok: true });
    if (path.startsWith("/api/alerts")) return ok({ alerts: live.alerts });
    return ok({}, 404);
  };
  w.eval(script);
  await new Promise(r => setTimeout(r, wait));
  return { w, calls, live, close: () => w.close() };
}
const checks = {};
const text = (w, sel) => (w.document.querySelector(sel) || {}).textContent || "";

{ // overview renders plain-language state
  const t = await run();
  checks.overview_headline = text(t.w, ".hero h1") === "1 thing needs attention";
  checks.pill_text = text(t.w, "#pill") === "▲ 1 needs attention";
  checks.nav_count = text(t.w, "#nav-count") === "1" && !t.w.document.getElementById("nav-count").hidden;
  checks.attention_card = text(t.w, ".alert h3").includes("203.0.113.50") && text(t.w, ".next li") === "Change the password";
  checks.footer_version = text(t.w, "#version") === "v9.9.9";
  checks.sources_listed = text(t.w, "ul.plain").includes("SSH logins") && text(t.w, "ul.plain").includes("not set up");
  checks.sparkline = t.w.document.querySelectorAll("svg.spark polyline").length === 1 && t.w.document.querySelectorAll("svg.spark circle").length === 1;
  checks.demo_banner_hidden = t.w.document.getElementById("banner").hidden === true;
  t.close();
}
{ // demo banner and states
  const t = await run({ data: { overview: overview({ demo: true, state: "critical", headline: "Needs your attention now" }) } });
  checks.demo_banner = !t.w.document.getElementById("banner").hidden && text(t.w, "#banner").includes("demo data");
  checks.critical_pill = text(t.w, "#pill") === "✖ Critical" && t.w.document.getElementById("pill").className.includes("state-critical");
  t.close();
  const s = await run({ data: { overview: overview({ state: "stopped", headline: "Erinix is not running", open: { total: 0, low: 0, medium: 0, high: 0, critical: 0 }, attention: [] }) } });
  checks.stopped_pill = text(s.w, "#pill") === "■ Not running" && text(s.w, ".empty").includes("Nothing needs your attention");
  s.close();
}
{ // hostile text is shown as text, never as markup
  const evil = '<img src=x onerror="window.__pwned=1">';
  const bad = alert({ headline: evil, why: "</script><script>window.__pwned=1</script>", next_steps: ["<b>bold</b>"], remote: "<i>x</i>", severity: '"><script>window.__pwned=1</script>',
    technical: { ...alert().technical, rule: "<svg onload=window.__pwned=1>", detail: "<iframe src=//evil>" } });
  for (const hash of ["#/", "#/alerts"]) {
    const t = await run({ hash, data: { overview: overview({ attention: [bad] }), alerts: [bad] } });
    const doc = t.w.document;
    doc.querySelectorAll("details.more").forEach(d => { d.open = true; });
    checks["hostile_no_execution" + hash] = t.w.__pwned === undefined;
    const imgs = [...doc.querySelectorAll("img")];
    checks["hostile_only_our_own_images" + hash] = imgs.length <= 2 && imgs.every(i => i.getAttribute("src").startsWith("/static/")) && doc.querySelectorAll("iframe, svg[onload], b").length === 0;
    checks["hostile_shown_as_text" + hash] = text(t.w, ".alert h3") === evil && text(t.w, ".next li") === "<b>bold</b>";
    checks["hostile_severity_falls_back" + hash] = doc.querySelector(".badge").className === "badge sev-low" && !doc.querySelector(".alert").className.includes("<");
    checks["hostile_no_scripts_added" + hash] = doc.scripts.length === 0;
    t.close();
  }
}
{ // signed out
  const t = await run({ status: 401 });
  checks.locked_screen = text(t.w, ".lock").includes("erinix ui") && text(t.w, "#pill") === "Signed out";
  t.close();
}
{ // server unreachable
  const t = await run({ reject: true });
  checks.offline_message = text(t.w, "#app").includes("Cannot reach Erinix") && text(t.w, "#pill") === "Offline";
  t.close();
}
{ // alerts view: tabs, dismiss with CSRF, reopen button
  const t = await run({ hash: "#/alerts" });
  checks.alerts_tabs = t.w.document.querySelectorAll(".tabs button").length === 3 && t.calls.some(c => c.path === "/api/alerts?status=open&limit=100");
  t.w.document.querySelector(".actions .btn").click();
  await new Promise(r => setTimeout(r, 100));
  const post = t.calls.find(c => c.method === "POST");
  checks.dismiss_request = !!post && post.path === "/api/alerts/" + "a".repeat(32) + "/status" && post.headers["X-Erinix-CSRF"] === "tok" && post.body === '{"status":"dismissed"}';
  t.close();
  const d = await run({ hash: "#/alerts", data: { alerts: [alert({ status: "dismissed" })] } });
  checks.reopen_button = text(d.w, ".actions .btn") === "Reopen" && d.w.document.querySelector(".alert").className.includes("is-dismissed");
  d.close();
}
{ // "See more" stays open when data refreshes
  const t = await run({ hash: "#/alerts" });
  const details = t.w.document.querySelector("details.more");
  details.open = true;
  details.dispatchEvent(new t.w.Event("toggle"));
  t.live.alerts = [alert({ headline: "Changed headline" })];
  await t.w.__erinix.refresh();
  checks.refresh_updates = text(t.w, ".alert h3") === "Changed headline";
  checks.details_stay_open = t.w.document.querySelector("details.more").open === true;
  t.close();
}
{ // sources page
  const t = await run({ hash: "#/sources" });
  checks.sources_page = t.w.document.querySelectorAll("table tbody tr").length === 2 && text(t.w, "table").includes("Blind") && text(t.w, "#app").includes("Live monitoring");
  t.close();
}
{ // sign-in: the token rides in the address fragment and is sent once, by the page
  const token = "T".repeat(43);
  const t = await run({ hash: "#login=" + token, needsLogin: true });
  const logins = t.calls.filter(c => c.path === "/api/login");
  checks.login_sent_once = logins.length === 1 && logins[0].method === "POST" && logins[0].body === JSON.stringify({ token }) && logins[0].headers["Content-Type"] === "application/json";
  checks.login_token_removed_from_address = t.w.location.hash === "" && !t.w.location.href.includes(token);
  checks.login_token_never_in_urls = t.calls.every(c => !c.path.includes(token));
  checks.login_then_dashboard = text(t.w, ".hero h1") === "1 thing needs attention" && !t.w.document.querySelector(".lock");
  t.close();
  // a duplicate open: the token is already used, but another copy of the page signed in
  const d = await run({ hash: "#login=" + token, needsLogin: true, login: "invalid", preSignedIn: true, wait: 900 });
  checks.login_duplicate_open_still_works = text(d.w, ".hero h1") === "1 thing needs attention" && !d.w.document.querySelector(".lock");
  d.close();
  for (const [code, words] of [["invalid", "already used"], ["expired", "expired"], ["unavailable", "could not read"]]) {
    const f = await run({ hash: "#login=" + token, needsLogin: true, login: code, wait: 900 });
    checks["login_" + code + "_message"] = text(f.w, ".lock .warn").includes(words) && text(f.w, ".lock").includes("erinix ui");
    checks["login_" + code + "_token_gone"] = f.w.location.hash === "";
    f.close();
  }
  // a link pasted into a tab that is already open only changes the "#" part: it must still sign in
  const p = await run({ needsLogin: true });
  checks.locked_before_paste = !!p.w.document.querySelector(".lock");
  p.w.location.hash = "#login=" + token;
  await new Promise(r => setTimeout(r, 400));
  checks.login_by_pasting_into_open_tab = text(p.w, ".hero h1") === "1 thing needs attention" && p.w.location.hash === "" && p.calls.filter(c => c.path === "/api/login").length === 1;
  p.close();
  // things that look like a token but are not: never sent
  for (const bad of ["#login=short", "#login=" + "x".repeat(200), "#login=" + "a".repeat(30) + "<b>", "#login="]) {
    const b = await run({ hash: bad, needsLogin: true });
    checks["login_ignores_" + bad.slice(0, 18)] = b.calls.every(c => c.path !== "/api/login") && !!b.w.document.querySelector(".lock");
    b.close();
  }
}
{ // ---- the live stream: incremental, pausable, filterable, bounded, safe
  const now = Date.now() / 1000;
  const mk = (id, o = {}) => ({ id, time: now - 10 + id / 100, kind: "web.request", label: "Web request", summary: "GET /p" + id + " → 200", remote: "10.0.0.1", alert: null, step: null, severity: null, ...o });
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const events = [mk(1), mk(2), mk(3, { alert: "a".repeat(32), step: "s", severity: "high", label: "Program started", summary: "bash (user 33)" })];
  const t = await run({ hash: "#/live", data: { events }, wait: 900 });
  const doc = t.w.document, rows = () => [...doc.querySelectorAll("#feed li.ev")];
  checks.feed_initial = rows().length === 3 && rows()[0].dataset.id === "3" && rows()[2].dataset.id === "1";
  checks.feed_flagged = rows()[0].className.includes("flagged") && rows()[0].className.includes("sev-high") && rows()[0].textContent.includes("Part of an attack") && !rows()[1].className.includes("flagged");
  const firstNode = rows()[0], alertNode = doc.querySelector(".alert");
  t.live.events.push(mk(4), mk(5));
  await sleep(900);
  checks.feed_appends = rows().length === 5 && rows()[0].dataset.id === "5" && rows().includes(firstNode);
  checks.feed_requests_only_newer = t.calls.some(c => c.path.startsWith("/api/events?after=3"));
  checks.feed_no_redraw = !alertNode || doc.querySelector(".alert") === alertNode;
  doc.querySelector('[data-action="pause"]').click();
  t.live.events.push(mk(6));
  await sleep(900);
  checks.feed_pause_holds = rows().length === 5 && doc.querySelector('[data-action="pause"]').textContent === "Resume (1 new)";
  doc.querySelector('[data-action="pause"]').click();
  checks.feed_resume_shows = rows().length === 6 && rows()[0].dataset.id === "6" && doc.querySelector('[data-action="pause"]').textContent === "Pause";
  doc.querySelector('[data-action="only"]').click();
  checks.feed_only_suspicious = rows().length === 1 && rows()[0].dataset.id === "3" && doc.querySelector('[data-action="only"]').getAttribute("aria-pressed") === "true";
  t.live.events.push(mk(7));
  await sleep(900);
  checks.feed_filter_keeps_filtering = rows().length === 1;
  doc.querySelector('[data-action="only"]').click();
  checks.feed_filter_off = rows().length === 7;
  t.live.events.length = 0; t.live.lastId = 0;
  await sleep(900);
  checks.feed_store_cleared = rows().length === 0 && !!doc.querySelector(".ev-empty");
  checks.feed_polls_twice_a_second = t.calls.filter(c => c.path.startsWith("/api/events")).length >= 5;       // about 8 polls in 4.5 s
  t.close();

  const evil = '<img src=x onerror="window.__pwned=1">';
  const many = Array.from({ length: 400 }, (_, i) => mk(i + 1));
  many[399] = mk(400, { label: evil, summary: evil, remote: evil, alert: "b".repeat(32), step: evil, severity: '"><script>x</script>' });
  const h = await run({ hash: "#/live", data: { events: many }, wait: 900 });
  const hd = h.w.document, hrows = () => [...hd.querySelectorAll("#feed li.ev")];
  checks.feed_hostile_is_text = h.w.__pwned === undefined && hrows()[0].textContent.includes(evil) && hd.querySelectorAll("#feed img, #feed script").length === 0;
  checks.feed_hostile_severity_falls_back = hrows()[0].className === "ev flagged sev-low";
  checks.feed_first_fill_is_bounded = hrows().length <= 80;
  for (let i = 401; i <= 700; i++) h.live.events.push(mk(i));
  await sleep(1700);
  checks.feed_flood_is_bounded = hrows().length <= 150 && hrows()[0].dataset.id === "700";
  h.close();
}
{ // ---- steps inside an attack
  const now = Date.now() / 1000;
  const steps = [
    { index: 1, label: "A web program starts a command line", state: "done", time: now - 2, detail: "bash (user 33)", count: 1 },
    { index: 2, label: "The command line connects <b>out</b>", state: "current", time: null, detail: "", count: 0 },
    { index: 3, label: "It gains full control (root)", state: "pending", time: null, detail: "", count: 0 }];
  const a = alert({ steps, timeline: [] });
  const t = await run({ hash: "#/alerts", data: { alerts: [a] } });
  const doc = t.w.document;
  checks.steps_states = doc.querySelectorAll(".tl.done").length === 1 && doc.querySelectorAll(".tl.current").length === 1 && doc.querySelectorAll(".tl.pending").length === 1;
  checks.steps_content = text(t.w, ".tl.done .tl-label") === "A web program starts a command line" && text(t.w, ".tl.done .tl-detail") === "bash (user 33)" && text(t.w, ".tl.current .tl-wait") === "waiting…" && /\d\d:\d\d:\d\d/.test(text(t.w, ".tl.done time"));
  checks.steps_fresh_marked = doc.querySelector(".tl.done").className.includes("fresh") && !doc.querySelector(".tl.pending").className.includes("fresh");
  checks.steps_hostile_label = text(t.w, ".tl.current .tl-label") === "The command line connects <b>out</b>" && doc.querySelectorAll(".timeline b").length === 0;
  t.close();
  const many = alert({ steps: [{ index: 1, label: "Many failed logins", state: "done", time: now - 60, detail: "POST /login → 401", count: 8 }], timeline: [] });
  const c = await run({ hash: "#/alerts", data: { alerts: [many] } });
  checks.steps_counts_repeats = text(c.w, ".tl-detail") === "8 times · last: POST /login → 401";
  c.close();
  const single = alert({ steps: [], progress: null, timeline: [{ id: 1, time: now, label: "File access", summary: "write /etc/shadow by vim", remote: null, step: "x", severity: "high" }] });
  const s = await run({ hash: "#/alerts", data: { alerts: [single] } });
  checks.timeline_for_single_events = text(s.w, ".tl-title") === "What was seen" && text(s.w, ".tl-detail") === "write /etc/shadow by vim";
  s.close();
}
{ // ---- the live page, the overview and counters that move in place
  const now = Date.now() / 1000;
  const recent = alert({ id: "r".repeat(32), updated: now - 30 }), old = alert({ id: "o".repeat(32), updated: now - 3600, headline: "Old one" });
  const t = await run({ hash: "#/live", data: { alerts: [recent, old] } });
  const doc = t.w.document;
  checks.live_page_lists_recent_attacks_only = doc.querySelectorAll("#app .alert").length === 1 && !text(t.w, "#app").includes("Old one");
  checks.live_cards_are_compact = !!doc.querySelector(".alert.compact") && !doc.querySelector(".alert.compact .next") && !doc.querySelector(".alert.compact .actions");
  checks.live_nav_link = !!doc.querySelector('#nav a[data-view="live"]') && doc.querySelector('#nav a[data-view="live"]').getAttribute("aria-current") === "page";
  t.close();
  const e = await run({ hash: "#/live", data: { alerts: [] } });
  checks.live_page_when_quiet = text(e.w, "#app").includes("No attack in progress") && !!e.w.document.querySelector("#feed");
  e.close();
  const o = await run({ hash: "#/" });
  const od = o.w.document;
  checks.overview_cards_are_full = !!od.querySelector(".alert .next li") && !od.querySelector(".alert.compact");
  checks.overview_has_a_small_live_feed = !!od.querySelector("#feed") && od.querySelector("#feed").getAttribute("data-limit") === "8" && !!od.querySelector('.feed-card a[href="#/live"]');
  const card = od.querySelector(".alert");
  const base = o.live.overview;
  const same = extra => overview({ since: base.since, attention: base.attention, ...extra });       // everything equal except what moves
  o.live.overview = same({ events_24h: 1299, alerts_24h: 9 });
  await o.w.__erinix.refresh();
  checks.counters_update_in_place = [...od.querySelectorAll('[data-live="events_24h"]')].length >= 2 && [...od.querySelectorAll('[data-live="events_24h"]')].every(el => /1.?299/.test(el.textContent)) && od.querySelector(".alert") === card;
  o.live.overview = same({ events_24h: 1299, alerts_24h: 9, activity: Array.from({ length: 48 }, (_, i) => ({ t: i * 1800, events: 50 + i, alerts: 0 })) });
  await o.w.__erinix.refresh();
  checks.chart_updates_in_place = od.querySelector(".alert") === card && od.querySelectorAll("svg.spark circle").length === 0;
  o.live.overview = same({ headline: "Needs your attention now", state: "critical", open: { total: 2, low: 0, medium: 0, high: 1, critical: 1 } });
  await o.w.__erinix.refresh();
  checks.real_changes_still_redraw = text(o.w, ".hero h1") === "Needs your attention now" && od.querySelector(".alert") !== card;
  o.close();
}
console.log(JSON.stringify({ checks }));
process.exit(0);
