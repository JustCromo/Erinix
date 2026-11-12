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

async function run({ hash = "#/", data = {}, status = 200, reject = false } = {}) {
  const dom = new JSDOM(html, { url: "http://127.0.0.1:8421/" + hash, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window, calls = [];
  const live = { overview: overview(), alerts: [alert()], ...data };
  w.fetch = async (path, opts = {}) => {
    calls.push({ path, method: opts.method || "GET", headers: opts.headers || {}, body: opts.body });
    if (reject) throw new TypeError("network down");
    const ok = (body, st = 200) => ({ ok: st < 400, status: st, json: async () => body });
    if (status === 401) return ok({ error: "locked" }, 401);
    if (path.startsWith("/api/session")) return ok({ csrf: "tok", version: "9.9.9" });
    if (path.startsWith("/api/overview")) return ok(live.overview);
    if (path.startsWith("/api/alerts/") && path.endsWith("/status")) return ok({ ok: true });
    if (path.startsWith("/api/alerts")) return ok({ alerts: live.alerts });
    return ok({}, 404);
  };
  w.eval(script);
  await new Promise(r => setTimeout(r, 150));
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
    checks["hostile_only_logo_image" + hash] = doc.querySelectorAll("img").length === 1 && doc.querySelectorAll("iframe, svg[onload], b").length === 0;
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
console.log(JSON.stringify({ checks }));
process.exit(0);
