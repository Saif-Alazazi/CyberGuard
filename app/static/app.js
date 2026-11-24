"use strict";
let lang = "en";
let lastScan = null;
let lastWarnings = null;
const $ = (s) => document.querySelector(s);
const t = (k) => I18N[lang][k] ?? k;
const TIER_CLASS = { official: "t-official", high_risk: "t-high", likely_scam: "t-likely", suspicious: "t-susp", not_verified: "t-nv" };

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return n;
}

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  $("#lang").textContent = lang === "ar" ? "English" : "عربي";
  document.querySelectorAll("[data-i18n]").forEach((n) => (n.textContent = t(n.dataset.i18n)));
  document.querySelectorAll("[data-i18n-ph]").forEach((n) => (n.placeholder = t(n.dataset.i18nPh)));
  const list = $("#demo-list");
  list.replaceChildren(...DEMOS.map((d) => el("button", { class: "chip", text: t(d.key), onclick: () => runDemo(d) })));
  if (lastScan) renderScan(lastScan);
  if (lastWarnings) renderWarnings(lastWarnings);
  try { localStorage.setItem("cg-lang", lang); } catch (e) { /* storage unavailable */ }
}

function runDemo(d) {
  $("#input").value = d.input;
  $("#sender").value = d.sender;
  scan();
}

async function scan() {
  const input = $("#input").value.trim();
  if (input.length < 3) return;
  const mode = document.querySelector("input[name=mode]:checked").value;
  const st = $("#status");
  st.hidden = false;
  st.className = "status busy";
  st.textContent = t(mode === "deep" ? "scanning_deep" : "scanning_fast");
  $("#go").disabled = true;
  try {
    const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input, mode, sender: $("#sender").value.trim() }) });
    const j = await r.json();
    if (!r.ok) throw new Error(j.detail === "No URL found in the input." ? t("no_url") : (j.detail || r.status));
    lastScan = j;
    st.hidden = true;
    renderScan(j);
  } catch (e) {
    st.className = "status err";
    st.textContent = t("error") + e.message;
  } finally {
    $("#go").disabled = false;
  }
}

function gauge(score, tier) {
  const r = 52, c = Math.PI * r, pct = Math.max(0, Math.min(100, score)) / 100;
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 140 84");
  svg.setAttribute("class", "gauge " + TIER_CLASS[tier]);
  const mk = (cls, dash) => {
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", "M18 72 A52 52 0 0 1 122 72");
    p.setAttribute("class", cls);
    if (dash != null) p.setAttribute("stroke-dasharray", `${dash} ${c}`);
    return p;
  };
  svg.append(mk("g-bg"), mk("g-fg", c * pct));
  const tx = document.createElementNS(ns, "text");
  tx.setAttribute("x", "70"); tx.setAttribute("y", "68"); tx.setAttribute("text-anchor", "middle");
  tx.textContent = score;
  svg.append(tx);
  return svg;
}

function kv(rows) {
  return el("dl", { class: "kv" }, rows.filter((r) => r[1] != null && r[1] !== "").flatMap(([k, v]) => [el("dt", { text: k }), el("dd", {}, v)]));
}

function renderMessage(m) {
  if (!m) return null;
  const rows = [];
  if (m.claimed_names?.length) rows.push([t("claims"), m.claimed_names.map((c) => c[lang]).join(", ")]);
  if (m.lure_hits?.length) rows.push([t("lures"), [...new Set(m.lure_hits.map((h) => h.phrase))].join(" · ")]);
  if (m.sender) rows.push([t("sender"), m.sender + (m.sender_flags?.length ? "  ⚠ " + m.sender_flags.join("; ") : "")]);
  return rows.length ? el("div", { class: "card msg" }, el("h3", { text: t("message") }), kv(rows)) : null;
}

function renderResult(r) {
  const tierName = I18N[lang].tiers[r.tier] || r.tier;
  const other = lang === "en" ? "ar" : "en";
  const head = el("div", { class: "res-head" },
    gauge(r.score, r.tier),
    el("div", { class: "verdict" },
      el("span", { class: "badge " + TIER_CLASS[r.tier], text: tierName }),
      el("span", { class: "label " + (r.label === "fraud" ? "lab-fraud" : "lab-ok"), text: r.label === "fraud" ? t("label_fraud") : t("label_legit") }),
      el("div", { class: "url mono", dir: "ltr", text: r.input_url }),
      r.final_url && r.final_url !== r.input_url ? el("div", { class: "muted mono small", dir: "ltr", text: "→ " + r.final_url }) : null,
      r.impersonated ? el("div", { class: "imp" }, el("b", { text: t("impersonates") + ": " }),
        lang === "ar" ? r.impersonated.name_ar || r.impersonated.name_en : r.impersonated.name_en,
        el("span", { class: "muted", text: "  ·  " + t("official_domain") + ": " }),
        el("span", { class: "mono", dir: "ltr", text: r.impersonated.official_domains.join(", ") })) : null));

  const reasons = el("ol", { class: "reasons" }, (r.reasons || []).filter((x) => x.weight !== 0 || ["ALLOW_OFFICIAL", "KNOWN_BAD"].includes(x.code)).slice(0, 8).map((x) =>
    el("li", { class: x.weight < 0 || x.code === "ALLOW_OFFICIAL" ? "neg" : "" },
      el("span", { class: "w mono", text: x.code === "KNOWN_BAD" ? "≥90" : (x.weight > 0 ? "+" : "") + x.weight }),
      el("div", {}, el("div", { text: x[lang] }), el("div", { class: "muted small", dir: other === "ar" ? "rtl" : "ltr", text: x[other] })))));

  const hops = (r.hops || []).map((h, i) => el("li", {},
    el("span", { class: "mono small", text: `${i}. ${h.status ?? h.error ?? ""}` }), " ",
    el("span", { class: "mono", dir: "ltr", text: h.url }), h.shortener ? el("span", { class: "pill", text: "shortener" }) : null,
    h.ip ? el("span", { class: "muted small mono", text: "  " + h.ip }) : null));

  const intel = r.intel || {}, who = intel.whois || {}, ip = intel.ip || {};
  const domainInfo = kv([
    [t("registrar"), who.registrar || (who.error ? who.error : null)],
    [t("created"), who.created ? `${who.created.slice(0, 10)} (${intel.age_days} ${t("age")})` : (r.tier === "official" ? null : t("unknown"))],
    [t("ip"), ip.ip ? `${ip.ip} · ${ip.asn || ""} ${ip.as_name || ""} · ${ip.country || ""}${ip.cloudflare_proxied ? " · Cloudflare proxy" : ""}` : null],
    [t("ns"), (who.nameservers?.length ? who.nameservers : r.dns?.ns || []).join(", ")],
    [t("feeds"), r.feeds?.length ? r.feeds.map((f) => `${f.source} (${f.match})`).join("; ") : t("not_listed")],
  ]);

  const page = r.page || {};
  const shot = page.cloudflare?.uuid || page.title != null ? el("img", { class: "shot", src: `/api/screenshot/${r.id}.png`, alt: "screenshot",
    onerror: (e) => e.target.remove() }) : null;
  const pageInfo = Object.keys(page).length ? el("div", { class: "page" }, shot, kv([
    ["Title", page.title], [t("fields"), (page.sensitive_fields || []).join(", ")], [t("phones"), (page.phones || []).join(", ")],
    ["Cloudflare", page.cloudflare?.report_url ? el("a", { href: page.cloudflare.report_url, target: "_blank", rel: "noopener", text: "report" }) : null]])) : null;
  const ai = r.llm ? el("div", {}, el("h4", { text: t("ai") + (r.llm.model ? ` · ${r.llm.model}` : "") }),
    el("ul", {}, (lang === "ar" ? r.llm.evidence_ar : r.llm.evidence_en || []).map((e) => el("li", { text: e })))) : null;

  const ev = el("div", { class: "evidence" }, el("b", { text: t("evidence") + ": " }),
    ["pdf", "json", "stix"].map((f) => el("a", { class: "btn", href: `/api/evidence/${r.id}?format=${f}`, text: t(f) })),
    el("span", { class: "muted small mono", text: `  ${t("case")} ${r.id} · ${r.elapsed_ms} ms · ${r.mode}` }));

  return el("article", { class: "card result " + TIER_CLASS[r.tier] }, head,
    el("h3", { text: t("reasons") }), reasons,
    hops.length > 1 ? el("details", { open: "" }, el("summary", { text: `${t("redirect")} (${hops.length})` }), el("ol", { class: "hops" }, hops)) : null,
    el("details", { open: r.tier !== "official" ? "" : null }, el("summary", { text: t("domain") }), domainInfo),
    pageInfo ? el("details", { open: "" }, el("summary", { text: t("page") }), pageInfo, ai) : null,
    r.skipped?.length ? el("p", { class: "muted small", text: t("skipped") + ": " + r.skipped.join("; ") }) : null,
    ev);
}

function renderScan(j) {
  $("#results").replaceChildren(renderMessage(j.message) || "", ...j.results.map(renderResult));
}

async function batch() {
  const f = $("#csv").files[0];
  if (!f) return;
  $("#batch-status").textContent = t("batch_running") + f.name;
  const fd = new FormData();
  fd.append("file", f);
  const r = await fetch("/api/batch", { method: "POST", body: fd });
  if (!r.ok) { $("#batch-status").textContent = t("error") + r.status; return; }
  const text = await r.text();
  const blob = new Blob([text], { type: "text/csv" });
  const a = el("a", { href: URL.createObjectURL(blob), download: "cyberguard_results.csv" });
  document.body.append(a); a.click(); a.remove();
  $("#batch-status").textContent = t("batch_done");
  const rows = text.replace(/^﻿/, "").trim().split(/\r?\n/).slice(0, 51).map(parseCsvLine);
  $("#batch-table").replaceChildren(el("table", {}, el("thead", {}, el("tr", {}, rows[0].slice(0, 4).map((h) => el("th", { text: h })))),
    el("tbody", {}, rows.slice(1).map((r) => el("tr", { class: r[1] === "fraud" ? "rowbad" : "" }, r.slice(0, 4).map((c) => el("td", { class: "mono", text: c })))))));
}

function parseCsvLine(line) {
  const out = []; let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) { if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (ch === '"') q = false; else cur += ch; }
    else if (ch === '"') q = true; else if (ch === ",") { out.push(cur); cur = ""; } else cur += ch;
  }
  out.push(cur);
  return out;
}

function gst(iso) {
  try { return new Date(iso).toLocaleString("en-GB", { timeZone: "Asia/Dubai", dateStyle: "medium", timeStyle: "short" }); } catch (e) { return iso; }
}

async function loadWarnings() {
  const r = await fetch("/api/early-warnings");
  lastWarnings = await r.json();
  renderWarnings(lastWarnings);
}

function renderWarnings(ws) {
  if (!ws.length) { $("#warn-table").replaceChildren(el("p", { class: "muted", text: t("no_warn") })); return; }
  $("#warn-table").replaceChildren(el("table", {},
    el("thead", {}, el("tr", {}, ["w_domain", "w_source", "w_first", "w_score", "w_block", "w_detail"].map((k) => el("th", { text: t(k) })))),
    el("tbody", {}, ws.map((w) => el("tr", {},
      el("td", { class: "mono", dir: "ltr" }, w.scan_id ? el("a", { href: `/api/evidence/${w.scan_id}?format=pdf`, text: w.domain }) : w.domain),
      el("td", {}, el("span", { class: "pill", text: t("src_" + w.source) })),
      el("td", { class: "small", text: gst(w.first_seen) }),
      el("td", {}, w.score != null ? el("span", { class: "badge " + (TIER_CLASS[w.tier] || ""), text: w.score }) : "-"),
      el("td", { class: w.blocklisted ? "small" : "small early", text: w.blocklisted ? t("blocked") : t("not_blocked") }),
      el("td", { class: "small", text: w.detail }))))));
}

let network = null;
async function loadGraph() {
  const g = await (await fetch("/api/graph")).json();
  const box = $("#graph");
  const linked = g.nodes.filter((n) => n.kind !== "domain").length;
  if (!linked || typeof vis === "undefined") {
    box.replaceChildren(el("p", { class: "muted", text: t("no_graph") }));
  } else {
    const color = (n) => n.kind !== "domain" ? "#94a3b8" : n.score >= 75 ? "#c0262d" : n.score >= 50 ? "#d9622b" : n.score >= 25 ? "#c99a06" : "#6b7280";
    const nodes = new vis.DataSet(g.nodes.map((n) => ({ id: n.id, label: n.label.length > 32 ? n.label.slice(0, 30) + "…" : n.label,
      title: `${n.kind}: ${n.label}${n.score != null ? " · score " + n.score : ""}`, shape: n.kind === "domain" ? "dot" : "diamond",
      size: n.kind === "domain" ? 10 + (n.score || 0) / 8 : 8, color: color(n), font: { size: 11 } })));
    const edges = new vis.DataSet(g.edges.map((e, i) => ({ id: i, from: e.from, to: e.to, title: e.kind, color: { color: "#cbd5e1" } })));
    network = new vis.Network(box, { nodes, edges }, { physics: { stabilization: { iterations: 150 } }, interaction: { hover: true } });
  }
  $("#campaigns").replaceChildren(g.campaigns.length ? el("div", {}, el("h3", { text: t("campaigns") }),
    el("ul", {}, g.campaigns.map((c) => el("li", {}, el("b", { text: `${c.domains.length} domains` }), " - ",
      el("span", { class: "mono small", dir: "ltr", text: c.domains.slice(0, 8).join(", ") }),
      el("div", { class: "muted small", text: c.shared.join(" · ") }))))) : "");
}

document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + b.dataset.tab));
  if (b.dataset.tab === "warnings") loadWarnings();
  if (b.dataset.tab === "graph") loadGraph();
}));
$("#lang").addEventListener("click", () => { lang = lang === "en" ? "ar" : "en"; applyLang(); });
$("#go").addEventListener("click", scan);
$("#input").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) scan(); });
$("#batch-go").addEventListener("click", batch);
try { lang = localStorage.getItem("cg-lang") || "en"; } catch (e) { lang = "en"; }
applyLang();
