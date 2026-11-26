// CyberGuard popup. Main job: paste a suspicious message -> every link in it is
// scored by the live engine (same idea as the website's Protect Message box).
// Secondary: check the page you're currently on. All detection is server-side.

const BASE = "https://cyberguard-m7tq.onrender.com";
const SCAN = BASE + "/api/scan";

const T = {
  en: {
    tag: "Scam message & link checker",
    tab_msg: "Check a message", tab_page: "This page",
    ph: "Paste a suspicious SMS, WhatsApp or email message here\n(e.g. a fake parcel, fine, or bank text)",
    check_msg: "Check message", recheck: "Re-check this page", checking: "Checking with the CyberGuard engine…",
    foot: "Powered by the live CyberGuard engine", full: "Full site →",
    pretends: "Pretends to be", score: "risk", caseid: "Case ID",
    nolink: "No links found in this message to check.",
    notpage: "This isn't a web page CyberGuard can check.",
    waking: "Couldn't reach the engine — it may be waking up. Wait ~20s and try again.",
    danger: "⚠ Dangerous link found — do not click.",
    warn: "⚠ Suspicious link — be careful.",
    clear: "✓ No dangerous links found.",
    tiers: { high_risk: "High-risk scam", likely_scam: "Likely scam", suspicious: "Suspicious",
             not_verified: "Not verified", official: "Official domain", review: "Needs review" },
  },
  ar: {
    tag: "فاحص الرسائل والروابط الاحتيالية",
    tab_msg: "فحص رسالة", tab_page: "هذه الصفحة",
    ph: "الصق رسالة SMS أو واتساب أو بريد مشبوهة هنا\n(مثل رسالة شحنة أو مخالفة أو بنك مزيفة)",
    check_msg: "افحص الرسالة", recheck: "إعادة فحص هذه الصفحة", checking: "جارٍ الفحص بواسطة محرّك CyberGuard…",
    foot: "مدعوم بمحرّك CyberGuard المباشر", full: "الموقع الكامل →",
    pretends: "ينتحل صفة", score: "الخطورة", caseid: "رقم الحالة",
    nolink: "لا توجد روابط في هذه الرسالة لفحصها.",
    notpage: "هذه ليست صفحة ويب يمكن لـ CyberGuard فحصها.",
    waking: "تعذّر الوصول للمحرّك — قد يكون قيد التشغيل. انتظر ~20 ثانية وحاول مجدداً.",
    danger: "⚠ تم العثور على رابط خطير — لا تضغط عليه.",
    warn: "⚠ رابط مشبوه — كن حذراً.",
    clear: "✓ لا توجد روابط خطيرة.",
    tiers: { high_risk: "احتيال عالي الخطورة", likely_scam: "احتيال مرجّح", suspicious: "مشبوه",
             not_verified: "غير موثّق", official: "نطاق رسمي", review: "يحتاج مراجعة" },
  },
};

let lang = "en";
const $ = (id) => document.getElementById(id);

function tr() { return T[lang]; }

function host(result) {
  const u = result.final_url || result.input_url || "";
  try { return new URL(u).hostname || u; } catch { return u; }
}

function applyStaticText() {
  const t = tr();
  document.querySelector(".tag").textContent = t.tag;
  $("tab-msg").textContent = t.tab_msg;
  $("tab-page").textContent = t.tab_page;
  $("msg").placeholder = t.ph;
  $("check-msg").textContent = t.check_msg;
  $("check-page").textContent = t.recheck;
  document.querySelector(".foot-note").textContent = t.foot;
  document.querySelector(".full").textContent = t.full;
  $("lang").textContent = lang === "en" ? "AR" : "EN";
  document.body.classList.toggle("rtl", lang === "ar");
}

function setStatus(msg, isError) {
  const s = $("status");
  s.textContent = msg;
  s.classList.remove("hidden");
  s.classList.toggle("error", !!isError);
}

function clearOutput() {
  $("results").innerHTML = "";
  $("summary").classList.add("hidden");
  $("status").classList.add("hidden");
}

function cardFor(result) {
  const t = tr();
  const tier = result.tier || "not_verified";
  const card = document.createElement("div");
  card.className = "card";

  const h = document.createElement("div");
  h.className = "host";
  h.textContent = host(result);
  card.appendChild(h);

  const v = document.createElement("div");
  v.className = "verdict";
  const badge = document.createElement("span");
  badge.className = "badge t-" + tier;
  badge.textContent = (t.tiers[tier] || tier);
  const sc = document.createElement("div");
  sc.className = "score";
  sc.innerHTML = (result.score ?? 0) + "<small>" + t.score + "</small>";
  v.appendChild(badge);
  v.appendChild(sc);
  card.appendChild(v);

  const imp = result.impersonated;
  const impName = imp && (lang === "ar" ? (imp.name_ar || imp.name_en) : imp.name_en);
  if (impName) {
    const d = document.createElement("div");
    d.className = "imp";
    d.innerHTML = t.pretends + " <b></b>";
    d.querySelector("b").textContent = impName;
    card.appendChild(d);
  }

  const reasons = (result.top_reasons || []).slice(0, 4);
  if (reasons.length) {
    const ul = document.createElement("ul");
    ul.className = "reasons";
    reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = (lang === "ar" ? (r.ar || r.en) : r.en) || "";
      ul.appendChild(li);
    });
    card.appendChild(ul);
  }

  if (result.id) {
    const c = document.createElement("div");
    c.className = "caseid";
    c.textContent = t.caseid + ": " + result.id;
    card.appendChild(c);
  }
  return card;
}

function renderResults(results) {
  const t = tr();
  clearOutput();
  const worst = results.reduce((acc, r) => {
    const rank = { high_risk: 4, likely_scam: 3, review: 2, suspicious: 1 }[r.tier] || 0;
    return Math.max(acc, (r.label === "fraud" ? 3 : 0), rank);
  }, 0);

  const sm = $("summary");
  sm.className = "summary";
  if (worst >= 3) { sm.classList.add("danger"); sm.textContent = t.danger; }
  else if (worst >= 1) { sm.classList.add("warn"); sm.textContent = t.warn; }
  else { sm.classList.add("clear"); sm.textContent = t.clear; }
  sm.classList.remove("hidden");

  const box = $("results");
  results.forEach((r) => box.appendChild(cardFor(r)));
}

async function scan(input) {
  clearOutput();
  setStatus(tr().checking);
  try {
    const resp = await fetch(SCAN, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input, mode: "fast" }),
    });
    if (resp.status === 422) { setStatus(tr().nolink); return; }
    if (!resp.ok) { setStatus("Engine error " + resp.status + ". Try again.", true); return; }
    const data = await resp.json();
    const results = data.results || [];
    if (!results.length) { setStatus(tr().nolink); return; }
    renderResults(results);
  } catch (e) {
    setStatus(tr().waking, true);
  }
}

/* message mode */
function checkMessage() {
  const text = $("msg").value.trim();
  if (text.length < 3) { $("msg").focus(); return; }
  scan(text);
}

/* page mode */
async function currentTabUrl() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] && tabs[0].url;
}
async function loadPage() {
  const url = await currentTabUrl();
  $("page-url").textContent = url || "(no page)";
  if (!/^https?:\/\//i.test(url || "")) { clearOutput(); setStatus(tr().notpage); return; }
  scan(url);
}

/* tabs */
function switchTab(which) {
  ["msg", "page"].forEach((k) => {
    $("tab-" + k).classList.toggle("active", k === which);
    $("pane-" + k).classList.toggle("hidden", k !== which);
  });
  clearOutput();
  if (which === "page") loadPage();
}

/* wiring */
$("tab-msg").addEventListener("click", () => switchTab("msg"));
$("tab-page").addEventListener("click", () => switchTab("page"));
$("check-msg").addEventListener("click", checkMessage);
$("check-page").addEventListener("click", loadPage);
$("msg").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) checkMessage(); });
$("lang").addEventListener("click", () => { lang = lang === "en" ? "ar" : "en"; applyStaticText(); });

applyStaticText();
$("msg").focus();
