// CyberGuard popup: grabs the active tab's URL, sends it to the live engine,
// and renders the verdict. The detection all happens server-side on Render.

const API = "https://cyberguard-m7tq.onrender.com/api/scan";

const TIER_LABEL = {
  high_risk: "High-risk scam",
  likely_scam: "Likely scam",
  suspicious: "Suspicious",
  not_verified: "No record – not verified",
  official: "Official domain",
  review: "Needs review",
};

const $ = (id) => document.getElementById(id);

function setStatus(msg, isError) {
  const s = $("status");
  s.textContent = msg;
  s.classList.remove("hidden");
  s.classList.toggle("error", !!isError);
}

function hideResult() {
  ["verdict", "brand", "reasons", "caseid"].forEach((id) => $(id).classList.add("hidden"));
}

function render(result) {
  const tier = result.tier || "not_verified";
  const badge = $("badge");
  badge.className = "badge t-" + tier;
  badge.textContent = TIER_LABEL[tier] || tier;

  $("score").textContent = (result.score ?? 0);
  $("verdict").classList.remove("hidden");

  const imp = result.impersonated;
  if (imp && imp.name_en) {
    $("brand").innerHTML = "Pretends to be <b>" + imp.name_en + "</b>";
    $("brand").classList.remove("hidden");
  } else {
    $("brand").classList.add("hidden");
  }

  const reasons = (result.top_reasons || []).slice(0, 4);
  const ul = $("reasons");
  ul.innerHTML = "";
  reasons.forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r.en || "";
    ul.appendChild(li);
  });
  ul.classList.toggle("hidden", reasons.length === 0);

  if (result.id) {
    $("caseid").textContent = "Case ID: " + result.id;
    $("caseid").classList.remove("hidden");
  }

  $("status").classList.add("hidden");
}

async function check(url) {
  hideResult();
  setStatus("Checking with the CyberGuard engine…");
  try {
    const resp = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: url, mode: "fast" }),
    });
    if (!resp.ok) {
      if (resp.status === 422) {
        setStatus("No checkable link on this page.");
      } else {
        setStatus("Engine returned " + resp.status + ". Try Re-check.", true);
      }
      return;
    }
    const data = await resp.json();
    const result = (data.results || [])[0];
    if (!result) {
      setStatus("No checkable link on this page.");
      return;
    }
    render(result);
  } catch (e) {
    setStatus("Couldn't reach the engine — it may be waking up. Wait ~20s and Re-check.", true);
  }
}

function isCheckable(url) {
  return /^https?:\/\//i.test(url || "");
}

async function currentTabUrl() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] && tabs[0].url;
}

async function start() {
  const url = await currentTabUrl();
  $("url").textContent = url || "(no page)";
  if (!isCheckable(url)) {
    setStatus("This isn't a web page CyberGuard can check (try it on a normal http/https site).");
    return;
  }
  check(url);
}

$("recheck").addEventListener("click", start);
start();
