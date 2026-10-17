// ScamShield UI. All server text is inserted with textContent (never innerHTML) to prevent XSS.
(() => {
  const $ = (id) => document.getElementById(id);
  const msg = $("message");
  const LABELS = { HIGH: ["⛔", "High risk: likely a scam"], MEDIUM: ["⚠️", "Be careful: some warning signs"], LOW: ["✅", "No common scam signs found"] };
  const TYPES = {
    kyc: "Fake KYC / account-block scam", otp_theft: "OTP or card-details theft", refund_upi: "Fake refund / UPI request",
    parcel: "Fake parcel / delivery", job: "Fake job / task scam", utility: "Electricity / connection threat",
    impersonation: "Police / official impersonation", prize: "Lottery / prize scam", loan: "Instant loan scam",
    investment: "Investment / trading scam", remote_access: "Remote-access app scam", fake_alert: "Fake bank alert",
  };
  let last = null;

  const list = (el, items) => {
    el.replaceChildren(...items.map((t) => { const li = document.createElement("li"); li.textContent = t; return li; }));
  };
  const showError = (text) => { $("error").textContent = text; $("error").hidden = !text; };

  msg.addEventListener("input", () => { $("count").textContent = msg.value.length; });
  msg.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) check(); });
  $("check").addEventListener("click", check);
  $("clear").addEventListener("click", () => { msg.value = ""; $("count").textContent = 0; $("result").hidden = true; msg.focus(); });

  async function post(path, body) {
    const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error === "too_long" ? "The message is too long (max 2000 characters)." :
      data.error === "rate_limited" ? "Too many checks. Please wait a minute." : "Something went wrong. Please try again.");
    return data;
  }

  function highlight(text, words) {
    const box = $("highlighted");
    box.replaceChildren();
    if (!words.length) { $("highlight-box").hidden = true; return; }
    const escaped = words.map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).filter(Boolean);
    const re = new RegExp(`(${escaped.join("|")})`, "gi");
    let pos = 0;
    for (const m of text.matchAll(re)) {
      if (m.index > pos) box.append(document.createTextNode(text.slice(pos, m.index)));
      const mark = document.createElement("mark");
      mark.textContent = m[0];
      box.append(mark);
      pos = m.index + m[0].length;
    }
    box.append(document.createTextNode(text.slice(pos)));
    $("highlight-box").hidden = false;
  }

  function render(text, r) {
    const [icon, label] = LABELS[r.risk_level];
    $("badge").className = `badge ${r.risk_level}`;
    $("badge-icon").textContent = icon;
    $("badge-text").textContent = label;
    $("type").textContent = r.scam_type ? `Looks like: ${TYPES[r.scam_type] || r.scam_type}` : "";
    list($("reasons"), r.reasons.map((x) => x.text));
    list($("advice"), r.advice);
    highlight(text, r.highlights.map((h) => h.word));
    $("links-box").hidden = !r.signals.urls.length;
    list($("links"), r.signals.urls);
    const tech = {
      "Risk score": r.risk_score, "Text AI (TF-IDF)": r.signals.p_text_lr, "Text AI (neural CNN)": r.signals.p_text_cnn ?? "off",
      "Link AI": r.signals.p_url ?? "no link", "Rules fired": r.signals.rules.join(", ") || "none",
      "Safety guardrail": r.signals.guardrail ? "yes" : "no", "Model": r.model_version, "Server time": `${r.latency_ms} ms`,
    };
    $("tech").replaceChildren(...Object.entries(tech).flatMap(([k, v]) => {
      const dt = document.createElement("dt"); dt.textContent = k;
      const dd = document.createElement("dd"); dd.textContent = String(v);
      return [dt, dd];
    }));
    $("disclaimer").textContent = r.disclaimer;
    $("fb").hidden = false;
    $("result").hidden = false;
  }

  async function check() {
    const text = msg.value.trim();
    showError("");
    if (!text) { showError("Please paste a message first."); msg.focus(); return; }
    $("check").disabled = true;
    $("check").textContent = "Checking…";
    try {
      const r = await post("/api/analyze", { text });
      last = { text, r };
      render(text, r);
      $("result").scrollIntoView({ behavior: "smooth", block: "start" });
      explain(text);
    } catch (e) {
      showError(e.message);
    } finally {
      $("check").disabled = false;
      $("check").textContent = "Check message";
    }
  }

  async function explain(text) {
    $("explain-text").textContent = "Preparing an explanation…";
    $("explain-src").textContent = "";
    try {
      const d = await post("/api/explain", { text });
      if (!last || last.text !== text) return; // user moved on
      $("explain-text").textContent = d.explanation.text;
      $("explain-src").textContent = d.explanation.source.startsWith("llm:")
        ? `Written by AI (${d.explanation.source.slice(4)}) from verified safety facts. The risk level above was decided separately.`
        : "Standard explanation.";
    } catch {
      $("explain-text").textContent = "Explanation unavailable right now.";
    }
  }

  $("speak").addEventListener("click", () => {
    if (!("speechSynthesis" in window) || !last) return;
    const parts = [$("badge-text").textContent, $("explain-text").textContent, ...last.r.advice];
    const u = new SpeechSynthesisUtterance(parts.join(". "));
    u.lang = "en-IN";
    u.rate = 0.9;
    speechSynthesis.cancel();
    speechSynthesis.speak(u);
  });

  document.querySelectorAll("#fb button").forEach((b) => b.addEventListener("click", async () => {
    if (!last) return;
    try {
      await post("/api/feedback", { text: last.text, verdict: b.dataset.v, level: last.r.risk_level });
      $("fb").textContent = "Thank you for the feedback.";
    } catch {
      $("fb").textContent = "Feedback is turned off on this server.";
    }
  }));

  fetch("/api/examples").then((r) => r.json()).then((items) => {
    $("examples").replaceChildren(...items.map((it) => {
      const b = document.createElement("button");
      b.type = "button";
      b.setAttribute("role", "listitem");
      b.textContent = it.label;
      b.addEventListener("click", () => { msg.value = it.text; $("count").textContent = it.text.length; check(); });
      return b;
    }));
  }).catch(() => {});

  fetch("/api/health").then((r) => r.json()).then((h) => {
    const onZ = h.arch === "s390x";
    $("platform").textContent = `${onZ ? "Running on IBM LinuxONE (s390x)" : `Running on ${h.arch}`} · ${h.cpus} CPUs · model ${h.model_version}` +
      ` · neural AI ${h.neural_model ? "on" : "off"} · GenAI ${h.llm_available ? "on" : "off (standard explanations)"}`;
  }).catch(() => { $("platform").textContent = ""; });
})();
