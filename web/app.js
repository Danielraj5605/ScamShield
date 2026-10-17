// ScamShield interface script. All server text is inserted with textContent, never innerHTML.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var msg = $("message");

  var LEVELS = {
    HIGH: { label: "High risk", summary: "This message shows strong signs of a scam." },
    MEDIUM: { label: "Some warning signs", summary: "This message has some warning signs. Be careful." },
    LOW: { label: "No common warning signs found", summary: "This does not guarantee the message is safe." }
  };
  var TYPES = {
    kyc: "Looks like a fake KYC or account-block message",
    otp_theft: "Looks like an attempt to get your OTP or card details",
    refund_upi: "Looks like a fake refund or UPI request",
    parcel: "Looks like a fake parcel or delivery message",
    job: "Looks like a fake job or task offer",
    utility: "Looks like a fake electricity or connection threat",
    impersonation: "Looks like someone pretending to be police or an official",
    prize: "Looks like a lottery or prize scam",
    loan: "Looks like an instant loan scam",
    investment: "Looks like an investment or trading scam",
    remote_access: "Looks like an attempt to take control of your phone",
    fake_alert: "Looks like a fake bank or payment alert"
  };
  var last = null;

  function fill(listEl, items) {
    listEl.replaceChildren.apply(listEl, items.map(function (t) {
      var li = document.createElement("li");
      li.textContent = t;
      return li;
    }));
  }
  function showError(text) { $("error").textContent = text || ""; $("error").hidden = !text; }
  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

  msg.addEventListener("input", function () { $("count").textContent = msg.value.length; });
  msg.addEventListener("keydown", function (e) { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) check(); });
  $("check").addEventListener("click", check);
  $("clear").addEventListener("click", function () {
    msg.value = "";
    $("count").textContent = "0";
    $("result").hidden = true;
    $("placeholder").hidden = false;
    showError("");
    last = null;
    msg.focus();
  });

  function post(path, body) {
    return fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (data) {
          if (!r.ok) {
            var text = data.error === "too_long" ? "The message is too long. The limit is 2000 characters."
              : data.error === "rate_limited" ? "Too many checks in a short time. Please wait a minute and try again."
              : "Something went wrong. Please try again.";
            throw new Error(text);
          }
          return data;
        });
      });
  }

  // Show the user's own message with the risky words and the links marked.
  function annotate(text, words, urls) {
    var box = $("annotated");
    box.replaceChildren();
    var spans = [], lower = text.toLowerCase();
    urls.forEach(function (u) {
      var raw = u.replace(/hxxp/gi, "http").replace(/\[\.\]/g, ".");
      var i = lower.indexOf(raw.toLowerCase());
      if (i >= 0) spans.push({ start: i, end: i + raw.length, kind: "link", shown: u });
    });
    words.forEach(function (w) {
      var re = new RegExp("\\b" + escapeRe(w) + "\\b", "gi"), m;
      while ((m = re.exec(text)) !== null) {
        spans.push({ start: m.index, end: m.index + m[0].length, kind: "word", shown: m[0] });
        if (m[0].length === 0) re.lastIndex++;
      }
    });
    spans.sort(function (a, b) { return a.start - b.start || (a.kind === "link" ? -1 : 1); });
    var pos = 0, marked = { word: 0, link: 0 };
    spans.forEach(function (s) {
      if (s.start < pos) return;
      if (s.start > pos) box.append(document.createTextNode(text.slice(pos, s.start)));
      var el = document.createElement(s.kind === "word" ? "mark" : "span");
      if (s.kind === "link") el.className = "link-mark";
      el.textContent = s.shown;
      box.append(el);
      marked[s.kind]++;
      pos = s.end;
    });
    box.append(document.createTextNode(text.slice(pos)));
    var parts = [];
    if (marked.word) parts.push("Highlighted words raised the risk.");
    if (marked.link) parts.push("Dashed text is a link, shown so it cannot be clicked.");
    $("legend").textContent = parts.length ? parts.join(" ") : "No single word or link stood out.";
  }

  function render(text, r) {
    var lv = LEVELS[r.risk_level];
    $("verdict").setAttribute("data-level", r.risk_level);
    $("verdict-label").textContent = lv.label;
    $("verdict-summary").textContent = lv.summary;
    var typeText = r.scam_type ? (TYPES[r.scam_type] || "") : "";
    $("scam-type").textContent = typeText;
    $("scam-type").hidden = !typeText;
    fill($("reasons"), r.reasons.map(function (x) { return x.text; }));
    fill($("advice"), r.advice);
    annotate(text, r.highlights.map(function (h) { return h.word; }), r.signals.urls);
    var tech = [
      ["Risk score", r.risk_score],
      ["Wording model (TF-IDF)", r.signals.p_text_lr],
      ["Wording model (neural network)", r.signals.p_text_cnn === null ? "not used" : r.signals.p_text_cnn],
      ["Link model", r.signals.p_url === null ? "no link in message" : r.signals.p_url],
      ["Warning signs found", r.signals.rules.join(", ") || "none"],
      ["Safety rule applied", r.signals.guardrail ? "yes" : "no"],
      ["Model version", r.model_version],
      ["Processing time", r.latency_ms + " ms"]
    ];
    var nodes = [];
    tech.forEach(function (row) {
      var dt = document.createElement("dt"); dt.textContent = row[0];
      var dd = document.createElement("dd"); dd.textContent = String(row[1]);
      nodes.push(dt, dd);
    });
    $("tech").replaceChildren.apply($("tech"), nodes);
    $("disclaimer").textContent = r.disclaimer;
    $("copy").textContent = "Copy summary";
    $("fb-q").hidden = false;
    $("fb-done").hidden = true;
    $("placeholder").hidden = true;
    $("result").hidden = false;
  }

  function check() {
    var text = msg.value.trim();
    showError("");
    if (!text) { showError("Paste a message first."); msg.focus(); return; }
    var btn = $("check");
    btn.disabled = true;
    btn.textContent = "Checking";
    post("/api/analyze", { text: text })
      .then(function (r) {
        last = { text: text, r: r };
        render(text, r);
        if (window.matchMedia("(max-width: 939px)").matches) { $("result").scrollIntoView({ block: "start" }); }
        explain(text);
      })
      .catch(function (e) { showError(e.message); })
      .then(function () { btn.disabled = false; btn.textContent = "Check message"; });
  }

  function explain(text) {
    $("explain-text").textContent = "Preparing an explanation.";
    $("explain-text").classList.add("muted");
    $("explain-src").textContent = "";
    post("/api/explain", { text: text })
      .then(function (d) {
        if (!last || last.text !== text) return;
        $("explain-text").textContent = d.explanation.text;
        $("explain-text").classList.remove("muted");
        $("explain-src").textContent = d.explanation.source.indexOf("llm:") === 0
          ? "Written by a language model (" + d.explanation.source.slice(4) + ") using checked safety facts. The risk level above was decided separately."
          : "Written by ScamShield.";
      })
      .catch(function () { $("explain-text").textContent = "No explanation is available right now."; });
  }

  $("speak").addEventListener("click", function () {
    if (!("speechSynthesis" in window) || !last) return;
    var parts = [$("verdict-label").textContent, $("verdict-summary").textContent].concat(last.r.advice);
    var u = new SpeechSynthesisUtterance(parts.join(". "));
    u.lang = "en-IN";
    u.rate = 0.9;
    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(u);
  });
  if (!("speechSynthesis" in window)) { $("speak").hidden = true; }

  // A plain-text summary that a helper can paste into a message to a family member.
  $("copy").addEventListener("click", function () {
    if (!last) return;
    var r = last.r, lv = LEVELS[r.risk_level];
    var lines = ["ScamShield result: " + lv.label + ".", lv.summary];
    if (r.scam_type && TYPES[r.scam_type]) lines.push(TYPES[r.scam_type] + ".");
    lines.push("", "What to do now:");
    r.advice.forEach(function (a, i) { lines.push((i + 1) + ". " + a); });
    lines.push("", "Why:");
    r.reasons.forEach(function (x) { lines.push("- " + x.text); });
    lines.push("", "Automated check. It can be wrong.");
    var btn = $("copy");
    if (!navigator.clipboard || !navigator.clipboard.writeText) { btn.textContent = "Copy not available here"; return; }
    navigator.clipboard.writeText(lines.join("\n"))
      .then(function () { btn.textContent = "Copied"; })
      .catch(function () { btn.textContent = "Copy not available here"; });
  });

  function feedbackDone(text) {
    $("fb-q").hidden = true;
    $("fb-done").textContent = text;
    $("fb-done").hidden = false;
  }
  Array.prototype.forEach.call(document.querySelectorAll("#fb-q button"), function (b) {
    b.addEventListener("click", function () {
      if (!last) return;
      post("/api/feedback", { text: last.text, verdict: b.dataset.v, level: last.r.risk_level })
        .then(function () { feedbackDone("Thank you for the feedback."); })
        .catch(function () { feedbackDone("Feedback is switched off on this server."); });
    });
  });

  fetch("/api/examples").then(function (r) { return r.json(); }).then(function (items) {
    var list = $("examples");
    items.forEach(function (it) {
      var li = document.createElement("li");
      var b = document.createElement("button");
      b.type = "button";
      b.className = "example";
      b.textContent = it.label;
      b.addEventListener("click", function () {
        msg.value = it.text;
        $("count").textContent = it.text.length;
        check();
      });
      li.append(b);
      list.append(li);
    });
  }).catch(function () {});

  fetch("/api/health").then(function (r) { return r.json(); }).then(function (h) {
    var where = h.arch === "s390x" ? "Running on IBM LinuxONE (s390x)" : "Running on " + h.arch;
    $("platform").textContent = where + ", " + h.cpus + " CPUs. Written explanations: " +
      (h.llm_available ? "language model with built-in fallback." : "built in.");
  }).catch(function () { $("platform").textContent = ""; });
})();
