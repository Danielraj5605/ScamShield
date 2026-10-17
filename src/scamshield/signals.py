"""Interpretable scam signals.

Signals serve three roles:
1. Input features for the learned ensemble (the AI decides how much each one matters).
2. Human-readable reasons shown to the user.
3. A handful of CRITICAL guardrails (e.g. "asks you to share an OTP") that always force HIGH risk,
   because missing them is far more costly than a false alarm.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .url_features import brand_impersonation, shorteners
from .urls import host_of, path_of, registered_domain

CRITICAL, HIGH, MED, SAFE = "CRITICAL", "HIGH", "MED", "SAFE"


@dataclass(frozen=True)
class Signal:
    id: str
    severity: str
    weight: float
    reason: str
    scam_type: str | None = None
    detail: dict = field(default_factory=dict, compare=False, hash=False)


_NEG = re.compile(r"(do not|don't|dont|never|nobody|no one|not to|mat)\W+(\w+\W+){0,3}$")
_SECRET = r"(?:[o0]\.?t\.?p|one[- ]time password|upi pin|atm pin|m-?pin|\bpin\b|cvv|password|verification code|security code)"
_SHARE_VERB = r"(?:share|send|tell|forward|give|provide|reply with|reply|sms|whatsapp)"


def _rx(p: str) -> re.Pattern:
    return re.compile(p, re.I)


# (id, severity, weight, scam_type, pattern, reason)
_TEXT_RULES = [
    ("R02", HIGH, 0.25, "kyc",
     _rx(r"(account|a/c|acct|kyc|pan|aadha+r|card|sim|wallet|net ?banking).{0,40}(block|suspend|expir|deactivat|freez|clos|terminat)"
         r"|(block|suspend|deactivat|freez|terminat).{0,30}(account|a/c|kyc|card|sim|wallet)"),
     "It threatens to block or close your account to rush you."),
    ("R02K", HIGH, 0.25, "kyc",
     _rx(r"kyc.{0,30}(update|complete|pending|verif|expir|renew)|(update|complete|verify).{0,20}kyc|(pan|aadha+r).{0,25}(link|updat|verif)"),
     "It asks you to update KYC or link PAN/Aadhaar through a message. Banks don't do this by SMS."),
    ("R03", MED, 0.1, None,
     _rx(r"\b(urgent|urgently|immediately|asap|within \d+ ?(min|mins|minutes|hour|hours|hrs)|today itself|today only|last chance|final (notice|warning|reminder)|act now|tonight|in 24 ?hours?|expires? today)\b"),
     "It tries to make you act fast without thinking."),
    ("R07", CRITICAL, 0.5, "refund_upi",
     _rx(r"(enter|use|type|put)\W+(your\W+)?(upi\W+)?(pin|mpin).{0,40}(receive|get|credit|claim|refund|cashback|accept)"
         r"|(collect|payment) request.{0,40}(approve|accept)|(approve|accept).{0,30}(collect )?request.{0,40}(receive|refund|cashback|credit)"),
     "You never need to enter your UPI PIN to receive money."),
    ("R08", MED, 0.15, "prize",
     _rx(r"\b(you('ve| have)? won|winner|lottery|lucky draw|prize|jackpot|cash ?back|gift card|you are selected|congratulations)\b"),
     "It promises money or a prize you didn't expect."),
    ("R08R", MED, 0.15, "refund_upi",
     _rx(r"\b(refund|reimburse|excess (amount|payment)|tax refund|claim (your|the) (amount|money))\b"),
     "It offers a refund. Scammers use fake refunds to get your bank details."),
    ("R09", HIGH, 0.2, "job",
     _rx(r"(part[- ]?time|work from home|\bwfh\b|daily (income|earning|payout|salary)|earn.{0,20}(per day|daily|/day|a day|per hour)"
         r"|(like|subscribe|rate|review).{0,25}(videos?|hotels?|products?).{0,30}(earn|pay|commission)|task[- ]?(based|job)|prepaid task)"),
     "Easy-money job offers are a common scam."),
    ("R10", HIGH, 0.25, "utility",
     _rx(r"(electricity|power|light|connection|meter).{0,50}(disconnect|cut|discontinu|suspend)"
         r"|(disconnect|discontinu).{0,30}(electricity|power|connection)"),
     "It threatens to cut your electricity or connection."),
    ("R11", CRITICAL, 0.5, "impersonation",
     _rx(r"digital arrest|((police|cbi|crime branch|cyber ?(cell|crime|police)|customs|narcotics|\bncb\b|enforcement directorate|\bed\b officer|court|trai|rbi officer)"
         r".{0,80}(arrest|warrant|\bfir\b|seized|illegal|drugs|summons|jail|money laundering|case (registered|filed|against)))"),
     "Police, courts and officials never arrest or fine anyone over a message or video call."),
    ("R12", HIGH, 0.2, "parcel",
     _rx(r"(parcel|courier|shipment|package|consignment|delivery).{0,60}(held|on hold|pending|failed|unable|incomplete address|address (is )?(incorrect|wrong|incomplete)|fee|pay|customs|redeliver|re-deliver)"),
     "It asks you to pay or update details to release a parcel, a common trick."),
    ("R13", CRITICAL, 0.5, "remote_access",
     _rx(r"\b(anydesk|any desk|teamviewer|team viewer|quick ?support|rustdesk|airdroid|screen ?shar\w*|apk file|download (this|the) apk|\.apk\b)"),
     "It asks you to install an app or share your screen, which lets strangers control your phone."),
    ("R14", HIGH, 0.2, "loan",
     _rx(r"(instant|pre-?approved|guaranteed|easy).{0,20}loan|loan.{0,30}(approved|sanctioned|without (cibil|documents|income proof))|(processing|registration|file) (fee|charge)"),
     "It offers an easy loan or asks for an upfront fee."),
    ("R15", HIGH, 0.2, "investment",
     _rx(r"(double your (money|investment)|guaranteed (returns?|profit)|\d+ ?% (daily|weekly|monthly|profit|returns?)|\bcrypto|bitcoin|\busdt\b|trading (group|tips|signals)|stock tips|ipo allot)"),
     "It promises guaranteed or very high investment returns."),
    ("R18", HIGH, 0.25, "refund_upi",
     _rx(r"(sent|send|transfer\w*|paid|credited|payment|paise|money|rs\.? ?\d).{0,80}(by mistake|wrongly|accidentally).{0,100}(return|send (it )?back|refund)"
         r"|(return|send back|refund).{0,40}(money|amount|rs\.? ?\d|paise).{0,60}(by mistake|wrongly|accidentally)"
         r"|(by mistake|wrongly|accidentally).{0,80}(\d{3,}|rs|paise|money|amount).{0,80}(return|send back|refund)"),
     "It says money was sent to you by mistake and asks you to send it back. This is a common trick."),
    ("R17", HIGH, 0.3, "otp_theft",
     _rx(r"(enter|update|confirm|verify|share|provide|send).{0,25}(card number|card details|cvv|expiry date|net ?banking|login details|bank details|account details|pan number|aadha+r number|atm pin|debit card)"),
     "It asks for your card, bank or login details."),
]


def _share_secret_request(norm_text: str) -> bool:
    """True if the text asks you to share an OTP/PIN, ignoring 'do not share' warnings."""
    # Legitimate delivery-OTP handover ("share OTP with the delivery agent at the time of delivery").
    if _DELIVERY_OTP.search(norm_text) and "http" not in norm_text:
        return False
    patterns = [
        re.compile(rf"{_SHARE_VERB}\W+(\w+\W+){{0,4}}{_SECRET}", re.I),
        re.compile(rf"{_SECRET}\W+(\w+\W+){{0,4}}{_SHARE_VERB}\b", re.I),
    ]
    for p in patterns:
        for m in p.finditer(norm_text):
            before = norm_text[max(0, m.start() - 30): m.start()]
            inside = m.group(0)
            if _NEG.search(before) or re.search(r"(do not|don't|dont|never|not)\b", inside):
                continue
            return True
    return False


_DELIVERY_OTP = re.compile(r"(at the time of|during|upon|on) delivery|delivery (agent|partner|executive|boy)", re.I)
_SAFE_OTP = re.compile(
    rf"({_SECRET}|code).{{0,120}}((do not|don't|dont|never)\W+(share|disclose|tell))"
    rf"|(do not|don't|dont|never)\W+(share|disclose)\W+(\w+\W+){{0,4}}({_SECRET}|code)"
    rf"|never asks? (for )?(your )?({_SECRET}|code)",
    re.I,
)
_TXN_WORD = r"(debited|credited|withdrawn|spent|deducted|received|paid|sent)"
_TXN_ACCT = r"(a/c|acct|account|card|wallet|upi)"
_TXN_VERB = re.compile(rf"{_TXN_WORD}.{{0,80}}{_TXN_ACCT}|{_TXN_ACCT}.{{0,80}}{_TXN_WORD}", re.I)
_TXN_REF = re.compile(r"(avl\.? ?bal|available (bal|limit)|bal|ref(erence)?\.? ?(no|number)?|utr|txn id|transaction id|xx\d{3,4}|ending \d{4})", re.I)
_PATH_KW = re.compile(r"(login|signin|verify|kyc|update|secure|account|reward|refund|claim|bank|wallet|confirm)", re.I)
_BRAND_IN_TEXT = re.compile(r"\b(sbi|hdfc|icici|axis bank|kotak|pnb|bank of baroda|canara|paytm|phonepe|amazon|flipkart|india ?post|income ?tax|uidai|aadha+r|npci|airtel|jio|bsnl|irctc|epfo|fedex|dhl|blue ?dart|delhivery)\b", re.I)


def detect_signals(norm_text: str, urls: list[str]) -> list[Signal]:
    found: list[Signal] = []
    if _share_secret_request(norm_text):
        found.append(Signal("R01", CRITICAL, 0.5, "It asks you to share a secret code (OTP/PIN/password). Banks never ask for this.", "otp_theft"))
    for sid, sev, w, stype, pattern, reason in _TEXT_RULES:
        if pattern.search(norm_text):
            found.append(Signal(sid, sev, w, reason, stype))

    hosts = [h for h in (host_of(u) for u in urls) if h]
    shortener_hit = False
    for url, host in zip(urls, hosts):
        imp = brand_impersonation(host)
        if imp and not any(s.id == "R04" for s in found):
            brand, reg = imp
            found.append(Signal("R04", CRITICAL, 0.5,
                                f"The link pretends to be {brand.upper()}, but the real website is {reg}.",
                                None, {"brand": brand, "domain": reg}))
        if registered_domain(host) in shorteners() or host in shorteners():
            shortener_hit = True
        if _PATH_KW.search(path_of(url)) and not any(s.id == "R16" for s in found):
            found.append(Signal("R16", MED, 0.1, "The link points to a login/verify/claim page.", None))
    if shortener_hit:
        found.append(Signal("R05", MED, 0.1, "The link is hidden behind a short link, so you can't see where it goes.", None))

    brand_m = _BRAND_IN_TEXT.search(norm_text)
    if brand_m and hosts and not any(s.id == "R04" for s in found):
        from .url_features import _official_domains  # local import keeps the public API small
        official = _official_domains()
        if not any(registered_domain(h) in official for h in hosts):
            found.append(Signal("R04B", HIGH, 0.3,
                                f"It mentions {brand_m.group(0).upper()} but the link goes to a different website.",
                                None, {"brand": brand_m.group(0)}))

    has_critical = any(s.severity == CRITICAL for s in found)
    if not urls and not has_critical and _SAFE_OTP.search(norm_text):
        found.append(Signal("S01", SAFE, -0.3, "Looks like a standard one-time-password notice that tells you not to share it.", None))
    if not urls and not has_critical and _TXN_VERB.search(norm_text) and _TXN_REF.search(norm_text):
        found.append(Signal("S02", SAFE, -0.3, "Looks like a standard bank or payment notification with account references and no links.", None))
    if hosts and not has_critical:
        from .url_features import _official_domains
        official = _official_domains()
        if all(registered_domain(h) in official or h in official for h in hosts):
            found.append(Signal("S03", SAFE, -0.3, "Every link in this message goes to a verified official website.", None))
    return found


SIGNAL_IDS = ["R01", "R02", "R02K", "R03", "R04", "R04B", "R05", "R07", "R08", "R08R", "R09", "R10",
              "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R18", "S01", "S02", "S03"]


def rules_only_score(signals: list[Signal]) -> float:
    """Baseline B0: transparent keyword/rule scoring with no learning."""
    if any(s.severity == CRITICAL for s in signals):
        return 1.0
    return max(0.0, min(1.0, sum(s.weight for s in signals)))
