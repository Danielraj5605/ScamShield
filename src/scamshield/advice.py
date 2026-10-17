"""Plain-language advice per scam type. Reviewed wording; verify helpline details before any demo."""
from __future__ import annotations

REPORT_EN = "Report it: call the National Cyber Crime Helpline 1930 or visit cybercrime.gov.in."

TYPE_LABELS = {
    "kyc": "fake KYC / account-block",
    "otp_theft": "OTP or card-details theft",
    "refund_upi": "fake refund / UPI request",
    "parcel": "fake parcel / delivery",
    "job": "fake job / task",
    "utility": "electricity or connection disconnection",
    "impersonation": "police / official impersonation (\"digital arrest\")",
    "prize": "lottery / prize",
    "loan": "instant loan",
    "investment": "investment / trading",
    "remote_access": "remote-access app",
    "fake_alert": "fake bank alert",
}

ADVICE_EN = {
    "kyc": "Banks do not block accounts or ask for KYC updates through SMS links. Open your bank's official app or visit a branch.",
    "otp_theft": "Never share an OTP, PIN, CVV or password with anyone, even if they say they are from your bank.",
    "refund_upi": "You never need to enter your UPI PIN or approve a request to receive money. Decline the request.",
    "parcel": "Check your order only on the official courier or shopping website or app. Don't pay small 'fees' through links.",
    "job": "Real employers don't ask you to pay a fee or do paid 'tasks'. Don't send money or personal documents.",
    "utility": "Electricity boards don't disconnect you through a personal mobile number. Check your bill on the official board website or app.",
    "impersonation": "Hang up. Police, courts and officials never arrest anyone or demand money over a phone or video call.",
    "prize": "You can't win a lottery you never entered. Don't pay any 'tax' or 'fee' to claim a prize.",
    "loan": "Only borrow through banks or RBI-registered lenders. Never pay an upfront fee for a loan.",
    "investment": "Guaranteed high returns are a warning sign. Don't send money to trading groups on WhatsApp or Telegram.",
    "remote_access": "Never install AnyDesk, TeamViewer or an APK file because someone asked you to. Uninstall it if you already did.",
    "fake_alert": "Check your balance in your bank's official app. Only call the number printed on your card or the bank's website.",
    "default_high": "Do not click links, call numbers or share codes from this message. If unsure, contact the organisation using its official app or website.",
    "medium": "Be careful. Don't share personal details or click links unless you are sure who sent this message.",
    "low": "We didn't find common scam signs, but stay alert. When in doubt, ask someone you trust.",
}

def build_advice(level: str, scam_type: str | None) -> list[str]:
    table = ADVICE_EN
    if level == "LOW":
        return [table.get("low", ADVICE_EN["low"])]
    if level == "MEDIUM":
        return [table.get(scam_type or "", table.get("medium", ADVICE_EN["medium"]))]
    first = table.get(scam_type or "", None) or table.get("default_high", ADVICE_EN["default_high"])
    return [first, REPORT_EN]
