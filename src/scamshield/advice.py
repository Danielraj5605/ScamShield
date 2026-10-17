"""Plain-language advice per scam type. Reviewed wording; verify helpline details before any demo."""
from __future__ import annotations

REPORT_EN = "Report it: call the National Cyber Crime Helpline 1930 or visit cybercrime.gov.in."

TYPE_LABELS = {
    "kyc": "fake KYC or account-block",
    "otp_theft": "OTP or card-details theft",
    "refund_upi": "fake refund or UPI request",
    "parcel": "fake parcel or delivery",
    "job": "fake job or task",
    "utility": "electricity or connection disconnection",
    "impersonation": "police or official impersonation (\"digital arrest\")",
    "prize": "lottery or prize",
    "loan": "instant loan",
    "investment": "investment or trading",
    "remote_access": "remote-access app",
    "fake_alert": "fake bank alert",
}

TYPE_DESCRIPTIONS = {
    "kyc": "Scammers use it to send people to a fake page that captures bank logins and one-time passwords.",
    "otp_theft": "A one-time password or PIN approves a payment, so anyone who gets it can take money from the account.",
    "refund_upi": "In UPI you only enter a PIN to send money, so a request to enter it to receive money is a way to take money out.",
    "parcel": "The small fee or address form is usually a way to collect card details.",
    "job": "These offers often pay small amounts at first, then ask for fees or deposits that are usually not returned.",
    "utility": "The threat of an immediate cut-off is used to push people into calling a number or paying through a link.",
    "impersonation": "Real officials do not arrest anyone or demand money over a message or video call.",
    "prize": "You cannot win a lottery you never entered. The aim is usually a fee or your bank details.",
    "loan": "Genuine lenders do not ask for a fee before paying out a loan, so the fee is usually the scam.",
    "investment": "No legitimate investment can guarantee high returns, and the balances shown to victims are usually fake.",
    "remote_access": "These apps let a stranger see your screen, read your codes and control your phone.",
    "fake_alert": "The phone number or link in such an alert usually leads to the scammer, not to your bank.",
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
