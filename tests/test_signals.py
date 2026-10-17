import pytest

from scamshield.features import prepare
from scamshield.signals import CRITICAL, rules_only_score


def ids(text):
    return {s.id for s in prepare(text).signals}


@pytest.mark.parametrize("text", [
    "Please share the OTP you received to verify your refund",
    "Kindly send me the 0TP sent to your phone",
    "tell me your atm pin to unblock the card",
])
def test_share_secret_request_fires(text):
    assert "R01" in ids(text)


@pytest.mark.parametrize("text", [
    "482913 is your OTP. Do not share it with anyone. -HDFC Bank",
    "Never share your OTP or PIN with anyone",
    "Share OTP 5521 with the delivery agent only at the time of delivery.",
])
def test_share_secret_request_not_fired_on_warnings(text):
    assert "R01" not in ids(text)


def test_safe_otp_signal():
    assert "S01" in ids("482913 is your OTP for txn of Rs 500. Do not share it with anyone.")
    assert "S01" not in ids("Your OTP is 4821, do not share. Verify at sbi-kyc.top")  # link present


@pytest.mark.parametrize("text,sid", [
    ("Your electricity will be disconnected tonight", "R10"),
    ("You are under digital arrest, stay on the call", "R11"),
    ("Install AnyDesk and share the code", "R13"),
    ("Enter your UPI PIN to receive the cashback", "R07"),
    ("Part time job, earn 3000 per day", "R09"),
    ("Your parcel is on hold, pay Rs 25 fee", "R12"),
    ("Visit sbi-kyc-update.top to update", "R04"),
    ("Dear SBI customer update at kyc-help.top", "R04B"),
    ("Click bit.ly/abc", "R05"),
    ("Hi, I sent Rs 4,000 to your number by mistake. Please return it", "R18"),
    ("Sorry, I transferred Rs 12,500 to your account wrongly. Kindly send it back", "R18"),
])

def test_specific_signals(text, sid):
    assert sid in ids(text)

def test_mistaken_payment_signal_ignores_ordinary_mistakes():
    assert "R18" not in ids("Sorry, I attached the wrong file by mistake, please resend")
    assert "R18" not in ids("I took your pen by mistake, will return it tomorrow")


def test_official_link_not_brand_mismatch():
    assert not {"R04", "R04B"} & ids("Your Amazon order is out for delivery. Track: https://www.amazon.in/orders")


def test_rules_only_baseline():
    assert rules_only_score(prepare("You are under digital arrest").signals) == 1.0
    assert rules_only_score(prepare("see you at 5").signals) == 0.0
    assert all(s.severity != CRITICAL for s in prepare("hello").signals)
