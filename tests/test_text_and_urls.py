from scamshield.normalize import normalize, placeholderize
from scamshield.url_features import FEATURE_NAMES, brand_impersonation, url_features
from scamshield.urls import defang, extract_urls, host_of, registered_domain


def test_normalize_folds_lookalikes_and_zero_width():
    assert normalize("Ѕ​ВІ") == "sbi"          # Cyrillic look-alikes + zero-width space
    assert normalize("ＦＲＥＥ  prize") == "free prize"   # full-width letters, extra spaces


def test_normalize_refangs_links():
    assert normalize("hxxps://bad[.]top/x") == "https://bad.top/x"


def test_placeholders():
    out = placeholderize(normalize("Pay Rs 1,250 now, call 9XXXXX1234 or +91 98765 43210, code 4521"))
    assert "__amt__" in out and out.count("__phone__") == 2 and "__num__" in out
    assert "1250" not in out and "1,250" not in out


def test_extract_urls_explicit_and_bare():
    text = normalize("Update at sbi-kyc.top/login or https://bit.ly/abc. e.g. Rs.500 is fine")
    assert extract_urls(text) == ["https://bit.ly/abc", "sbi-kyc.top/login"]


def test_extract_urls_ignores_plain_text():
    assert extract_urls(normalize("ok see u at 5.30 i.e. after class")) == []


def test_hosts_and_registered_domains():
    assert host_of("https://www.SBI.co.in/web") == "sbi.co.in"
    assert registered_domain("a.b.sbi.co.in") == "sbi.co.in"
    assert registered_domain("login.sbi-kyc-update.top") == "sbi-kyc-update.top"


def test_brand_impersonation():
    assert brand_impersonation("sbi-kyc-update.top") == ("sbi", "sbi-kyc-update.top")
    assert brand_impersonation("onlinesbi-verify.com") is not None
    assert brand_impersonation("hdfcbnak.com") is not None           # typosquat
    assert brand_impersonation("onlinesbi.sbi") is None              # official
    assert brand_impersonation("netbanking.hdfcbank.com") is None    # official subdomain
    assert brand_impersonation("taxisbooking.com") is None


def test_url_features_shape():
    assert len(url_features("paytm-reward7.xyz")) == len(FEATURE_NAMES)


def test_defang():
    assert defang("http://a.top/x") == "hxxp://a[.]top/x"
