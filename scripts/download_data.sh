#!/usr/bin/env sh
# Download the three public datasets into data/raw/ and verify their SHA-256 checksums.
# Licences: UCI SMS Spam Collection (CC BY 4.0), Mendeley SMS Phishing Dataset (CC BY 4.0),
# PhiUSIIL Phishing URL Dataset (CC BY 4.0). See docs/DATA_CARD.md.
set -eu
mkdir -p "$(dirname "$0")/../data/raw"
cd "$(dirname "$0")/../data/raw"

fetch() {  # dir url file sha256
  mkdir -p "$1"
  if [ ! -f "$1/$3" ]; then
    echo "downloading $1/$3"
    curl -fsSL -o "$1/$3" "$2"
  fi
  actual=$(sha256sum "$1/$3" | cut -d' ' -f1)
  if [ "$actual" != "$4" ]; then
    echo "CHECKSUM MISMATCH for $1/$3 (got $actual)" >&2
    exit 1
  fi
  (cd "$1" && unzip -o -q "$3")
  echo "ok  $1/$3"
}

fetch uci_sms  "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip" sms.zip \
  1587ea43e58e82b14ff1f5425c88e17f8496bfcdb67a583dbff9eefaf9963ce3
fetch mendeley "https://data.mendeley.com/public-files/datasets/f45bkkt8pr/files/edb361de-918d-469f-9106-e84823830665/file_downloaded" Dataset_5971.zip \
  9bbf3188fdad81495d8e82825648b9b63b53fc86841a3d26c02629990b233cc3
fetch phiusiil "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip" phiusiil.zip \
  0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a
echo "all datasets present"
