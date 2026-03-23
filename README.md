# 🛡️ Domain Squatting Detector

A Python CLI tool that automatically scans the internet for domains that may be impersonating yours — catching typosquatting, lookalike domains, and brand hijacking before attackers exploit them.

> **Example:** If your domain is `google.com`, this tool finds threats like `g0ogle.com`, `googel.com`, `google-login.com`, and hundreds more.

---

## 🔍 What It Detects

The tool generates and checks **8 categories** of squatting attacks:

| Technique | Description | Example (`google.com`) |
|---|---|---|
| **Character Substitution** | Swaps letters with lookalikes or numbers | `g0ogle.com`, `goоgle.com` *(Cyrillic о)* |
| **Character Omission** | Drops one letter (easy to miss) | `gogle.com`, `googl.com` |
| **Character Duplication** | Doubles a letter | `gooogle.com`, `googlee.com` |
| **Transposition** | Swaps two adjacent characters | `googel.com`, `goolge.com` |
| **Hyphen Tricks** | Inserts or removes hyphens | `go-ogle.com` |
| **TLD Variations** | Same name, different extension | `google.net`, `google.io`, `google.xyz` |
| **Prefix / Suffix** | Adds common words around your brand | `getgoogle.com`, `google-login.com` |
| **Bitsquatting** | Single-bit character flips (rare, advanced) | Characters 1 bit away in ASCII |

---

## 📋 Requirements

- Python 3.7+
- Optional but recommended:

```bash
pip3 install dnspython python-whois
```

> The tool works without these packages using socket-based DNS fallback, but `dnspython` improves accuracy and `python-whois` enables registrar lookups on inactive domains.

---

## 🚀 Installation

```bash
# Clone the repo
git clone https://github.com/justinroaquin/Domain-Squatter-Detector.git
cd domain-squatting-detector

# Install dependencies
pip3 install dnspython python-whois
```

---

## 🧑‍💻 Usage

```bash
python3 domain_squatter_detector.py <your-domain>
```

### Examples

```bash
# Basic scan
python3 domain_squatter_detector.py google.com

# Save results to a JSON file
python3 domain_squatter_detector.py google.com --output results.json

# Show registrar info for registered domains
python3 domain_squatter_detector.py google.com --verbose

# Faster scan with more threads
python3 domain_squatter_detector.py google.com --threads 50

# Quick test with only 100 variants
python3 domain_squatter_detector.py google.com --limit 100

# Show all domains including available ones
python3 domain_squatter_detector.py google.com --show-all
```

### All Options

| Flag | Default | Description |
|---|---|---|
| `domain` | *(required)* | Your domain to protect, e.g. `google.com` |
| `--threads` | `30` | Number of parallel threads for faster scanning |
| `--output` | *(none)* | Save full results to a `.json` file |
| `--verbose` | `false` | Show WHOIS registrar info next to each result |
| `--show-all` | `false` | Print available (unclaimed) domains too |
| `--limit` | `0` (all) | Cap the number of variants checked (useful for quick tests) |

---

## 📊 Output

During the scan, threats are printed in real time with a progress bar:

```
╔══════════════════════════════════════════════════╗
║        Domain Squatting Detector  v1.0           ║
║  Finds typosquatting / lookalike domain threats  ║
╚══════════════════════════════════════════════════╝

🎯  Target domain : google.com
📋  Variants to check: 4,821
🚀  Threads          : 30
-------------------------------------------------------
  🔴  g0ogle.com                        [RESOLVING]
  🟡  googel.net                         [REGISTERED]
  🔴  google-login.com                  [RESOLVING]
  ...
  [████████████████████] 100%  (4821/4821)

-------------------------------------------------------
✅  Scan complete in 48.3s
🔴  Resolving (live) : 12
🟡  Registered (dark): 7
⬜  Available        : 4802
```

### Status Icons

| Icon | Status | Meaning |
|---|---|---|
| 🔴 | **Resolving** | Domain is live with active DNS — highest risk |
| 🟡 | **Registered** | Domain is registered but inactive / parked — still a threat |
| ⬜ | **Available** | Not registered — safe |

### JSON Output Format

When using `--output results.json`:

```json
{
  "scanned_at": "2026-03-22T10:00:00Z",
  "target": "google.com",
  "total_checked": 4821,
  "threats": [
    {
      "domain": "g0ogle.com",
      "dns_resolves": true,
      "status": "resolving",
      "whois": {
        "registrar": "GoDaddy LLC",
        "creation_date": "2021-04-15",
        "expiration_date": "2027-04-15"
      }
    }
  ],
  "all_results": [...]
}
```

---

## ⚠️ Limitations

- **No content analysis** — the tool checks whether a domain exists, not what it hosts. It won't tell you if a site is actively phishing.
- **WHOIS accuracy** — some registrars block or throttle WHOIS lookups, so registrar data may occasionally be incomplete.
- **Rate limiting** — very aggressive thread counts may get your IP temporarily blocked by some DNS resolvers. The default of 30 threads is safe for most cases.
- **Scan time** — a full scan typically generates 3,000–6,000 variants depending on domain length. With 30 threads this usually finishes in under 2 minutes.

---

## 🗺️ Roadmap

- [ ] HTTP/HTTPS reachability check (is there an actual website?)
- [ ] Screenshot capture of live squatting sites
- [ ] Email / Slack alerting for scheduled scans
- [ ] Similarity scoring to rank threats by risk level
- [ ] Support for scanning multiple domains at once

---

## 📄 License

This script is purely vibe coded and for research purposes 😁 Do not use for production without reviewing the code.

---

## 🤝 Contributing

Pull requests are welcome! If you find a new squatting technique or want to add TLDs to the watchlist, feel free to open an issue or PR.
