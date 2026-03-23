#!/usr/bin/env python3
"""
Domain Squatting Detector
Generates lookalike/typosquatting variants of your domain and checks
which ones are registered (i.e., potentially squatting on your brand).

Usage:
    python domain_squatter_detector.py google.com
    python domain_squatter_detector.py google.com --threads 20 --output results.json
"""

import argparse
import concurrent.futures
import json
import socket
import sys
import time
from datetime import datetime
from itertools import product

# ── Optional dependencies (graceful fallback if not installed) ────────────────
try:
    import whois  # pip install python-whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver  # pip install dnspython
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ── Character substitution map (visual lookalikes / keyboard neighbors) ───────
CHAR_SWAPS = {
    "a": ["4", "@", "à", "á", "â", "ä", "е"],  # Cyrillic е looks like Latin e
    "b": ["d", "lb", "ib", "vb"],
    "c": ["k", "е"],
    "d": ["b", "cl", "dl"],
    "e": ["3", "é", "ê", "ë", "е"],             # Cyrillic е
    "f": ["ph"],
    "g": ["9", "q", "gg"],
    "i": ["1", "l", "!", "і"],                  # Cyrillic і
    "l": ["1", "i", "|", "Ⅼ"],
    "m": ["n", "nn", "rn"],
    "n": ["m", "ni", "nr"],
    "o": ["0", "ο", "о"],                        # Greek ο / Cyrillic о
    "p": ["рp"],
    "q": ["g", "9"],
    "r": ["n"],
    "s": ["5", "$", "z"],
    "t": ["7", "+"],
    "u": ["v", "ü"],
    "v": ["u", "vv"],
    "w": ["vv", "uu", "2u"],
    "x": ["ks"],
    "y": ["j", "ÿ"],
    "z": ["s", "2"],
}

# Common TLDs used in squatting
SQUATTING_TLDS = [
    "com", "net", "org", "info", "biz", "co",
    "io", "online", "site", "website", "store",
    "shop", "app", "xyz", "club", "us", "uk",
    "cc", "tv", "mobi", "pw",
]

# Common squatting prefixes/suffixes
PREFIXES = ["my", "get", "the", "buy", "best", "go", "try", "use", "www", "login", "secure", "account", "support"]
SUFFIXES = ["online", "official", "store", "shop", "app", "web", "site", "help", "support", "login", "secure"]


# ── Variant generators ────────────────────────────────────────────────────────

def split_domain(domain: str):
    """Return (name, tld) — e.g. 'google.com' → ('google', 'com')."""
    parts = domain.lower().rsplit(".", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return parts[0], "com"


def gen_char_substitutions(name: str) -> set:
    """Replace one character at a time with lookalikes."""
    variants = set()
    for i, ch in enumerate(name):
        for swap in CHAR_SWAPS.get(ch, []):
            variants.add(name[:i] + swap + name[i+1:])
    return variants


def gen_char_omissions(name: str) -> set:
    """Drop one character at a time."""
    return {name[:i] + name[i+1:] for i in range(len(name))}


def gen_char_duplications(name: str) -> set:
    """Double one character at a time."""
    return {name[:i] + ch + name[i:] for i, ch in enumerate(name)}


def gen_adjacent_swaps(name: str) -> set:
    """Swap adjacent characters (fat-finger transpositions)."""
    variants = set()
    lst = list(name)
    for i in range(len(lst) - 1):
        lst[i], lst[i+1] = lst[i+1], lst[i]
        variants.add("".join(lst))
        lst[i], lst[i+1] = lst[i+1], lst[i]  # swap back
    return variants


def gen_char_insertions(name: str) -> set:
    """Insert each keyboard-neighbor character at every position."""
    neighbors = "abcdefghijklmnopqrstuvwxyz0123456789-"
    variants = set()
    for i in range(len(name) + 1):
        for ch in neighbors:
            new = name[:i] + ch + name[i:]
            if new != name:
                variants.add(new)
    return variants


def gen_hyphen_tricks(name: str) -> set:
    """Add/remove hyphens between characters."""
    variants = set()
    # Insert hyphen between each pair
    for i in range(1, len(name)):
        variants.add(name[:i] + "-" + name[i:])
    # Remove existing hyphens
    if "-" in name:
        variants.add(name.replace("-", ""))
    return variants


def gen_tld_variants(name: str, original_tld: str) -> list:
    """Same name, different TLDs."""
    return [f"{name}.{tld}" for tld in SQUATTING_TLDS if tld != original_tld]


def gen_prefix_suffix(name: str, tld: str) -> list:
    """Prepend / append common words."""
    variants = []
    for p in PREFIXES:
        variants.append(f"{p}{name}.{tld}")
        variants.append(f"{p}-{name}.{tld}")
    for s in SUFFIXES:
        variants.append(f"{name}{s}.{tld}")
        variants.append(f"{name}-{s}.{tld}")
    return variants


def gen_bitsquatting(name: str) -> set:
    """Single-bit flip in each character (bitsquatting)."""
    variants = set()
    for i, ch in enumerate(name):
        code = ord(ch)
        for bit in range(8):
            flipped = chr(code ^ (1 << bit))
            if flipped.isalnum() or flipped == "-":
                variants.add(name[:i] + flipped + name[i+1:])
    return variants


def generate_all_variants(domain: str) -> list:
    """Collect all candidate squatting domains."""
    name, tld = split_domain(domain)
    candidates = set()

    # Name-level mutations → paired with original TLD
    mutations = (
        gen_char_substitutions(name)
        | gen_char_omissions(name)
        | gen_char_duplications(name)
        | gen_adjacent_swaps(name)
        | gen_hyphen_tricks(name)
        | gen_bitsquatting(name)
    )

    for m in mutations:
        if m and len(m) > 1:                # skip empty / single-char names
            candidates.add(f"{m}.{tld}")
            # Also cross with a few high-risk TLDs
            for t in ["com", "net", "org"]:
                if t != tld:
                    candidates.add(f"{m}.{t}")

    # TLD-only variants
    for v in gen_tld_variants(name, tld):
        candidates.add(v)

    # Prefix / suffix variants
    for v in gen_prefix_suffix(name, tld):
        candidates.add(v)

    # Remove the original domain itself
    candidates.discard(domain.lower())

    return sorted(candidates)


# ── Registration checker ──────────────────────────────────────────────────────

def check_dns(domain: str, timeout: float = 3.0) -> bool:
    """Return True if the domain resolves (has DNS records)."""
    if DNS_AVAILABLE:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.resolve(domain, "A")
            return True
        except Exception:
            pass
        try:
            resolver.resolve(domain, "NS")
            return True
        except Exception:
            return False
    else:
        # Fallback: basic socket lookup
        try:
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(domain)
            return True
        except socket.error:
            return False


def check_whois(domain: str) -> dict:
    """Return WHOIS info if available."""
    if not WHOIS_AVAILABLE:
        return {}
    try:
        w = whois.whois(domain)
        return {
            "registrar": getattr(w, "registrar", None),
            "creation_date": str(getattr(w, "creation_date", None)),
            "expiration_date": str(getattr(w, "expiration_date", None)),
        }
    except Exception:
        return {}


def check_domain(domain: str) -> dict:
    """Full check for one candidate domain."""
    result = {
        "domain": domain,
        "dns_resolves": False,
        "whois": {},
        "status": "available",   # available | registered | resolving
    }
    dns_ok = check_dns(domain)
    result["dns_resolves"] = dns_ok

    if dns_ok:
        result["status"] = "resolving"          # definitely registered & live
        result["whois"] = check_whois(domain)
    else:
        # WHOIS check even without DNS (parked / inactive domains)
        w = check_whois(domain)
        if w:
            result["status"] = "registered"
            result["whois"] = w

    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

def print_banner():
    print("""
╔══════════════════════════════════════════════════╗
║        Domain Squatting Detector  v1.0           ║
║  Finds typosquatting / lookalike domain threats  ║
╚══════════════════════════════════════════════════╝
""")


def print_result(r: dict, verbose: bool = False):
    status = r["status"]
    icon = {"resolving": "🔴", "registered": "🟡", "available": "⬜"}.get(status, "❓")
    line = f"  {icon}  {r['domain']:<40} [{status.upper()}]"
    if verbose and r["whois"]:
        registrar = r["whois"].get("registrar") or "unknown"
        line += f"  registrar={registrar}"
    print(line)


def main():
    parser = argparse.ArgumentParser(
        description="Detect domain squatting / typosquatting for your domain."
    )
    parser.add_argument("domain", help="Your domain, e.g. google.com")
    parser.add_argument("--threads", type=int, default=30, help="Parallel threads (default 30)")
    parser.add_argument("--output", help="Save results to JSON file")
    parser.add_argument("--verbose", action="store_true", help="Show WHOIS registrar info")
    parser.add_argument("--show-all", action="store_true", help="Also print available (unclaimed) domains")
    parser.add_argument("--limit", type=int, default=0,
                        help="Max variants to check (0 = all; use for quick tests)")
    args = parser.parse_args()

    print_banner()

    if not WHOIS_AVAILABLE:
        print("⚠️  python-whois not installed. WHOIS lookups disabled.")
        print("   Install with: pip install python-whois\n")
    if not DNS_AVAILABLE:
        print("⚠️  dnspython not installed. Using socket fallback for DNS.")
        print("   Install with: pip install dnspython\n")

    domain = args.domain.lower().strip()
    print(f"🎯  Target domain : {domain}")
    print(f"⚙️   Generating variants …")
    variants = generate_all_variants(domain)

    if args.limit:
        variants = variants[:args.limit]

    print(f"📋  Variants to check: {len(variants):,}")
    print(f"🚀  Threads          : {args.threads}")
    print("-" * 55)

    results = []
    threats = []
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_map = {executor.submit(check_domain, v): v for v in variants}
        done = 0
        for future in concurrent.futures.as_completed(future_map):
            done += 1
            try:
                r = future.result()
                results.append(r)
                if r["status"] != "available":
                    threats.append(r)
                    print_result(r, verbose=args.verbose)
                elif args.show_all:
                    print_result(r)
            except Exception as exc:
                pass  # silently skip errors

            # Progress bar every 50 completions
            if done % 50 == 0 or done == len(variants):
                pct = done / len(variants) * 100
                bar = "█" * int(pct // 5) + "░" * (20 - int(pct // 5))
                print(f"\r  [{bar}] {pct:.0f}%  ({done}/{len(variants)})", end="", flush=True)

    elapsed = time.time() - start
    print(f"\n\n{'─'*55}")
    print(f"✅  Scan complete in {elapsed:.1f}s")
    print(f"🔴  Resolving (live) : {sum(1 for r in results if r['status']=='resolving')}")
    print(f"🟡  Registered (dark): {sum(1 for r in results if r['status']=='registered')}")
    print(f"⬜  Available        : {sum(1 for r in results if r['status']=='available')}")
    print(f"{'─'*55}\n")

    if threats:
        print("⚠️  THREAT SUMMARY — domains that may be squatting on you:\n")
        for r in sorted(threats, key=lambda x: x["status"]):
            print_result(r, verbose=True)

    if args.output:
        output = {
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "target": domain,
            "total_checked": len(results),
            "threats": threats,
            "all_results": results,
        }
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\n💾  Results saved to: {args.output}")


if __name__ == "__main__":
    main()