#!/usr/bin/env python3
# Darknode Threat Feed Aggregator
# Downloads free public threat intelligence feeds and saves as JSON files
# for the Darknode website to serve directly (no CORS, no API keys).
# Usage: python3 threat-feed-sync.py
# Recommended: run via cron every 6-12 hours

import json
import os
import sys
import ssl
import gzip
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from io import BytesIO

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "data", "feeds")
MAX_ENTRIES = 500
TIMEOUT = 30
USER_AGENT = "Darknode-ThreatSync/1.0 (https://darknode.ai)"

FEEDS = {
    "cisa-kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "file": "cisa-kev.json",
    },
    "feodo": {
        "name": "Feodo Tracker Botnet C2",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "file": "botnet-c2.json",
    },
    "urlhaus": {
        "name": "URLhaus Malware URLs",
        "url": "https://urlhaus.abuse.ch/downloads/json_recent/",
        "file": "malware-urls.json",
    },
    "threatfox": {
        "name": "ThreatFox IOCs",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "file": "threat-iocs.json",
    },
    "firehol": {
        "name": "FireHOL Level 1 Blocklist",
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "file": None,
    },
    "ipsum": {
        "name": "stamparm IPSUM Threat IPs",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "file": None,
    },
}


def log(msg):
    print("[%s] %s" % (datetime.now(timezone.utc).strftime("%H:%M:%S"), msg))


def fetch_url(url):
    ctx = ssl.create_default_context()
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"})
    resp = urlopen(req, timeout=TIMEOUT, context=ctx)
    raw = resp.read()
    if resp.headers.get("Content-Encoding") == "gzip":
        raw = gzip.GzipFile(fileobj=BytesIO(raw)).read()
    return raw


def save_feed(filename, data_list, source_name):
    now = datetime.now(timezone.utc).isoformat()
    trimmed = data_list[:MAX_ENTRIES]
    payload = {"updated": now, "source": source_name, "count": len(trimmed), "data": trimmed}
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w") as f:
        json.dump(payload, f, indent=1)
    return len(trimmed)


def sync_cisa_kev():
    log("Fetching CISA KEV catalog...")
    raw = fetch_url(FEEDS["cisa-kev"]["url"])
    blob = json.loads(raw)
    vulns = blob.get("vulnerabilities", [])
    entries = []
    for v in vulns:
        entries.append({
            "cve": v.get("cveID", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "description": v.get("shortDescription", ""),
            "dateAdded": v.get("dateAdded", ""),
            "dueDate": v.get("dueDate", ""),
            "action": v.get("requiredAction", ""),
            "knownRansomware": v.get("knownRansomwareCampaignUse", "Unknown"),
        })
    entries.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    count = save_feed(FEEDS["cisa-kev"]["file"], entries, "CISA KEV")
    log("  CISA KEV: %d vulnerabilities (saved %d)" % (len(vulns), count))
    return count


def sync_feodo():
    log("Fetching Feodo Tracker botnet C2 list...")
    raw = fetch_url(FEEDS["feodo"]["url"])
    blob = json.loads(raw)
    items = []
    for entry in blob:
        items.append({
            "ip": entry.get("ip_address", ""),
            "port": entry.get("port", 0),
            "status": entry.get("status", ""),
            "malware": entry.get("malware", ""),
            "firstSeen": entry.get("first_seen", ""),
            "lastOnline": entry.get("last_online", ""),
            "asName": entry.get("as_name", ""),
            "asNumber": entry.get("as_number", 0),
            "country": entry.get("country", ""),
        })
    items.sort(key=lambda x: x.get("firstSeen", ""), reverse=True)
    count = save_feed(FEEDS["feodo"]["file"], items, "Feodo Tracker (abuse.ch)")
    log("  Feodo Tracker: %d C2 servers (saved %d)" % (len(blob), count))
    return count


def sync_urlhaus():
    log("Fetching URLhaus malware URLs...")
    raw = fetch_url(FEEDS["urlhaus"]["url"])
    blob = json.loads(raw)
    items = []
    urls_data = blob if isinstance(blob, list) else list(blob.values()) if isinstance(blob, dict) else []
    if isinstance(blob, dict) and "urls" in blob:
        urls_data = blob["urls"]
    elif isinstance(blob, dict) and len(blob) > 0:
        first_val = next(iter(blob.values()))
        if isinstance(first_val, dict):
            urls_data = list(blob.values())
    for entry in urls_data:
        if not isinstance(entry, dict):
            continue
        tags = entry.get("tags", [])
        if tags is None:
            tags = []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        items.append({
            "url": entry.get("url", ""),
            "status": entry.get("url_status", entry.get("status", "")),
            "host": entry.get("host", ""),
            "threat": entry.get("threat", ""),
            "tags": tags,
            "dateAdded": entry.get("dateadded", entry.get("date_added", "")),
            "reporter": entry.get("reporter", ""),
            "urlhausRef": entry.get("urlhaus_reference", ""),
        })
    items.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    count = save_feed(FEEDS["urlhaus"]["file"], items, "URLhaus (abuse.ch)")
    log("  URLhaus: %d malware URLs (saved %d)" % (len(items), count))
    return count


def sync_threatfox():
    log("Fetching ThreatFox IOCs...")
    raw = fetch_url(FEEDS["threatfox"]["url"])
    blob = json.loads(raw)
    items = []
    ioc_data = []
    if isinstance(blob, dict):
        if "data" in blob:
            data_val = blob["data"]
            if isinstance(data_val, list):
                ioc_data = data_val
            elif isinstance(data_val, dict):
                for key in data_val:
                    entries = data_val[key]
                    if isinstance(entries, list):
                        ioc_data.extend(entries)
                    elif isinstance(entries, dict):
                        ioc_data.append(entries)
    for entry in ioc_data:
        if not isinstance(entry, dict):
            continue
        tags = entry.get("tags", [])
        if tags is None:
            tags = []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        items.append({
            "ioc": entry.get("ioc", entry.get("ioc_value", "")),
            "iocType": entry.get("ioc_type", entry.get("ioc_type_desc", "")),
            "threatType": entry.get("threat_type", ""),
            "threatDesc": entry.get("threat_type_desc", ""),
            "malware": entry.get("malware_printable", entry.get("malware", "")),
            "malwareAlias": entry.get("malware_alias", ""),
            "confidence": entry.get("confidence_level", 0),
            "firstSeen": entry.get("first_seen", ""),
            "lastSeen": entry.get("last_seen", ""),
            "reporter": entry.get("reporter", ""),
            "tags": tags,
            "reference": entry.get("reference", ""),
        })
    items.sort(key=lambda x: x.get("firstSeen", ""), reverse=True)
    count = save_feed(FEEDS["threatfox"]["file"], items, "ThreatFox (abuse.ch)")
    log("  ThreatFox: %d IOCs (saved %d)" % (len(items), count))
    return count


def sync_firehol():
    log("Fetching FireHOL Level 1 blocklist...")
    raw = fetch_url(FEEDS["firehol"]["url"])
    text = raw.decode("utf-8", errors="replace")
    ips = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip = line.split("/")[0].strip()
        if ip and ip[0].isdigit():
            ips[ip] = {"ip": ip, "score": 5, "source": "firehol", "subnet": line if "/" in line else None}
    log("  FireHOL: %d IPs parsed" % len(ips))
    return ips


def sync_ipsum():
    log("Fetching stamparm IPSUM threat IPs...")
    raw = fetch_url(FEEDS["ipsum"]["url"])
    text = raw.decode("utf-8", errors="replace")
    ips = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            ip = parts[0].strip()
            try:
                score = int(parts[1].strip())
            except ValueError:
                score = 1
            if ip and ip[0].isdigit():
                ips[ip] = {"ip": ip, "score": score, "source": "ipsum"}
    log("  IPSUM: %d IPs parsed" % len(ips))
    return ips


def sync_malicious_ips():
    firehol_ips = {}
    ipsum_ips = {}
    try:
        firehol_ips = sync_firehol()
    except Exception as e:
        log("  [WARN] FireHOL fetch failed: %s" % str(e))
    try:
        ipsum_ips = sync_ipsum()
    except Exception as e:
        log("  [WARN] IPSUM fetch failed: %s" % str(e))

    combined = {}
    for ip, entry in firehol_ips.items():
        combined[ip] = entry
    for ip, entry in ipsum_ips.items():
        if ip in combined:
            combined[ip]["score"] = max(combined[ip]["score"], entry["score"])
            combined[ip]["source"] = "firehol+ipsum"
        else:
            combined[ip] = entry

    sorted_ips = sorted(combined.values(), key=lambda x: x.get("score", 0), reverse=True)
    count = save_feed("malicious-ips.json", sorted_ips, "FireHOL + stamparm IPSUM")
    total_fh = len(firehol_ips)
    total_ip = len(ipsum_ips)
    log("  Malicious IPs: %d FireHOL + %d IPSUM = %d combined (saved %d)" % (total_fh, total_ip, len(combined), count))
    return count


def main():
    print("")
    print("=" * 60)
    print("  DARKNODE THREAT FEED SYNC")
    print("  %s" % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("=" * 60)
    print("")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    results = {}
    errors = []

    tasks = [
        ("CISA KEV", sync_cisa_kev),
        ("Feodo Tracker", sync_feodo),
        ("URLhaus", sync_urlhaus),
        ("ThreatFox", sync_threatfox),
        ("Malicious IPs", sync_malicious_ips),
    ]

    for name, func in tasks:
        try:
            count = func()
            results[name] = count
        except Exception as e:
            log("[ERROR] %s failed: %s" % (name, str(e)))
            errors.append(name)
            results[name] = 0
        print("")

    print("=" * 60)
    print("  SYNC SUMMARY")
    print("=" * 60)
    for name, count in results.items():
        status = "OK" if count > 0 else "FAILED"
        print("  %-20s %5d entries  [%s]" % (name, count, status))
    print("")
    print("  Output directory: %s" % OUTPUT_DIR)
    if errors:
        print("  Errors: %s" % ", ".join(errors))
        print("  (Failed feeds will retry on next run)")
    else:
        print("  All feeds synced successfully!")
    print("=" * 60)
    print("")

    if errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
