#!/usr/bin/env python3
"""
fetch_feeds.py - Descarga los feeds oficiales de avisos de seguridad de los fabricantes
y los consolida en data/feeds.json para que Radar VOC los lea.

Solo maneja informacion publica de los fabricantes. No agregar aqui inventario,
nombres de clientes ni versiones instaladas.
"""
import calendar
import json
import os
import re
from datetime import datetime, timedelta, timezone

import feedparser
import requests

FEEDS = {
    "Palo Alto": ["https://security.paloaltonetworks.com/rss.xml"],
    "Cisco": ["https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
              "https://sec.cloudapps.cisco.com/security/center/rss.x?i=44"],
    "Fortinet": ["https://www.fortiguard.com/rss/ir.xml",
                 "https://filestore.fortinet.com/fortiguard/rss/ir.xml"],
    "Microsoft": ["https://api.msrc.microsoft.com/update-guide/rss"],
    "Ivanti": ["https://www.ivanti.com/blog/topics/security-advisory/rss"],
    "Citrix": ["https://support.citrix.com/feed/products/all/securitybulletins.rss"],
}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "feeds.json")
KEEP_DAYS = 90            # historial que se conserva en el archivo
DETAIL_DAYS = 14          # solo se abre la pagina del aviso si es de los ultimos 14 dias
MAX_DETAIL_PER_VENDOR = 25
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SEV_RE = re.compile(r"\b(?:severity|severidad)\b[^A-Za-z]{0,40}(critical|high|medium|moderate|low|important)", re.I)
CVSS_RE = re.compile(r"CVSS(?:[^0-9]{0,6}v?[234]\.[01])?[^0-9]{0,40}?(10\.0|\d\.\d)", re.I)

http = requests.Session()
http.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "application/rss+xml, application/xml, text/xml, text/html;q=0.9, */*;q=0.8",
})


def iso(entry):
    for key in ("published_parsed", "updated_parsed"):
        t = entry.get(key)
        if t:
            return datetime.fromtimestamp(calendar.timegm(t), tz=timezone.utc).isoformat()
    return None


def clean(html, n=600):
    text = re.sub(r"<[^>]+>", " ", html or "")
    return re.sub(r"\s+", " ", text).strip()[:n]


def detail(url):
    """Abre la pagina del aviso para sacar CVE, severidad y CVSS cuando el RSS no los trae."""
    try:
        r = http.get(url, timeout=30)
        if r.status_code != 200:
            return {}
        text = clean(r.text, 200000)
        sev = SEV_RE.search(text)
        cvss = CVSS_RE.search(text)
        return {"cves": sorted({c.upper() for c in CVE_RE.findall(text)})[:40],
                "severity": sev.group(1).capitalize() if sev else None,
                "cvss": float(cvss.group(1)) if cvss else None}
    except Exception:  # noqa: BLE001
        return {}


def fetch_vendor(vendor, urls, previous):
    last_err = None
    for url in urls:
        try:
            r = http.get(url, timeout=45)
            if r.status_code != 200:
                last_err = f"HTTP {r.status_code} en {url}"
                continue
            feed = feedparser.parse(r.content)
            if not feed.entries:
                last_err = f"feed vacio o ilegible en {url}"
                continue
            items, opened = [], 0
            recent = datetime.now(timezone.utc) - timedelta(days=DETAIL_DAYS)
            for e in feed.entries:
                link = e.get("link", "")
                text = f"{e.get('title', '')} {e.get('summary', '')}"
                item = {
                    "vendor": vendor, "title": clean(e.get("title", ""), 300), "link": link,
                    "published": iso(e), "summary": clean(e.get("summary", "")),
                    "cves": sorted({c.upper() for c in CVE_RE.findall(text)})[:40],
                    "severity": (SEV_RE.search(text).group(1).capitalize() if SEV_RE.search(text) else None),
                    "cvss": (float(CVSS_RE.search(text).group(1)) if CVSS_RE.search(text) else None),
                    "thirdParty": bool(re.search(r"\bimpact of\b|third[- ]party|open ?source component", text, re.I)),
                }
                prev = previous.get(link)
                if prev and prev.get("detailFetched"):
                    for k in ("cves", "severity", "cvss"):
                        item[k] = item[k] or prev.get(k)
                    item["detailFetched"] = True
                else:
                    pub = item["published"]
                    is_recent = pub is None or datetime.fromisoformat(pub) >= recent
                    needs = not item["cves"] or item["severity"] is None
                    if link and is_recent and needs and opened < MAX_DETAIL_PER_VENDOR:
                        d = detail(link)
                        opened += 1
                        if d:
                            item["cves"] = item["cves"] or d.get("cves", [])
                            item["severity"] = item["severity"] or d.get("severity")
                            item["cvss"] = item["cvss"] or d.get("cvss")
                            item["detailFetched"] = True
                items.append(item)
            return items, {"url": url, "ok": True, "count": len(items)}
        except Exception as ex:  # noqa: BLE001
            last_err = f"{type(ex).__name__}: {ex}"[:300]
    return [], {"url": urls[-1], "ok": False, "error": last_err}


def main():
    try:
        old = json.load(open(OUT))
    except Exception:  # noqa: BLE001
        old = {"items": []}
    previous = {i["link"]: i for i in old.get("items", []) if i.get("link")}

    merged, sources = dict(previous), {}
    for vendor, urls in FEEDS.items():
        items, status = fetch_vendor(vendor, urls, previous)
        sources[vendor] = status
        for it in items:
            if it["link"]:
                first = previous.get(it["link"], {}).get("firstSeen")
                it["firstSeen"] = first or datetime.now(timezone.utc).isoformat()
                merged[it["link"]] = it
        print(f"{vendor}: {status}")

    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).isoformat()
    items = [i for i in merged.values() if (i.get("published") or i.get("firstSeen") or "") >= cutoff]
    items.sort(key=lambda i: i.get("published") or i.get("firstSeen") or "", reverse=True)

    new_content = {"sources": sources, "items": items}
    old_content = {"sources": old.get("sources"), "items": old.get("items")}
    if new_content == old_content:
        print("Sin cambios")
        return
    new_content["generatedAt"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(new_content, f, ensure_ascii=False, indent=1)
    print(f"Escrito {OUT}: {len(items)} avisos")


if __name__ == "__main__":
    main()
