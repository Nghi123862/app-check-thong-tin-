import os
import re
import socket
from urllib.parse import urlparse
from typing import Dict, List, Tuple
import requests
from bs4 import BeautifulSoup
from .text_detector import analyze_text

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')


def _load_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    items: List[str] = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            items.append(line.lower())
    return items


def _load_blocklist() -> List[str]:
    return _load_lines(os.path.join(DATA_DIR, 'domains_blocklist.txt'))


def _load_whitelist() -> List[str]:
    return _load_lines(os.path.join(DATA_DIR, 'domains_whitelist.txt'))


BLOCKLIST = set(_load_blocklist())
WHITELIST = set(_load_whitelist())


URL_SHORTENERS = {
    'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'is.gd', 'buff.ly', 'adf.ly',
    'sh.st', 'bc.vc', 'ow.ly',
}

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.site', '.online', '.link', '.live', '.digital',
    '.biz', '.info', '.work', '.click', '.buzz', '.rest', '.gq', '.cf', '.ga', '.ml', '.tk',
    '.zip', '.mov'
}


def _domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.hostname or ''
    except Exception:
        return ''


def _resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ''


def _fetch_text(url: str, timeout: int = 8) -> Tuple[str, Dict[str, str]]:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; ContentSafety/1.0)"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        for tag in soup(['script', 'style', 'noscript']):
            tag.decompose()
        text = soup.get_text(" ", strip=True)
        meta = {"final_url": resp.url, "status": str(resp.status_code)}
        return text, meta
    except Exception as e:
        return '', {"error": str(e)}


def analyze_url(url: str) -> Dict[str, object]:
    domain = _domain_from_url(url).lower()
    in_block = domain in BLOCKLIST or any(domain.endswith('.' + d) for d in BLOCKLIST)
    in_white = domain in WHITELIST or any(domain.endswith('.' + d) for d in WHITELIST)

    resolved_ip = _resolve_ip(domain) if domain else ''

    page_text, meta = _fetch_text(url)

    indicators: List[str] = []
    if in_block:
        indicators.append(f"Tên miền nằm trong danh sách cảnh báo: {domain}")
    if in_white:
        indicators.append(f"Tên miền thuộc nguồn tin uy tín: {domain}")
    if resolved_ip:
        if resolved_ip.startswith('10.') or resolved_ip.startswith('192.168.'):
            indicators.append("Tên miền trỏ về mạng nội bộ (bất thường)")
    else:
        indicators.append("Không phân giải được DNS cho tên miền")

    # Handle unreachable/non-existent links
    unreachable = False
    if not resolved_ip:
        unreachable = True
    if 'error' in meta:
        err = meta.get('error', '').lower()
        if any(key in err for key in ['name or service not known', 'nodename nor servname', 'failed to establish a new connection', 'name_resolved', 'dns', 'not found', '404']):
            unreachable = True
            indicators.append(f"Lỗi truy cập: {meta.get('error')}")

    # Analyze text content
    text_analysis = analyze_text(page_text)
    text_risk = text_analysis.get("risk_score", 0)
    text_hits = text_analysis.get("hits", 0)

    # URL-specific risk factors
    url_risk = 0
    subdomain_count = domain.count('.')
    tld = '.' + domain.split('.')[-1] if subdomain_count > 0 else ''

    if in_block:
        url_risk += 60
    if domain in URL_SHORTENERS:
        url_risk += 25
        indicators.append("Tên miền là dịch vụ rút gọn link (rủi ro cao)")
    if tld in SUSPICIOUS_TLDS:
        url_risk += 15
        indicators.append(f"TLD đáng ngờ: {tld}")
    if subdomain_count > 3:
        url_risk += 10
        indicators.append(f"Số lượng subdomain bất thường: {subdomain_count}")
    if not page_text:
        url_risk += 10
    if in_white:
        url_risk = max(0, url_risk - 40)  # Stronger whitelist effect
    if unreachable:
        url_risk += 25  # Unreachable link => cannot verify → at least medium risk

    # Special verdict for unreachable
    if unreachable:
        return {
            "url": url, "domain": domain, "resolved_ip": resolved_ip,
            "blocklisted": in_block, "whitelisted": in_white,
            "indicators": indicators, "meta": meta,
            "risk_score": max(url_risk, 40),
            "risk_level": 'Trung bình' if url_risk < 80 else 'Cao',
            "verdict": "Liên kết không tồn tại/không đủ dữ liệu",
            "confidence": 20,
            "rationale": "Không phân giải DNS hoặc truy cập thất bại, không đủ dữ liệu xác thực",
            "text_analysis": text_analysis,
        }

    # Combine scores for a final verdict
    total_risk = url_risk + text_risk
    if total_risk >= 85 or (in_block and text_risk >= 30):
        verdict, confidence, rationale = "Thông tin giả/vi phạm", 90, f"Tên miền cảnh báo và nội dung đáng ngờ (URL risk: {url_risk}, Text risk: {text_risk})"
    elif total_risk >= 50:
        verdict, confidence, rationale = "Trung tính nhưng có rủi ro", 60, f"Có dấu hiệu rủi ro từ URL hoặc nội dung (URL risk: {url_risk}, Text risk: {text_risk})"
    else:
        verdict, confidence, rationale = "Thông tin có vẻ thật/an toàn", 80, "Ít dấu hiệu rủi ro" + (", nguồn tin uy tín" if in_white else "")

    risk_level = 'Thấp'
    if total_risk >= 80: risk_level = 'Cao'
    elif total_risk >= 40: risk_level = 'Trung bình'

    return {
        "url": url, "domain": domain, "resolved_ip": resolved_ip,
        "blocklisted": in_block, "whitelisted": in_white,
        "text_match_count": text_hits,
        "indicators": indicators, "meta": meta,
        "risk_score": total_risk, "risk_level": risk_level,
        "verdict": verdict, "confidence": confidence, "rationale": rationale,
        "text_analysis": text_analysis,
    }
