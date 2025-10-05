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

    # Base risk score on domain and reachability
    risk_score = 0
    indicators: List[str] = []
    if in_block:
        risk_score += 60
        indicators.append(f"Tên miền nằm trong danh sách cảnh báo: {domain}")
    if in_white:
        risk_score -= 25
        indicators.append(f"Tên miền thuộc nguồn tin uy tín: {domain}")

    # Check for suspicious TLDs
    suspicious_tlds = ['.test', '.xyz', '.info', '.top', '.loan', '.stream']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        risk_score += 40
        indicators.append(f"Tên miền sử dụng TLD có rủi ro cao: {domain.split('.')[-1]}")

    # Check for suspicious keywords in domain
    suspicious_keywords = ['fake', 'scam', 'phishing', 'malware', 'fraud', 'free-money']
    for keyword in suspicious_keywords:
        if keyword in domain:
            risk_score += 35
            indicators.append(f"Tên miền chứa từ khóa đáng ngờ: '{keyword}'")

    if not resolved_ip:
        risk_score += 15
        indicators.append("Không phân giải được DNS cho tên miền")
    if 'error' in meta:
        risk_score += 15
        indicators.append(f"Lỗi truy cập: {meta.get('error')}")

    # Analyze text content if available
    text_analysis = None
    if page_text:
        text_analysis = analyze_text(page_text)
        # Combine scores: text score is influential but capped to prevent it from solely dominating
        text_risk_component = min(text_analysis.get("risk_score", 0), 40)
        risk_score += text_risk_component
    else:
        risk_score += 10  # Penalty for no content

    risk_score = max(0, min(100, risk_score))

    # Determine verdict and rationale
    risk_level = "Thấp"
    if risk_score >= 70:
        risk_level = "Cao"
    elif risk_score >= 35:
        risk_level = "Trung bình"

    verdict = "Thông tin có vẻ thật/an toàn"
    confidence = 100 - risk_score
    rationale = "Không phát hiện dấu hiệu đáng kể."

    if risk_level == "Cao":
        verdict = "Thông tin giả/vi phạm"
        rationale = "Rủi ro cao từ tên miền hoặc nội dung."
    elif risk_level == "Trung bình":
        verdict = "Trung tính nhưng có rủi ro"
        rationale = "Một số dấu hiệu cần chú ý."

    if text_analysis:
        # Append text analysis rationale if it's significant
        if text_analysis.get("risk_score", 0) > 20:
            rationale += f" Nội dung: {text_analysis.get('rationale', '')}"

    return {
        "url": url,
        "domain": domain,
        "resolved_ip": resolved_ip,
        "blocklisted": in_block,
        "whitelisted": in_white,
        "indicators": indicators,
        "meta": meta,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "confidence": confidence,
        "rationale": rationale.strip(),
        "text_analysis_summary": text_analysis,
    }
