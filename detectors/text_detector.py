import os
import re
from typing import Dict, List

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')


def _load_lines(name: str) -> List[str]:
    path = os.path.join(DATA_DIR, name)
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


def _load_keywords() -> List[str]:
    return _load_lines('keywords_violation.txt')

PHRASES_WHITE = _load_lines('phrases_whitelist.txt')
PHRASES_BLACK = _load_lines('phrases_blacklist.txt')

KEYWORDS = _load_keywords()


def _get_word_count(text: str) -> int:
    return len(re.findall(r'\w+', text))


MISSPELLINGS = {
    # General typos
    "lunừa đảo": "lừa đảo", "lua đảo": "lừa đảo", "lừa đao": "lừa đảo",
    "kích độngg": "kích động", "kich động": "kích động", "kik động": "kích động",
    "bạo lựcc": "bạo lực", "bạo lwcj": "bạo lực", "bao lực": "bạo lực",
    "thù hằnn": "thù hằn", "thu hằn": "thù hằn", "thù hăn": "thù hằn",
    "khủng bô": "khủng bố", "khủngbố": "khủng bố",
    "xuyên tạcc": "xuyên tạc", "xuyen tac": "xuyên tạc",
    "phỉ bángg": "phỉ báng", "phi bang": "phỉ báng",
    # English misspellings
    "fak news": "fake news", "fakenews": "fake news",
    "scamm": "scam",
    "porrn": "porn",
    "hat speech": "hate speech", "hatespeech": "hate speech",
    "terrorr": "terror", "teror": "terror",
}


def _normalize_text(text: str) -> str:
    t = text.lower()
    for mis, cor in MISSPELLINGS.items():
        t = t.replace(mis, cor)
    return t


def _count_keyword_hits(text: str) -> int:
    t = text.lower()
    total = 0
    for kw in KEYWORDS:
        if kw and kw in t:
            total += 1
    return total


# Base suspicious patterns
SUSPICIOUS_PATTERNS = [
    re.compile(r"\b(100%|siêu|bạo|cam kết|miễn phí)\b", re.IGNORECASE),
    re.compile(r"\b(bịa đặt|xuyên tạc|kích động|thù hằn|lừa đảo)\b", re.IGNORECASE),
]

# Doomsday hoax specific cues
DOOMSDAY_PATTERNS = [
    re.compile(r"ngày\s+tận\s+thế", re.IGNORECASE),
    re.compile(r"nibiru", re.IGNORECASE),
    re.compile(r"hành\s+tinh\s+bí\s+ẩn", re.IGNORECASE),
    re.compile(r"va\s+chạm\s+trái\s+đất", re.IGNORECASE),
    re.compile(r"nasa\s+(che giấu|giấu giếm)", re.IGNORECASE),
    re.compile(r"tiên\s+tri\s+cổ\s+đại", re.IGNORECASE),
    re.compile(r"mưa\s+đỏ|ánh\s+sáng\s+tím", re.IGNORECASE),
    re.compile(r"đào\s+hầm|tích\s+trữ\s+thực\s+phẩm", re.IGNORECASE),
    re.compile(r"bùa\s+bảo\s+vệ|lá\s+bùa|năng\s+lượng\s+bảo\s+vệ", re.IGNORECASE),
]

# Scam/monetization cues
SCAM_PATTERNS = [
    re.compile(r"bán\s+(bùa|gói|khóa\s*học|thuốc|lá\s*chắn\s*năng\s*lượng)", re.IGNORECASE),
    re.compile(r"giá\s*\d+[\.,]?\d*\s*(triệu|nghìn|k|vnd|đ)", re.IGNORECASE),
]

# Astrophysics-hoax cues
ASTRO_HOAX = [
    re.compile(r"hố\s*đen\s*mini", re.IGNORECASE),
    re.compile(r"chậm\s*thời\s*gian", re.IGNORECASE),
    re.compile(r"sóng\s*hấp\s*dẫn", re.IGNORECASE),
    re.compile(r"lá\s*chắn\s*năng\s*lượng", re.IGNORECASE),
]


def _verdict_from_score(score: int, hits: int, patterns: int, doom: int, scam: int, white: int, black: int, astro: int) -> (str, int, str):
    truth_confidence = max(5, min(95, 95 - score))
    if doom >= 2 or scam >= 1 or black >= 2 or astro >= 1 or score >= 80:
        return "Thông tin giả/vi phạm", max(5, min(truth_confidence, 18)), f"Dấu hiệu ngày tận thế ({doom}), astro-hoax ({astro}), scam ({scam}), blacklist ({black}), từ khóa {hits}, mẫu {patterns}"
    if score >= 50:
        return "Trung tính nhưng có rủi ro", max(20, min(truth_confidence, 70)), f"Nhiều dấu hiệu ({hits} từ khóa, {patterns} mẫu)"
    bonus = f", cụm whitelist ({white})" if white else ""
    return "Thông tin có vẻ thật/an toàn", max(75, truth_confidence), "Không phát hiện dấu hiệu đáng kể" + bonus


def analyze_text(text: str) -> Dict[str, object]:
    if not text:
        return {"risk_level": "Không có dữ liệu", "risk_score": 0, "hits": 0, "patterns": [], "verdict": "Không đủ dữ liệu", "confidence": 0, "rationale": ""}

    normalized_text = _normalize_text(text)
    word_count = _get_word_count(normalized_text)
    hits = _count_keyword_hits(normalized_text)

    pattern_hits: List[str] = []
    for pat in SUSPICIOUS_PATTERNS:
        if pat.search(normalized_text):
            pattern_hits.append(pat.pattern)

    doom_hits = sum(1 for pat in DOOMSDAY_PATTERNS if pat.search(normalized_text))
    scam_hits = sum(1 for pat in SCAM_PATTERNS if pat.search(normalized_text))
    astro_hits = sum(1 for pat in ASTRO_HOAX if pat.search(normalized_text))

    # Add patterns that were hit to the list
    for pat in DOOMSDAY_PATTERNS + SCAM_PATTERNS + ASTRO_HOAX:
        if pat.search(normalized_text):
            pattern_hits.append(pat.pattern)

    white_hits = sum(1 for p in PHRASES_WHITE if p in normalized_text)
    black_hits = sum(1 for p in PHRASES_BLACK if p in normalized_text)

    # Risk scoring with keyword density
    density = (hits / word_count) * 100 if word_count > 0 else 0
    density_score = min(density * 20, 50)  # Cap density score

    risk_score = density_score + (len(pattern_hits) * 8) + (doom_hits * 25) + (scam_hits * 45) + (black_hits * 18) + (astro_hits * 30)
    risk_score = max(0, risk_score - white_hits * 22)

    if word_count < 10 and hits >= 1:
        risk_score += 10  # Higher risk for very short, impactful text
    if doom_hits >= 2 or black_hits >= 2 or astro_hits >= 1:
        risk_score += 25

    risk_level = 'Thấp'
    if risk_score >= 80: risk_level = 'Cao'
    elif risk_score >= 40: risk_level = 'Trung bình'

    verdict, confidence, rationale = _verdict_from_score(risk_score, hits, len(pattern_hits), doom_hits, scam_hits, white_hits, black_hits, astro_hits)

    if verdict == "Thông tin giả/vi phạm":
        risk_level = 'Cao' if (scam_hits >= 1 or doom_hits >= 1 or black_hits >= 2 or astro_hits >= 1 or risk_score >= 80) else 'Trung bình'

    return {
        "hits": hits, "word_count": word_count, "density": f"{density:.2f}%",
        "pattern_hits": pattern_hits, "doom_hits": doom_hits, "scam_hits": scam_hits,
        "astro_hits": astro_hits, "white_hits": white_hits, "black_hits": black_hits,
        "risk_score": risk_score, "risk_level": risk_level,
        "verdict": verdict, "confidence": confidence, "rationale": rationale,
    }
