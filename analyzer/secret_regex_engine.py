# import re, jsbeautifier
# from concurrent.futures import ThreadPoolExecutor, as_completed

# SECRET_PATTERNS = [
#     {
#         "name": "AWS Access Key ID",
#         "regex": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
#         "severity": "High",
#         "confidence": "High",
#         "value_group": 0
#     },
#     {
#         "name": "Google API Key",
#         "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b",
#         "severity": "Medium",
#         "confidence": "Medium",
#         "value_group": 0
#     },
#     {
#         "name": "Stripe Secret Key",
#         "regex": r"\bsk_(?:live|test)_[0-9a-zA-Z]{20,}\b",
#         "severity": "Critical",
#         "confidence": "High",
#         "value_group": 0
#     },
#     {
#         "name": "Stripe Publishable Key",
#         "regex": r"\bpk_(?:live|test)_[0-9a-zA-Z]{20,}\b",
#         "severity": "Low",
#         "confidence": "High",
#         "value_group": 0
#     },
#     {
#         "name": "GitHub Token",
#         "regex": r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b",
#         "severity": "High",
#         "confidence": "High",
#         "value_group": 0
#     },
#     {
#         "name": "Slack Token",
#         "regex": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
#         "severity": "High",
#         "confidence": "High",
#         "value_group": 0
#     },
#     {
#         "name": "JWT Token",
#         "regex": r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
#         "severity": "Medium",
#         "confidence": "Medium",
#         "value_group": 0
#     },
#     {
#         "name": "Private Key Block",
#         "regex": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
#         "severity": "Critical",
#         "confidence": "High",
#         "value_group": 0
#     },
#     {
#         "name": "Generic Secret Assignment",
#         "regex": r"""(?i)\b(api[_-]?key|apikey|secret|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|pwd|authorization|bearer)\b\s*[:=]\s*["']([^"'\n]{8,})["']""",
#         "severity": "Medium",
#         "confidence": "Medium",
#         "value_group": 2
#     }
# ]

# def one_detect_regex_secrets(file_info):
#     findings = []
    
#     with open(file_info['path'] , 'r', encoding="utf-8") as file:
#         js_content = file.read()
#     content = jsbeautifier.beautify(js_content)
    
#     for pattern in SECRET_PATTERNS:
#         regex = re.compile(pattern['regex'])
#         value_group = pattern.get('value_group', 0)

#         for match in re.finditer(regex, content):
#             if value_group == 0:
#                 value = match.group(0)
#             else:
#                 value = match.group(value_group)
                
#             findings.append({
#                     'type': pattern['name'],
#                     'keyword': match.group(0).split('=')[0],
#                     'value': value,
#                     'file': file_info['filename'],
#                     'url': file_info['url'],
#                     'engine': "regex"
#             })
                    
#     return findings


# def detect_regex_secrets(files, threads=20):
#     findings = []

#     with ThreadPoolExecutor(max_workers=threads) as executor:
#         futures = []

#         for item in files:
#             futures.append(executor.submit(one_detect_regex_secrets, item))

#         for future in as_completed(futures):
#             result = future.result()

#             if result:
#                 findings.extend(result)

#     return findings


# info = {
#     "url": "",
#     "path": "/tmp/js_files_mcdonalds.com/WidgetUtil_8b0591f27ae75b189775f36367372e8f.js",
#     "filename": "WidgetUtil_8b0591f27ae75b189775f36367372e8f.js"
# }

# print(detect_regex_secrets(info)) 



import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from math import log2


SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "regex": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "severity": "High",
        "confidence": "High",
        "value_group": 0,
        "keyword_group": None,
        "flags": 0,
    },
    {
        "name": "Google API Key",
        "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "severity": "Medium",
        "confidence": "Medium",
        "value_group": 0,
        "keyword_group": None,
        "flags": 0,
    },
    {
        "name": "Stripe Secret Key",
        "regex": r"\bsk_(?:live|test)_[0-9a-zA-Z]{20,}\b",
        "severity": "Critical",
        "confidence": "High",
        "value_group": 0,
        "keyword_group": None,
        "flags": 0,
    },
    {
        "name": "Stripe Publishable Key",
        "regex": r"\bpk_(?:live|test)_[0-9a-zA-Z]{20,}\b",
        "severity": "Low",
        "confidence": "High",
        "value_group": 0,
        "keyword_group": None,
        "flags": 0,
    },
    {
        "name": "GitHub Token",
        "regex": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b",
        "severity": "High",
        "confidence": "High",
        "value_group": 0,
        "keyword_group": None,
        "flags": 0,
    },
    {
        "name": "Slack Token",
        "regex": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "severity": "High",
        "confidence": "High",
        "value_group": 0,
        "keyword_group": None,
        "flags": 0,
    },
    {
        "name": "JWT Token",
        "regex": r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
        "severity": "Medium",
        "confidence": "Medium",
        "value_group": 0,
        "keyword_group": None,
        "flags": 0,
    },
    {
        "name": "Full Private Key Block",
        "regex": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{50,}?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": "Critical",
        "confidence": "High",
        "value_group": 0,
        "keyword_group": None,
        "flags": 0,
    },
    {
        "name": "Generic Secret Assignment",
        "regex": r"""
            (?ix)
            \b(
                api[_-]?key|apikey|apiKey|
                secret|client[_-]?secret|clientSecret|
                token|authToken|accessToken|refreshToken|
                access[_-]?token|refresh[_-]?token|
                password|passwd|pwd|
                authorization|bearer
            )\b
            \s*[:=]\s*
            ([`'"])
            ([^`'"\r\n]{8,})
            \2
        """,
        "severity": "Medium",
        "confidence": "Medium",
        "value_group": 3,
        "keyword_group": 1,
        "flags": re.VERBOSE | re.IGNORECASE,
    },
]


COMPILED_PATTERNS = [
    {**pattern, "compiled": re.compile(pattern["regex"], pattern.get("flags", 0))}
    for pattern in SECRET_PATTERNS
]


FALSE_POSITIVE_VALUES = {
    "your_api_key",
    "your-api-key",
    "api_key_here",
    "changeme",
    "change_me",
    "example",
    "undefined",
    "null",
    "false",
    "true",
}


def shannon_entropy(value):
    if not value:
        return 0

    freq = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0
    length = len(value)

    for count in freq.values():
        p = count / length
        entropy -= p * log2(p)

    return entropy


def is_false_positive(value, finding_type):
    value_clean = value.strip().lower()

    if value_clean in FALSE_POSITIVE_VALUES:
        return True

    if "${" in value:
        return True

    if "<" in value or ">" in value:
        return True

    if finding_type == "Generic Secret Assignment":
        if len(value) < 12:
            return True

        if shannon_entropy(value) < 3.0:
            return True

    return False


def get_snippet(content, start, end, window=80):
    left = max(0, start - window)
    right = min(len(content), end + window)
    snippet = content[left:right]
    return snippet.replace("\n", "\\n").replace("\r", "\\r")


def one_detect_regex_secrets(file_info):
    findings = []

    path = Path(file_info["path"])

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as error:
        return [{
            "type": "Read Error",
            "error": str(error),
            "file": file_info.get("filename"),
            "url": file_info.get("url"),
            "engine": "regex"
        }]

    for pattern in COMPILED_PATTERNS:
        regex = pattern["compiled"]
        value_group = pattern.get("value_group", 0)
        keyword_group = pattern.get("keyword_group")

        for match in regex.finditer(content):
            value = match.group(value_group) if value_group else match.group(0)
            keyword = match.group(keyword_group) if keyword_group else pattern["name"]

            if is_false_positive(value, pattern["name"]):
                continue

            findings.append({
                "type": pattern["name"],
                "keyword": keyword,
                "value": value,
                "file": file_info.get("filename"),
                "url": file_info.get("url"),
                # "line": get_line_number(content, match.start()),
                # "snippet": get_snippet(content, match.start(), match.end()),
                "engine": "regex"
            })
            
            # findings.append({
            #         'type': pattern['name'],
            #         'keyword': match.group(0).split('=')[0],
            #         'value': value,
            #         'file': file_info['filename'],
            #         'url': file_info['url'],
            #         'engine': "regex"
            # })

    return findings


def deduplicate_findings(findings):
    seen = set()
    unique = []

    for finding in findings:
        key = (
            finding.get("type"),
            finding.get("value"),
            finding.get("file"),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

    return unique


def detect_regex_secrets(files, threads=20):
    findings = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_file = {
            executor.submit(one_detect_regex_secrets, item): item
            for item in files
        }

        for future in as_completed(future_to_file):
            try:
                result = future.result()
                if result:
                    findings.extend(result)
            except Exception as error:
                continue
    return deduplicate_findings(findings)