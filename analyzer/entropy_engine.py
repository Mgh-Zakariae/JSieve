import math, re, jsbeautifier
from concurrent.futures import ThreadPoolExecutor, as_completed


ASSIGNMENT_REGEX = re.compile(
    r"""(?ix)
    ["']?
    (?P<key>
        api[_-]?key|
        apikey|
        apiKey|
        client[_-]?secret|
        clientSecret|
        access[_-]?token|
        accessToken|
        refresh[_-]?token|
        refreshToken|
        id[_-]?token|
        idToken|
        auth[_-]?token|
        authToken|
        secret[_-]?key|
        secretKey|
        private[_-]?key|
        privateKey|
        password|
        passwd|
        pwd|
        authorization
    )
    ["']?
    \s*[:=]\s*
    ["']
    (?P<value>[^"'\n]{12,300})
    ["']
    """
)


NOISE_SUBSTRINGS = [
    "bg-token",
    "text-token",
    "border-token",
    "ring-token",
    "shadow",
    "hover:",
    "dark:",
    "keyword.",
    "punctuation.",
    "storage.",
    "source.",
    "support.",
    "variable.",
    "entity.name",
    "\\b",
    "\\s",
    "(?",
    "\\\\",
    "csrf token error",
    "invalid token",
    "token expired",
    "author",
    "documentation",
]


def calculate_entropy(value):
    if not value:
        return 0

    frequencies = {}

    # This line counts how many times each character appears in the string.
    for char in value:
        frequencies[char] = frequencies.get(char, 0) + 1

    # value = "aabc"
    # frequencies = {
    #     "a": 2,
    #     "b": 1,
    #     "c": 1
    # }


    entropy = 0
    # Entropy = - Σ [ p(char) * log2(p(char)) ] 
    for count in frequencies.values():
        probability = count / len(value)
        entropy -= probability * math.log2(probability)

    return entropy


def get_position(content, index):
    line = content.count("\n", 0, index) + 1
    last_newline = content.rfind("\n", 0, index)

    if last_newline == -1:
        column = index + 1
    else:
        column = index - last_newline

    return line, column


def get_context(content, start, end, size=80):
    start_pos = max(0, start - size)
    end_pos = min(len(content), end + size)
    return content[start_pos:end_pos].replace("\n", " ")


def is_noise_value(value):
    value_lower = value.lower().strip()

    if len(value_lower) < 20:
        return True

    if any(noise in value_lower for noise in NOISE_SUBSTRINGS):
        return True

    if value_lower.startswith("http://") or value_lower.startswith("https://"):
        return True

    if value_lower.startswith("/"):
        return True

    if any(value_lower.endswith(ext) for ext in [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".gif"
    ]):
        return True

    if any(space in value for space in [" ", "\t", "\r", "\n"]):
        return True

    if any(symbol in value for symbol in ["<", ">", "{", "}", "$"]):
        return True

    allowed_chars = 0

    for char in value:
        if char.isalnum() or char in "_-+=/.":
            allowed_chars += 1

    allowed_ratio = allowed_chars / len(value)

    if allowed_ratio < 0.85:
        return True

    return False


def one_entropy_engine(file_info):
    findings = []

    with open(file_info["path"], "r", encoding="utf-8", errors="ignore") as file:
        js_content = file.read()
    content = jsbeautifier.beautify(js_content)

    for match in ASSIGNMENT_REGEX.finditer(content):
        key = match.group("key")
        value = match.group("value").strip()

        if is_noise_value(value):
            continue

        entropy = calculate_entropy(value)

        if entropy < 4.0:
            continue

        line, column = get_position(content, match.start())
        context = get_context(content, match.start(), match.end())

        # findings.append({
        #     "type": "High Entropy Sensitive Assignment",
        #     "keyword": key,
        #     "value": value,
        #     "entropy": round(entropy, 2),
        #     "severity": "Medium",
        #     "confidence": "Medium",
        #     "file": file_info["filename"],
        #     "url": file_info["url"],
        #     "line": line,
        #     "column": column,
        #     "engine": "entropy",
        #     "context": context
        # })
        
        findings.append({
                "type": "High Entropy Sensitive String", 
                "keyword": key,
                "value": value,
                "file": file_info["filename"],
                "url": file_info["url"],
                "engine": "entropy"
            })

    return findings


def entropy_engine(files, threads=20):
    findings = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []

        for item in files:
            futures.append(executor.submit(one_entropy_engine, item))

        for future in as_completed(futures):
            result = future.result()

            if result:
                findings.extend(result)

    return findings