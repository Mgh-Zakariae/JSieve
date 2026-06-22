import requests, re, jsbeautifier, os, hashlib
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


def extract_endpoints(js_content):
    patterns = [
        # API paths
        r'["\'`](/api/[^\s"\'`]+)["\'`]',
        r'["\'`](/v\d+/[^\s"\'`]+)["\'`]',
        r'["\'`](/(?:api|v\d+|rest|graphql)(?:/[^\s"\'`\)]+)?)["\'`]',
        
        # Full URLs
        r'["\'`]((?:https?|wss?)://[^\s"\'`]+)["\'`]',
        
        # fetch / axios / XHR calls
        r'fetch\s*\(\s*["\'`]([^"\'`]+)["\'`]',
        r'axios\.[a-z]+\s*\(\s*["\'`]([^"\'`]+)["\'`]',
        r'\.(?:get|post|put|delete|patch)\s*\(\s*["\'`]([^"\'`]+)["\'`]',
        r'\.open\s*\(\s*["\'`][A-Z]+["\'`]\s*,\s*["\'`]([^"\'`]+)["\'`]',
        
        # Template literals with base URL
        r'`\$\{[^}]+\}(/[^`]+)`',
        
        # Common variable names
        r'(?:url|endpoint|path|route|api)\s*[:=]\s*["\'`]([^"\'`]+)["\'`]',
        
        # General relative paths
        r'["\'`](/[a-zA-Z0-9_\-/]+)["\'`]',
    ]
    
    endpoints = set()
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)

        for match in matches:
            if isinstance(match, tuple):
                match = match[0]

            endpoints.add(match.strip())
            
    return endpoints


def filter_endpoints(endpoints):
    filtered = set()
    
    exclude_extensions = {
        '.js', '.css', '.png', '.jpg', '.jpeg', '.svg',
        '.ico', '.woff', '.woff2', '.ttf', '.map', '.gif',
        '.mp4', '.webm', '.pdf', '.zip'
    }

    exclude_keywords = {
        'localhost',
        'example.com',
        'bg-token',
        'text-token',
        'border-token',
        'keyword.',
        'punctuation.',
        'storage.',
        'source.',
        'support.',
        'variable.',
        '\\b',
        '\\s',
        '(?',
    }
    
    useful_keywords = {
        'api',
        'auth',
        'login',
        'logout',
        'token',
        'user',
        'users',
        'profile',
        'account',
        'admin',
        'internal',
        'debug',
        'upload',
        'download',
        'export',
        'import',
        'graphql',
        'webhook',
        'callback',
        'session',
        'oauth',
        'config',
        'settings'
    }

    for endp in endpoints:
        endp = endp.strip()

        if not endp:
            continue

        lower = endp.lower()
        clean = lower.split("?")[0].split("#")[0]

        if any(clean.endswith(ext) for ext in exclude_extensions):
            continue

        if any(keyw in lower for keyw in exclude_keywords):
            continue

        if len(endp) < 2 or len(endp) > 200:
            continue

        if " " in endp:
            continue  

        # Full URLs are accepted if not static assets
        if lower.startswith(("http://", "https://", "ws://", "wss://")):
            filtered.add(endp)
            continue

        # Relative endpoints must start with /
        if not endp.startswith("/"):
            continue
        
        # Ignore protocol-relative URLs
        if endp.startswith("//"):
            continue

        # Keep API-like paths directly
        if lower.startswith(("/api/", "/v1/", "/v2/", "/v3/", "/graphql")):
            filtered.add(endp)
            continue

        # General paths are kept only if useful
        if any(word in lower for word in useful_keywords):
            filtered.add(endp)

    return filtered


def is_valid(endpoint):
    if len(endpoint) < 2 or len(endpoint) > 200:
        return False

    if re.search(r'\.(png|jpg|jpeg|css|ico|woff|woff2|svg|js|map|gif|pdf|zip)(\?|#|$)', endpoint, re.I):
        return False

    if endpoint.startswith("//"):
        return False

    return endpoint.startswith('/') or endpoint.startswith(('http://', 'https://', 'ws://', 'wss://'))


def one_endpointExtractor(js_info):
    with open(js_info['path'], 'r', encoding="utf-8", errors="ignore") as file:
        js_content = file.read()

    # Optional. Beautifier can slow the tool, but it can help regex extraction.
    js_content = jsbeautifier.beautify(js_content)
    
    endpoints = extract_endpoints(js_content)
    endpoints = filter_endpoints(endpoints)

    results = []
        
    for endp in endpoints:
        if is_valid(endp):
            results.append({
                "type": "Endpoint",
                "endpoint": endp,
                "file": js_info["filename"],
                "url": js_info["url"],
                "engine": "endpoint_extractor"
            })

    return results


def endpointExtractor(files, threads=20):
    endpoints = []

    with ThreadPoolExecutor(max_workers=int(threads)) as executor:
        futures = []

        for item in files:
            futures.append(executor.submit(one_endpointExtractor, item))
                
        for future in as_completed(futures):
            result = future.result()

            if result:
                endpoints.extend(result)

    # global deduplication
    endpoints = list({
        f"{item['endpoint']}|{item['file']}": item
        for item in endpoints
    }.values())

    return endpoints


# files = [
#   {
#     "path": "/tmp/js_files_chatgpt.com/e802befe_auth.enroll_mfa-hpepy3zj.js",
#     "filename": "e802befe_auth.enroll_mfa-hpepy3zj.js",
#     "url": "https://chatgpt.com/cdn/assets/e802befe_auth.enroll_mfa-hpepy3zj.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e7796cca_codex.cloud.failwhale-i9kz91qu.js",
#     "filename": "e7796cca_codex.cloud.failwhale-i9kz91qu.js",
#     "url": "https://chatgpt.com/cdn/assets/e7796cca_codex.cloud.failwhale-i9kz91qu.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e77b88b5_agents_.studio._b.edit._gptId.memory._index-otr6xvqy.js",
#     "filename": "e77b88b5_agents_.studio._b.edit._gptId.memory._index-otr6xvqy.js",
#     "url": "https://chatgpt.com/cdn/assets/e77b88b5_agents_.studio._b.edit._gptId.memory._index-otr6xvqy.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e7b3c758_checkout._entity._checkoutId-gtzhcdyl.js",
#     "filename": "e7b3c758_checkout._entity._checkoutId-gtzhcdyl.js",
#     "url": "https://chatgpt.com/cdn/assets/e7b3c758_checkout._entity._checkoutId-gtzhcdyl.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e945a0d7_codex.settings.analytics-gsyzwfkl.js",
#     "filename": "e945a0d7_codex.settings.analytics-gsyzwfkl.js",
#     "url": "https://chatgpt.com/cdn/assets/e945a0d7_codex.settings.analytics-gsyzwfkl.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e59871f1_0d64c7f8-g1yad4ejm0e0xt9m.js",
#     "filename": "e59871f1_0d64c7f8-g1yad4ejm0e0xt9m.js",
#     "url": "https://chatgpt.com/cdn/assets/e59871f1_0d64c7f8-g1yad4ejm0e0xt9m.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5a46c8f-e5poxkl492r9tgqu.js",
#     "filename": "e5a46c8f-e5poxkl492r9tgqu.js",
#     "url": "https://chatgpt.com/cdn/assets/e5a46c8f-e5poxkl492r9tgqu.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5aef47b-ieehx0fc2l4zl09g.js",
#     "filename": "e5aef47b-ieehx0fc2l4zl09g.js",
#     "url": "https://chatgpt.com/cdn/assets/e5aef47b-ieehx0fc2l4zl09g.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5bcc1d2_8f23643e-n76mq3fnxosj9pc3.js",
#     "filename": "e5bcc1d2_8f23643e-n76mq3fnxosj9pc3.js",
#     "url": "https://chatgpt.com/cdn/assets/e5bcc1d2_8f23643e-n76mq3fnxosj9pc3.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5becf5f-by467n391zmqu0ck.js",
#     "filename": "e5becf5f-by467n391zmqu0ck.js",
#     "url": "https://chatgpt.com/cdn/assets/e5becf5f-by467n391zmqu0ck.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5d04313_apps._name._id.connect-bvt7kacm.js",
#     "filename": "e5d04313_apps._name._id.connect-bvt7kacm.js",
#     "url": "https://chatgpt.com/cdn/assets/e5d04313_apps._name._id.connect-bvt7kacm.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5d54aa7-ogqw1oy8tah0yvt3.js",
#     "filename": "e5d54aa7-ogqw1oy8tah0yvt3.js",
#     "url": "https://chatgpt.com/cdn/assets/e5d54aa7-ogqw1oy8tah0yvt3.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5e23956-djpqm1xm8sy5rslo.js",
#     "filename": "e5e23956-djpqm1xm8sy5rslo.js",
#     "url": "https://chatgpt.com/cdn/assets/e5e23956-djpqm1xm8sy5rslo.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5f1e212-gf0fkvpqb77eqv7g.js",
#     "filename": "e5f1e212-gf0fkvpqb77eqv7g.js",
#     "url": "https://chatgpt.com/cdn/assets/e5f1e212-gf0fkvpqb77eqv7g.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5f1e212-knbdykxwuv2c8ivd.js",
#     "filename": "e5f1e212-knbdykxwuv2c8ivd.js",
#     "url": "https://chatgpt.com/cdn/assets/e5f1e212-knbdykxwuv2c8ivd.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5f2872f-fbm417kt3wtkxijw.js",
#     "filename": "e5f2872f-fbm417kt3wtkxijw.js",
#     "url": "https://chatgpt.com/cdn/assets/e5f2872f-fbm417kt3wtkxijw.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e5f2872f-nqy3rkrkdx5m7rc1.js",
#     "filename": "e5f2872f-nqy3rkrkdx5m7rc1.js",
#     "url": "https://chatgpt.com/cdn/assets/e5f2872f-nqy3rkrkdx5m7rc1.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e6089cb0_codex.downgrade._planType-l9ph4hjr.js",
#     "filename": "e6089cb0_codex.downgrade._planType-l9ph4hjr.js",
#     "url": "https://chatgpt.com/cdn/assets/e6089cb0_codex.downgrade._planType-l9ph4hjr.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e60aec0d_aa7d8353-x88q3d7lb6fcr75c.js",
#     "filename": "e60aec0d_aa7d8353-x88q3d7lb6fcr75c.js",
#     "url": "https://chatgpt.com/cdn/assets/e60aec0d_aa7d8353-x88q3d7lb6fcr75c.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e60f01a5-kmip6pxypf5c6ht0.js",
#     "filename": "e60f01a5-kmip6pxypf5c6ht0.js",
#     "url": "https://chatgpt.com/cdn/assets/e60f01a5-kmip6pxypf5c6ht0.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e6123106-jow812xwonp0rgaq.js",
#     "filename": "e6123106-jow812xwonp0rgaq.js",
#     "url": "https://chatgpt.com/cdn/assets/e6123106-jow812xwonp0rgaq.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e6124987_e07eb098-msqot0cj6xnxvcl0.js",
#     "filename": "e6124987_e07eb098-msqot0cj6xnxvcl0.js",
#     "url": "https://chatgpt.com/cdn/assets/e6124987_e07eb098-msqot0cj6xnxvcl0.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e638df80_bda065e7-05y8z6tiip5zdt2m.js",
#     "filename": "e638df80_bda065e7-05y8z6tiip5zdt2m.js",
#     "url": "https://chatgpt.com/cdn/assets/e638df80_bda065e7-05y8z6tiip5zdt2m.js",
#     "type": "javascript"
#   },
#   {
#     "path": "/tmp/js_files_chatgpt.com/e645842c_944cfef8-mjmlk9nypi48y14x.js",
#     "filename": "e645842c_944cfef8-mjmlk9nypi48y14x.js",
#     "url": "https://chatgpt.com/cdn/assets/e645842c_944cfef8-mjmlk9nypi48y14x.js",
#     "type": "javascript"
#   }
# ]

# endp = endpointExtractor(files)

# import json

# print(json.dumps(endp, indent=4))






