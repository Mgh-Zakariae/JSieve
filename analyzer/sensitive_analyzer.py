from entropy_engine import entropy_engine
from secret_regex_engine import detect_regex_secrets


def analyzer(files_info, threads=20): 
    all_findings = []

    # Process all files with threads using entropy engine
    entropy_findings = entropy_engine(files_info, threads=threads)
    
    # Process all files with threads using regex engine
    regex_findings = detect_regex_secrets(files_info, threads=threads)

    all_findings.extend(regex_findings)
    all_findings.extend(entropy_findings)

    return all_findings


# files = [{'path': '/home/oxmg/web-vuln-toolkit/JS-Secret-Finder/js_test_lab/js_test_lab/checkout.bundle.js', 'filename': 'checkout.bundle.js', 'url': 'local-test://checkout.bundle.js', 'type': 'javascript'}, {'path': '/home/oxmg/web-vuln-toolkit/JS-Secret-Finder/js_test_lab/js_test_lab/api.client.js', 'filename': 'api.client.js', 'url': 'local-test://api.client.js', 'type': 'javascript'}, {'path': '/home/oxmg/web-vuln-toolkit/JS-Secret-Finder/js_test_lab/js_test_lab/auth.bundle.js', 'filename': 'auth.bundle.js', 'url': 'local-test://auth.bundle.js', 'type': 'javascript'}, {'path': '/home/oxmg/web-vuln-toolkit/JS-Secret-Finder/js_test_lab/js_test_lab/dashboard.routes.js', 'filename': 'dashboard.routes.js', 'url': 'local-test://dashboard.routes.js', 'type': 'javascript'}, {'path': '/home/oxmg/web-vuln-toolkit/JS-Secret-Finder/js_test_lab/js_test_lab/noise.vendor.js', 'filename': 'noise.vendor.js', 'url': 'local-test://noise.vendor.js', 'type': 'javascript'}]




# import json
# print(json.dumps(analyzer(files), indent=4))