import os
import json
import pandas as pd


def load_json(path):
    if not os.path.exists(path):
        return []

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def json_to_html(output_dir):
    findings_path = os.path.join(output_dir, "findings.json")
    endpoints_path = os.path.join(output_dir, "endpoints.json")
    report_path = os.path.join(output_dir, "report.html")

    findings = load_json(findings_path)
    endpoints = load_json(endpoints_path)

    findings_df = pd.DataFrame(findings)
    endpoints_df = pd.DataFrame(endpoints)

    findings_table = findings_df.to_html(
        index=False,
        escape=True,
        classes="table"
    ) if not findings_df.empty else "<p>No sensitive findings found.</p>"

    endpoints_table = endpoints_df.to_html(
        index=False,
        escape=True,
        classes="table"
    ) if not endpoints_df.empty else "<p>No endpoints found.</p>"

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>JS-Secret-Finder Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #111827;
            color: #e5e7eb;
            padding: 30px;
        }}

        h1, h2 {{
            color: #38bdf8;
        }}

        .summary {{
            background: #1f2937;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
        }}

        .table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 35px;
            background: #1f2937;
            font-size: 14px;
        }}

        .table th {{
            background: #374151;
            color: #f9fafb;
            padding: 8px;
            border: 1px solid #4b5563;
        }}

        .table td {{
            padding: 8px;
            border: 1px solid #4b5563;
            vertical-align: top;
            word-break: break-word;
        }}

        .table tr:nth-child(even) {{
            background: #0f172a;
        }}
    </style>
</head>

<body>
    <h1>JS-Secret-Finder Report</h1>

    <div class="summary">
        <p><strong>Total sensitive findings:</strong> {len(findings)}</p>
        <p><strong>Total endpoints:</strong> {len(endpoints)}</p>
    </div>

    <h2>Sensitive Findings</h2>
    {findings_table}

    <h2>Endpoints</h2>
    {endpoints_table}

</body>
</html>
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return report_path

# print(json_to_html("./output/chatgpt.com"))