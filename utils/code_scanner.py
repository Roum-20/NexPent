import re

def scan_file_content(content):
    warnings = []
    if re.search(r"(password|passwd|pwd)\s*=\s*['\"]", content, re.I):
        warnings.append("Hardcoded password found.")
    if "eval(" in content or "exec(" in content:
        warnings.append("Use of dangerous functions found.")
    if "select" in content.lower() and "'" in content:
        warnings.append("Possible raw SQL query found.")
    return warnings
