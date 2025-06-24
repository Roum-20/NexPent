from jinja2 import Template

def generate_html_report(vulns, output="report/report.html"):
    with open("template.html", encoding="utf-8") as f:
        template = Template(f.read())
    report = template.render(vulnerabilities=vulns)
    with open(output, "w", encoding="utf-8") as f:
        f.write(report)
