from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

def export_pdf_from_vulns(vulns, pdf_path="report/report.pdf"):
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)

    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, height - 72, "🛡️NexPent Vulnerability Report")

    c.setFont("Helvetica", 12)
    y = height - 100

    if not vulns:
        c.drawString(72, y, "No vulnerabilities found.")
    else:
        for vuln in vulns:
            if y < 72:
                c.showPage()
                y = height - 72
                c.setFont("Helvetica", 12)
            c.drawString(72, y, f"- {vuln}")
            y -= 20

    c.save()
