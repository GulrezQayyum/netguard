# core/reporter.py
from fpdf import FPDF
from datetime import datetime
import os

def generate_report(alert: dict, remediation: dict, block_result: dict | None) -> str:
    """Generate a PDF incident report and return the file path."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Header
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 12, "NetGuard — Incident Report", ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(6)

    # Severity badge
    severity = remediation.get("severity", "low")
    colors = {"high": (220, 50, 50), "medium": (220, 150, 0), "low": (30, 160, 100)}
    r, g, b = colors.get(severity, (100, 100, 100))
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(40, 8, f"  {severity.upper()}  ", fill=True, ln=True)
    pdf.ln(4)

    # Incident summary
    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, remediation.get("title", "Incident"), ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 6, remediation.get("what_happened", ""))
    pdf.ln(4)

    # Alert details
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Alert Details", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for key, val in alert.items():
        pdf.cell(0, 6, f"  {key}: {val}", ln=True)
    pdf.ln(4)

    # Remediation steps
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Recommended Actions", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for i, step in enumerate(remediation.get("steps", []), 1):
        pdf.multi_cell(0, 6, f"  {i}. {step}")
    pdf.ln(4)

    # Block result
    if block_result:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Automated Response", ln=True)
        pdf.set_font("Helvetica", "", 10)
        status = "SUCCESS" if block_result["success"] else "FAILED"
        pdf.cell(0, 6, f"  IP Block ({status}): {block_result['ip']}", ln=True)
        pdf.cell(0, 6, f"  {block_result['message']}", ln=True)

    # Save
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    return filename