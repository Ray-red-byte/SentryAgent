import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    def __init__(self, workspace_dir: Path):
        self.workspace_dir = workspace_dir
        self.reports_dir = workspace_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_pdf(self, session_id: str, scan_results: list, audit_results: dict):
        """
        Generates a PDF summary.
        audit_results format: { "file_path.py": [ {vuln_dict}, ... ] }
        """
        filename = f"sentry_report_{session_id[:8]}.pdf"
        file_path = self.reports_dir / filename
        
        c = canvas.Canvas(str(file_path), pagesize=letter)
        width, height = letter

        # --- HEADER ---
        c.setFont("Helvetica-Bold", 24)
        c.drawString(50, height - 50, "Sentry Agent Security Report")
        
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 70, f"Session ID: {session_id}")
        c.drawString(50, height - 85, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        c.setStrokeColor(colors.gray)
        c.line(50, height - 100, width - 50, height - 100)

        # --- SECTION 1: SCAN OVERVIEW ---
        y = height - 140
        c.setFont("Helvetica-Bold", 18)
        c.drawString(50, y, "1. Attack Surface Overview")
        y -= 30
        
        c.setFont("Helvetica", 12)
        total_files = len(scan_results)
        total_risks = sum(f['risk_score'] for f in scan_results)
        
        c.drawString(60, y, f"• Total Files Scanned: {total_files}")
        y -= 20
        c.drawString(60, y, f"• Cumulative Risk Score: {total_risks}")
        y -= 40

        # High Risk Files Table
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Top Risky Files:")
        y -= 25
        
        c.setFont("Helvetica", 10)
        # Sort by risk score descending
        sorted_files = sorted(scan_results, key=lambda x: x['risk_score'], reverse=True)[:10]
        
        for file in sorted_files:
            if y < 100:
                c.showPage()
                y = height - 50
            c.drawString(60, y, f"• {file['file']} (Score: {file['risk_score']})")
            y -= 15

        # --- SECTION 2: AUDIT DETAILS ---
        y -= 30
        c.setFont("Helvetica-Bold", 18)
        c.drawString(50, y, "2. Deep Audit Findings")
        y -= 30

        if not audit_results:
            c.setFont("Helvetica-Oblique", 12)
            c.drawString(50, y, "No deep audits performed in this session.")
        else:
            for file_path, vulnerabilities in audit_results.items():
                if y < 150:
                    c.showPage()
                    y = height - 50
                
                # File Header
                c.setFont("Helvetica-Bold", 12)
                c.setFillColor(colors.darkblue)
                c.drawString(50, y, f"File: {file_path}")
                c.setFillColor(colors.black)
                y -= 20
                
                # Vulnerabilities
                c.setFont("Helvetica", 10)
                if not vulnerabilities or len(vulnerabilities) == 0:
                     c.drawString(70, y, "No vulnerabilities found (Clean).")
                     y -= 20
                else:
                    for vuln in vulnerabilities:
                        # Safety check for dict vs list issues
                        if isinstance(vuln, dict):
                            severity = vuln.get('severity', 'UNKNOWN')
                            v_type = vuln.get('type', 'Issue')
                            desc = vuln.get('description', '')
                            
                            c.setFont("Helvetica-Bold", 10)
                            c.setFillColor(colors.red if severity in ['HIGH', 'CRITICAL'] else colors.black)
                            c.drawString(70, y, f"[{severity}] {v_type}")
                            c.setFillColor(colors.black)
                            y -= 15
                            
                            c.setFont("Helvetica", 9)
                            # Simple wrapping for description
                            if len(desc) > 90:
                                c.drawString(70, y, desc[:90] + "...")
                            else:
                                c.drawString(70, y, desc)
                            y -= 25
                        
                        if y < 80:
                            c.showPage()
                            y = height - 50

        c.save()
        return file_path