from fpdf import FPDF
import datetime
from typing import List, Dict

class SecurityReport(FPDF):
    def header(self):
        # 로고나 헤더 타이틀 (A.I.R. Platform)
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'A.I.R. Platform - Vulnerability Scan Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        # 페이지 번호
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 10, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, body)
        self.ln()

    def add_vulnerability(self, vuln: Dict):
        # 취약점 타이틀 (CVE ID + Severity)
        title = f"[{vuln.get('severity', 'UNKNOWN').upper()}] {vuln.get('cve_id', 'N/A')}"
        self.chapter_title(title)

        # 상세 내용
        self.set_font('Arial', 'B', 10)
        self.cell(40, 10, 'Target URL:', 0, 0)
        self.set_font('Arial', '', 10)
        self.cell(0, 10, vuln.get('target_url', 'N/A'), 0, 1)

        self.set_font('Arial', 'B', 10)
        self.cell(40, 10, 'Description:', 0, 1)
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, vuln.get('description', 'No description provided.').strip())
        self.ln(2)

        # 기술적 세부사항 (Technical Evidence)
        self.set_font('Arial', 'B', 10)
        self.cell(40, 10, 'Technical Evidence (Payload):', 0, 1)
        self.set_font('Courier', '', 9)  # 고정폭 폰트 사용 (코드 가독성)
        self.set_fill_color(240, 240, 240)
        
        # Payload가 너무 길 경우를 대비해 Multi-cell 사용
        payload = vuln.get('attack_pattern', 'N/A')
        self.multi_cell(0, 5, payload, 1, 'L', True)
        self.ln(5)

        # 조치 방안
        self.set_font('Arial', 'B', 10)
        self.cell(40, 10, 'Remediation:', 0, 1)
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, vuln.get('remediation', 'N/A').strip())
        self.ln(10)
        self.line(10, self.get_y(), 200, self.get_y()) # 구분선
        self.ln(10)

def generate_pdf_report(scan_results: List[Dict], filename="AIR_Scan_Report.pdf"):
    pdf = SecurityReport()
    pdf.add_page()
    
    # 보고서 메타데이터
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, f'Generated Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
    pdf.cell(0, 10, f'Total Vulnerabilities: {len(scan_results)}', 0, 1)
    pdf.ln(10)

    for vuln in scan_results:
        pdf.add_vulnerability(vuln)

    pdf.output(filename)
    return filename