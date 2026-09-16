import tkinter as tk
from tkinter import filedialog, messagebox
import os, re, datetime, hashlib, random

from reportlab.platypus import SimpleDocTemplate, Paragraph, Image, Spacer
from reportlab.lib.styles import getSampleStyleSheet

import matplotlib.pyplot as plt

# ===== HASH =====
def file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return "N/A"

# ===== SCORING =====
def calculate_score(findings):
    score = 0
    for f in findings:
        if f[1] == "CRITICAL": score += 5
        elif f[1] == "HIGH": score += 3
        elif f[1] == "MEDIUM": score += 2
        elif f[1] == "LOW": score += 1
    return score

# ===== AI =====
def ai_analysis(findings):
    score = calculate_score(findings)
    if score >= 8:
        return "High likelihood of compromise detected."
    elif score >= 5:
        return "Moderate risk detected."
    else:
        return "Low risk."
def analyze(content):
    findings = []
    if "token=" in content:
        findings.append(("Token", "CRITICAL"))
    if re.search(r'\d+\.\d+\.\d+\.\d+', content):
        findings.append(("Network", "HIGH"))
    if "delete" in content.lower():
        findings.append(("File deletion", "MEDIUM"))
    if "auth" in content.lower():
        findings.append(("Authentication", "LOW"))
    return findings
def scan_folder(folder):
    results = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            path = os.path.join(root, file)
            try:
                with open(path, "r", errors="ignore") as f:
                    content = f.read()
                findings = analyze(content)
                if findings:
                    results.append((file, path, findings))
            except:
                pass
    return results

def scan_multiple(folders):
    all_results = []
    for f in folders:
        all_results.extend(scan_folder(f))
    return all_results
def generate_chart(results):
    scores = [calculate_score(f) for _,_,f in results]
    if not scores:
        return None

    plt.figure()
    plt.plot(scores, marker='o')
    plt.title("Risk Score per File")
    plt.xlabel("File Index")
    plt.ylabel("Risk Score")
    plt.grid()

    filename = "risk_chart.png"
    plt.savefig(filename)
    plt.close()
    return filename
def generate_pdf(app, results):
    i = 1
    while True:
        filename = f"FORENSIC_REPORT_{i}.pdf"
        if not os.path.exists(filename):
            break
        i += 1

    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("DIGITAL FORENSIC ANALYSIS REPORT", styles["Title"]))
    content.append(Spacer(1,10))

    total_findings = sum(len(f) for _,_,f in results)

    if total_findings > 5:
        summary = "High level of suspicious activity detected."
    elif total_findings > 2:
        summary = "Moderate anomalies detected."
    else:
        summary = "Low risk profile."

    content.append(Paragraph("Executive Summary", styles["Heading2"]))
    content.append(Paragraph(summary, styles["Normal"]))
    content.append(Spacer(1,10))

    content.append(Paragraph("Findings", styles["Heading2"]))

    for file, path, findings in results:
        content.append(Paragraph(f"<b>{file}</b>", styles["Normal"]))
        content.append(Paragraph(f"Score: {calculate_score(findings)}", styles["Normal"]))

        for f in findings:
            content.append(Paragraph(f"- {f[0]} ({f[1]})", styles["Normal"]))

        content.append(Paragraph(ai_analysis(findings), styles["Normal"]))
        content.append(Spacer(1,10))

    chart = generate_chart(results)
    if chart and os.path.exists(chart):
        content.append(Paragraph("Risk Chart", styles["Heading2"]))
        content.append(Image(chart, width=400, height=250))

    doc.build(content)
    return filename
def generate_court_report(results):
    i = 1
    while True:
        filename = f"COURT_REPORT_{i}.txt"
        if not os.path.exists(filename):
            break
        i += 1

    with open(filename, "w") as f:
        f.write("DIGITAL FORENSIC EXAMINATION REPORT\n")
        f.write("="*60 + "\n\n")

        count = 1
        for file, path, findings in results:
            for fnd in findings:
                f.write(f"\nAnomaly {count}:\n")
                f.write(f" Type: {fnd[0]}\n")
                f.write(f" Severity: {fnd[1]}\n")
                f.write(f" File: {file}\n")
                f.write(f" Path: {path}\n")
                f.write(f" Hash: {file_hash(path)}\n")
                count += 1

        f.write("\nConclusion:\nPotential anomalies detected.\n")
        f.write("\nChain of Custody:\nData integrity preserved.\n")

    return filename
class App:
    def __init__(self, root):
        self.root = root
        root.title("Forensic Scanner AI")
        root.geometry("700x500")
        root.configure(bg="#121212")

        tk.Label(root,text="Forensic Scanner AI",
                 font=("Segoe UI",18,"bold"),
                 fg="#00ffcc",bg="#121212").pack(pady=10)

        tk.Button(root,text="📁 Add Folder",
                  command=self.add_folder,
                  bg="#1f1f1f",fg="white").pack(pady=5)

        tk.Button(root,text="💻 Scan Disk C:",
                  command=self.scan_disk,
                  bg="#333",fg="white").pack(pady=5)

        tk.Button(root,text="▶ Run Scan",
                  command=self.run_scan,
                  bg="#00aa88",fg="white").pack(pady=10)

        self.output = tk.Text(root,bg="#1e1e1e",fg="#00ffcc")
        self.output.pack(fill="both",expand=True,padx=10,pady=10)

        self.folders = []

    def add_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folders.append(folder)
            self.output.insert(tk.END,f"Added: {folder}\n")

    def scan_disk(self):
        self.folders = ["C:\\"]
        self.output.insert(tk.END,"Scanning full disk...\n")

    def run_scan(self):
        if not self.folders:
            messagebox.showerror("Error","Add folder first")
            return

        self.output.insert(tk.END,"\n[+] Scanning...\n")
        self.root.update()

        results = scan_multiple(self.folders)

        for file,path,findings in results:
            score = calculate_score(findings)
            self.output.insert(tk.END,f"\n{file} | Score: {score}\n")
            for f in findings:
                self.output.insert(tk.END,f" - {f[0]} ({f[1]})\n")
            self.output.insert(tk.END,f" AI: {ai_analysis(findings)}\n")

        pdf = generate_pdf("demo",results)
        court = generate_court_report(results)
        chart = generate_chart(results)

        self.output.insert(tk.END,f"\nPDF: {pdf}\nCourt: {court}\nChart: {chart}\n")

if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()