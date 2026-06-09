from flask import Flask, render_template, jsonify
import os
import re
from core.parser import DirsearchParser

app = Flask(__name__)
OUTPUT_DIR = "outputs"

def get_scan_details():
    """
    Parses nmap_result.gnmap using clean line searches to pull 
    target domains and ports dynamically.
    """
    gnmap_path = os.path.join(OUTPUT_DIR, "nmap_result.gnmap")
    details = {"target": "N/A", "ip": "N/A", "status": "Down", "ports": []}
    
    if os.path.exists(gnmap_path):
        with open(gnmap_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                # 1. EXTRACT HOSTNAME, IP, AND INFRASTATUS
                if "Host:" in line and "Status:" not in line:
                    # Extract the IP address
                    ip_match = re.search(r"Host:\s+([0-9.]+)", line)
                    if ip_match:
                        details["ip"] = ip_match.group(1)
                        details["status"] = "Active"
                    
                    # Extract the hostname hidden inside parentheses (e.g., (sbtet.telangana.gov.in))
                    host_match = re.search(r"\(([^)]+)\)", line)
                    if host_match and host_match.group(1).strip():
                        details["target"] = host_match.group(1).strip()
                    else:
                        # Fallback if no domain name was resolved (uses raw IP as target name)
                        if details["target"] == "N/A":
                            details["target"] = details["ip"]
                    
                    # 2. EXTRACT OPEN PORTS
                    if "Ports:" in line:
                        ports_part = line.split("Ports: ")[1]
                        for port_info in ports_part.split(", "):
                            if "open" in port_info:
                                details["ports"].append(port_info.split("/")[0])
                                
    return details

@app.route("/")
def index():
    # Gather network scan details
    scan_info = get_scan_details()
    
    # Read and parse all custom fuzzer JSON outputs dynamically
    all_findings = {}
    if os.path.exists(OUTPUT_DIR):
        for filename in os.listdir(OUTPUT_DIR):
            if filename.startswith("dirsearch_") and filename.endswith(".json"):
                file_path = os.path.join(OUTPUT_DIR, filename)
                parsed_findings = DirsearchParser.parse_results(file_path)
                
                # Reconstruct original clean URL name from filename
                clean_url = filename.replace("dirsearch_", "").replace(".json", "").replace("_", ".", 3).replace("_", ":")
                clean_url = clean_url.replace("http.", "http://").replace("https.", "https://")
                
                all_findings[clean_url] = parsed_findings

    return render_template("report.html", scan_info=scan_info, findings=all_findings)

if __name__ == "__main__":
    print("[+] Launching Web UI Dashboard on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)