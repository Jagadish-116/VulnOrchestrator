import re
import os
import json
import os

class DirsearchParser:
    @staticmethod
    def parse_results(json_file_path):
        """
        Parses a dirsearch JSON output file to extract sensitive/interesting findings.
        """
        findings = []
        if not os.path.exists(json_file_path):
            return findings

        try:
            with open(json_file_path, "r", encoding="utf-8") as file:
                data = json.load(file)
                
                # Dirsearch JSON structure contains top-level keys for URLs scanned
                for url, scan_data in data.items():
                    for entry in scan_data:
                        status = entry.get("status")
                        path = entry.get("path")
                        content_length = entry.get("content-length", 0)
                        redirect_url = entry.get("redirect", "")

                        # Filter: Focus on 200 OK, 301/302 Redirects, and 403 Forbidden
                        if status in [200, 301, 302, 403]:
                            severity = "Low" # Default severity
                            
                            # Simple rule-based logic to flag interesting targets
                            low_path = path.lower()
                            if any(x in low_path for x in [".env", ".git", "config", "backup", "db", "sql"]):
                                severity = "High"
                            elif any(x in low_path for x in ["admin", "login", "dashboard", "panel"]):
                                severity = "Medium"

                            findings.append({
                                "path": path,
                                "status": status,
                                "size": content_length,
                                "redirect": redirect_url,
                                "severity": severity
                            })
            return findings
        except Exception as e:
            print(f"[-] Error parsing Dirsearch JSON file {json_file_path}: {str(e)}")
            return []
        
class NmapParser:
    @staticmethod
    def extract_web_urls(gnmap_file_path):
        """
        Parses a .gnmap file to find hosts running web services (HTTP/HTTPS)
        and returns a list of target URLs.
        """
        web_urls = []
        
        if not os.path.exists(gnmap_file_path):
            print(f"[-] Debug Error: File does not exist at {gnmap_file_path}")
            return []

        try:
            with open(gnmap_file_path, "r", encoding="utf-8", errors="ignore") as file:
                lines = file.readlines()
                print(f"[DEBUG] Total lines read from gnmap file: {len(lines)}")
                
                for line_num, line in enumerate(lines, 1):
                    # Clean whitespaces
                    line = line.strip()
                    
                    if "Host:" in line and "Ports:" in line:
                        print(f"[DEBUG] Found target data on line {line_num}: {line[:60]}...")
                        
                        # Extract the IP address
                        ip_match = re.search(r"Host:\s+([0-9.]+)", line)
                        if not ip_match:
                            continue
                        ip = ip_match.group(1)
                        
                        # Split target data out
                        ports_data = line.split("Ports: ")[1]
                        individual_ports = ports_data.split(", ")
                        
                        for port_info in individual_ports:
                            if "open" in port_info:
                                port_details = port_info.split("/")
                                if len(port_details) < 5:
                                    continue
                                    
                                port_num = port_details[0]
                                service_name = port_details[4].lower()
                                
                                # Identify web protocols
                                if "http" in service_name or "ssl" in service_name or "https" in service_name:
                                    if "https" in service_name or port_num == "443":
                                        url = f"https://{ip}:{port_num}"
                                    else:
                                        url = f"http://{ip}:{port_num}"
                                    
                                    print(f"[DEBUG] Match Found: {url}")
                                    web_urls.append(url)
                                        
            final_urls = list(set(web_urls))
            print(f"[DEBUG] Unique web URLs extracted: {final_urls}")
            return final_urls
            
        except Exception as e:
            print(f"[-] Critical Parser Exception: {str(e)}")
            return []