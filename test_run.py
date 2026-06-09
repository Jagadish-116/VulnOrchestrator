import os
from core.scanner import SecurityScanner
from core.parser import NmapParser, DirsearchParser

def main():
    # Target can be an IP or a domain. 
    # 'gandalf.gcoos.org' is an authorized public testing endpoint.
    target = "testaspnet.vulnweb.com"
    all_pipeline_findings = {}
    
    print("========================================")
    print("   VULNORCHESTRATOR - COMPREHENSIVE RUN ")
    print("========================================")
    
    # Initialize the core scanner engine with our target
    orchestrator = SecurityScanner(target)
    
    # Phase 1: Trigger the Nmap Recon Scan
    gnmap_report = orchestrator.run_nmap()
    if not gnmap_report:
        print("[-] Pipeline halted: Nmap scan failed.")
        return
        
    # Phase 2: Feed Nmap raw grepable log data straight into the Parser
    print("\n[+] Extraction Engine processing Nmap logs...")
    discovered_web_targets = NmapParser.extract_web_urls(gnmap_report)
    if not discovered_web_targets:
        print("[-] Pipeline halted: No web targets discovered open.")
        return
        
    print(f"[─] Discovered {len(discovered_web_targets)} live web services:")
    for url in discovered_web_targets:
        print(f"    -> {url}")
        
    # Phase 3: Loop through all discovered web targets and auto-trigger Dirsearch
    print("\n[+] Commencing directory brute-force sequences...")
    for web_url in discovered_web_targets:
        # Run directory brute force with the unique filename configuration
        dirsearch_report = orchestrator.run_dirsearch(web_url)
        
        # Verify the report file exists before attempting to parse its JSON structure
        if dirsearch_report and os.path.exists(dirsearch_report):
            print(f"[+] Analyzing findings for {web_url}...")
            # Parse the individual JSON file
            port_findings = DirsearchParser.parse_results(dirsearch_report)
            all_pipeline_findings[web_url] = port_findings
            print(f"[─] Extracted {len(port_findings)} interesting directories/files.")
        else:
            print(f"[-] Warning: Output file missing or empty for {web_url}")

    # Phase 4: Structured Console Summary Report
    print("\n========================================")
    print("        SECURITY VULNERABILITY SUMMARY   ")
    print("========================================")
    
    total_issues = 0
    for target_url, findings in all_pipeline_findings.items():
        print(f"\nTarget: {target_url}")
        if not findings:
            print("  No notable directories exposed.")
            continue
            
        for f in findings:
            total_issues += 1
            print(f"  [{f['severity']}] Path: {f['path']} (Status: {f['status']} | Size: {f['size']})")
            
    print(f"\n[─] Pipeline processing finalized. Total assets flagged: {total_issues}")
    print("========================================")

if __name__ == "__main__":
    main()