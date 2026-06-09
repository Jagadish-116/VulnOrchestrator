import subprocess
import os
from core.brute import CoreBruter

class SecurityScanner:
    def __init__(self, target):
        self.target = target
        self.output_dir = "outputs"
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def run_nmap(self):
        """Executes Nmap safely on Windows with an extended processing window."""
        print(f"\n[+] Core engine initiating Nmap scan on target: {self.target}")
        output_file = os.path.join(self.output_dir, "nmap_result.gnmap")
        
        nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        if not os.path.exists(nmap_path):
            nmap_path = r"C:\Program Files\Nmap\nmap.exe"

        command_args = [nmap_path, "-F", "-sV", self.target, "-oG", output_file]
        
        try:
            process = subprocess.Popen(
                command_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            print("[*] Scan in progress... Waiting for Nmap to complete execution (Timeout: 5m).")
            
            # EXTENDED: Timeout bumped to 300 seconds to account for network version-probing overhead
            stdout, stderr = process.communicate(timeout=300)
            print("[─] Nmap process completed and closed.")
            return output_file
        except subprocess.TimeoutExpired:
            print("[-] Error: Nmap scan timed out. Forcing process termination.")
            process.kill()
            return output_file if os.path.exists(output_file) else None
        except Exception as e:
            print(f"[-] Scanner Engine Exception: {str(e)}")
            return None

    def run_dirsearch(self, target_url):
        """Bypasses broken system path commands by routing to our custom native script."""
        bruter = CoreBruter(target_url, self.output_dir)
        output_file = bruter.run()
        return output_file