import requests
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

class CoreBruter:
    def __init__(self, target_url, output_dir="outputs"):
        self.target_url = target_url.rstrip("/")
        self.output_dir = output_dir
        
        # A curated list of high-interest security endpoints to test quickly
        self.wordlist = [
            "admin", "login", "config.php", "config.bak", ".env", ".git/HEAD",
            "wp-admin", "dashboard", "backup.sql", "db.sql", "backup.zip",
            "robots.txt", "assets", "api", "v1", "test", "phpinfo.php"
        ]

    def check_path(self, path):
        """Worker function to test a single URL path."""
        url = f"{self.target_url}/{path}"
        try:
            # Send standard HTTP request, allow redirects but don't follow them automatically
            response = requests.get(url, timeout=5, allow_redirects=False)
            status = response.status_code
            
            # We care about 200 OK, 301/302 Redirects, and 403 Forbidden pages
            if status in [200, 301, 302, 403]:
                return {
                    "path": f"/{path}",
                    "status": status,
                    "content-length": len(response.content),
                    "redirect": response.headers.get("Location", "")
                }
        except requests.RequestException:
            pass
        return None

    def run(self):
        print(f"[+] Starting custom web path brute-force on: {self.target_url}")
        results = []
        
        # Run 10 threads concurrently to speed up execution
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.check_path, path): path for path in self.wordlist}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    print(f"    [Found] {result['path']} (Status: {result['status']})")
                    results.append(result)

        # Structure data identically to how our parser expects it
        report_data = {self.target_url: results}
        
        safe_name = self.target_url.replace("://", "_").replace(".", "_").replace(":", "_")
        output_file = os.path.join(self.output_dir, f"dirsearch_{safe_name}.json")
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
            
        print(f"[─] Brute-force sequence finished for {self.target_url}")
        return output_file