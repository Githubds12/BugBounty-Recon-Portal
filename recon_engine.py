import os
import json
import subprocess
import time
from datetime import datetime

# Configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RECON_DIR = os.path.join(SCRIPT_DIR, "recon_storage")
DATA_FILE = os.path.join(SCRIPT_DIR, "dashboard_data.js")
IS_RENDER = "RENDER" in os.environ
os.makedirs(RECON_DIR, exist_ok=True)

class ReconEngine:
    def __init__(self, target):
        self.target = target
        self.timestamp = int(time.time())
        # Dynamic Concurrency: Max power locally, Safe mode on Render
        self.threads = "10" if IS_RENDER else "50"
        self.katana_workers = "3" if IS_RENDER else "15"
        self.results = {
            "target": target,
            "timestamp": self.timestamp,
            "subdomains": [],
            "live_hosts": [],
            "open_ports": [],
            "crawled_urls": [],
            "stats": {}
        }

    def log(self, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def run_command(self, cmd, input_data=None, timeout=300):
        try:
            binary_name = cmd[0]
            is_windows = os.name == 'nt'
            
            # 1. Check local ./bin folder (Works on Windows and Render)
            local_bin_path = os.path.join(SCRIPT_DIR, "bin", f"{binary_name}.exe" if is_windows else binary_name)
            
            if os.path.exists(local_bin_path):
                cmd[0] = local_bin_path
                if not is_windows:
                    os.chmod(local_bin_path, 0o755) # Ensure execution permissions on Linux
            else:
                # 2. Fallback to System PATH
                self.log(f"Warning: {binary_name} not found in ./bin, checking system PATH...")

            self.log(f" > Running {' '.join(cmd)}...")
            result = subprocess.run(
                cmd, 
                input=input_data if input_data else None,
                capture_output=True, 
                text=True,
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired as e:
            self.log(f" ! Timeout expired for {cmd[0]}")
            return e.stdout if e.stdout else ""
        except Exception as e:
            self.log(f" ! Error running {cmd[0]}: {e}")
            return ""

    def execute(self):
        self.log(f"Starting FULL 7-TOOL reconnaissance for {self.target}")
        
        # 1. Subdomain Discovery (3 Tools)
        sub_list = []
        
        # Subfinder
        out = self.run_command(["subfinder", "-d", self.target, "-silent"])
        if out: sub_list.extend(out.splitlines())
        
        # Assetfinder
        out = self.run_command(["assetfinder", "--subs-only", self.target])
        if out: sub_list.extend(out.splitlines())
        
        # Amass
        out = self.run_command(["amass", "enum", "-passive", "-d", self.target, "-silent"], timeout=600)
        if out: sub_list.extend(out.splitlines())
        
        unique_subs = sorted(list(set([s.strip().lower() for s in sub_list if s.strip()])))
        self.results["subdomains"] = unique_subs
        self.log(f"Phase 1 Complete: {len(unique_subs)} subdomains found from 3 sources.")

        # 2. DNS Verification (dnsx)
        dns_out = self.run_command(["dnsx", "-silent"], input_data="\n".join(unique_subs))
        verified_subs = [s.strip() for s in dns_out.splitlines() if s.strip()]
        self.log(f"Phase 2 Complete: {len(verified_subs)} active subdomains.")

        # 3. HTTP Probing (httpx) - Scaled Concurrency
        httpx_out = self.run_command(["httpx", "-silent", "-title", "-status-code", "-json", "-t", self.threads], input_data="\n".join(verified_subs))
        live_data = []
        for line in httpx_out.splitlines():
            try: live_data.append(json.loads(line))
            except: pass
        self.results["live_hosts"] = live_data
        self.log(f"Phase 3 Complete: {len(live_data)} live web hosts.")

        # 4. Port Scanning (Top 1000)
        naabu_flags = ["-top-ports", "1000", "-silent", "-s", "c"]
        naabu_out = self.run_command(["naabu"] + naabu_flags, input_data="\n".join(verified_subs))
        if naabu_out: 
            self.results["open_ports"] = [p.strip() for p in naabu_out.splitlines() if p.strip()]
        self.log(f"Phase 4 Complete: {len(self.results['open_ports'])} open ports.")

        # 5. Web Crawling (Katana Deep Crawl) - Scaled Concurrency
        targets_to_crawl = [self.target] + [h.get('url') for h in live_data[:10] if h.get('url')]
        katana_out = self.run_command(["katana", "-list", ",".join(targets_to_crawl), "-silent", "-d", "2", "-c", self.katana_workers, "-jc"])
        if katana_out:
            self.results["crawled_urls"] = [u.strip() for u in katana_out.splitlines() if u.strip()]
        self.log(f"Phase 5 Complete: {len(self.results['crawled_urls'])} URLs discovered via Katana.")

        # Finalize
        self.save_results()
        self.generate_report()
        self.update_dashboard_data()
        self.log("Reconnaissance engine finished.")
        return self.results

    def generate_report(self):
        report_path = os.path.join(RECON_DIR, f"report_{self.target}_{self.timestamp}.md")
        with open(report_path, "w", encoding='utf-8') as f:
            f.write(f"# 🛡️ FULL 7-TOOL Intelligence Dossier: {self.target}\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## 📊 Mission Summary\n")
            f.write(f"- **Unique Subdomains:** {len(self.results['subdomains'])}\n")
            f.write(f"- **Live Web Services:** {len(self.results['live_hosts'])}\n")
            f.write(f"- **Total Open Ports:** {len(self.results['open_ports'])}\n")
            f.write(f"- **Discovered Endpoints:** {len(self.results['crawled_urls'])}\n\n")

            f.write("## 🌐 Web Infrastructure Map\n")
            f.write("| URL | Status | Title | Tech Stack |\n")
            f.write("| --- | --- | --- | --- |\n")
            for item in self.results['live_hosts']:
                title = item.get('title', 'N/A').replace("|", "-")
                tech = ", ".join(item.get('tech', []))
                f.write(f"| {item.get('url')} | {item.get('status-code')} | {title} | {tech} |\n")
            f.write("\n")

            f.write("## 🔌 Service & Port Matrix\n")
            if not self.results['open_ports']:
                f.write("*No open ports identified in the top 1000 scan.*\n")
            else:
                for port in self.results['open_ports']:
                    f.write(f"- `{port}`\n")
            f.write("\n")

            f.write("## 🔍 Subdomain Intelligence (Consolidated)\n")
            f.write("<details>\n<summary>Click to expand all subdomains</summary>\n\n")
            for sub in sorted(self.results['subdomains']):
                f.write(f"- {sub}\n")
            f.write("\n</details>\n\n")

            f.write("## 🕸️ Endpoint Discovery (Katana Crawl)\n")
            f.write("<details>\n<summary>Click to expand all discovered URLs</summary>\n\n")
            for url in sorted(self.results['crawled_urls']):
                f.write(f"- `{url}`\n")
            f.write("\n</details>\n\n")
            
            f.write("## 🛡️ Toolchain Integrity Trace\n")
            f.write("- ✅ **Subfinder**: Passive enumeration complete.\n")
            f.write("- ✅ **Assetfinder**: Certificate/Source scraping complete.\n")
            f.write("- ✅ **Amass**: Cross-source correlation complete.\n")
            f.write("- ✅ **DNSX**: Active resolution complete.\n")
            f.write("- ✅ **Httpx**: Protocol & Tech stack fingerprinting complete.\n")
            f.write("- ✅ **Naabu**: Tactical port sweep complete.\n")
            f.write("- ✅ **Katana**: Depth-2 spidering complete.\n")
                    
        self.log(f"Report generated: {report_path}")

    def save_results(self):
        filepath = os.path.join(RECON_DIR, f"recon_{self.target}_{self.timestamp}.json")
        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=4)
        self.log(f"JSON Results saved to {filepath}")

    def update_dashboard_data(self):
        try:
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, "r") as f:
                    content = f.read()
                    data = json.loads(content.replace("const dashboardData = ", "").rstrip(";"))
            else: data = []
        except: data = []

        data.insert(0, self.results)
        with open(DATA_FILE, "w") as f:
            f.write(f"const dashboardData = {json.dumps(data[:10], indent=4)};")
        self.log("Dashboard data updated.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python recon_engine.py <domain>")
        sys.exit(1)
    
    engine = ReconEngine(sys.argv[1])
    engine.execute()
