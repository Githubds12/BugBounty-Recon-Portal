import os

def check_tools():
    import subprocess
    bin_dir = "./bin"
    status = {}
    
    # Tools and their light test commands
    tools = {
        "subfinder": ["-version"],
        "assetfinder": ["-h"],
        "amass": ["version"],
        "dnsx": ["-version"],
        "httpx": ["-version"],
        "naabu": ["-h"],
        "katana": ["-version"]
    }
    
    for tool, cmd in tools.items():
        path = os.path.join(bin_dir, tool)
        if os.name == 'nt' and not path.endswith('.exe'):
            path += '.exe'
            
        if os.path.exists(path):
            try:
                # Real test: try to execute it
                subprocess.run([path] + cmd, capture_output=True, timeout=2)
                status[tool] = "OK"
            except Exception:
                status[tool] = "EXECUTION_ERROR"
        else:
            status[tool] = "MISSING"
            
    return status

if __name__ == "__main__":
    print(check_tools())
