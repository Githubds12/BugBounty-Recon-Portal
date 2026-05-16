from flask import Flask, render_template, Response, request, jsonify
import subprocess
import os
import time
import json
import threading
import queue
from datetime import datetime
from werkzeug.utils import secure_filename

RECON_DIR = 'recon_storage'

app = Flask(__name__, static_folder='.', template_folder='.')

# Global lock to prevent duplicate scans
running_scans = set()

@app.route('/')
def index():
    # Serve the main dashboard
    return app.send_static_file('index.html')

@app.route('/api/reports', methods=['GET', 'DELETE'])
def handle_reports():
    if request.method == 'DELETE':
        # Clear all reports
        for f in os.listdir('recon_storage'):
            if f.endswith('.json') or f.endswith('.md'):
                os.remove(os.path.join('recon_storage', f))
        return {"status": "Archive Purged"}

    reports = []
    # Match .md reports with their .json data
    if os.path.exists('recon_storage'):
        for f in os.listdir('recon_storage'):
            if f.endswith('.json'):
                try:
                    base_name = f.replace('.json', '')
                    report_file = base_name.replace('recon_', 'report_') + '.md'
                    
                    with open(os.path.join('recon_storage', f), 'r') as json_f:
                        data = json.load(json_f)
                        target_name = data.get('target', 'unknown')
                        if target_name == 'unknown': continue
                        
                        raw_ts = data.get('timestamp', time.time())
                        if isinstance(raw_ts, str):
                            try: ts = int(datetime.fromisoformat(raw_ts).timestamp())
                            except: ts = int(time.time())
                        else: ts = int(raw_ts)

                        reports.append({
                            "filename": report_file,
                            "target": target_name,
                            "subs": len(data.get('subdomains', [])),
                            "live": len(data.get('live_hosts', [])),
                            "ports": len(data.get('open_ports', [])),
                            "timestamp": ts * 1000
                        })
                except: continue
    return {"reports": sorted(reports, key=lambda x: x.get('timestamp', 0), reverse=True)}

@app.route('/api/active_scans')
def get_active_scans():
    return {"active": list(running_scans)}

@app.route('/api/stats')
def get_stats():
    # Pull stats from the latest JSON in recon_storage
    files = [f for f in os.listdir('recon_storage') if f.endswith('.json')]
    if not files:
        return {"subs": 0, "live": 0, "ports": 0}
    
    latest = max(files, key=lambda x: os.path.getmtime(os.path.join('recon_storage', x)))
    with open(os.path.join('recon_storage', latest), 'r') as f:
        data = json.load(f)
        return {
            "subs": len(data.get('subdomains', [])),
            "live": len(data.get('live_hosts', [])),
            "ports": len(data.get('open_ports', []))
        }

@app.route('/api/report/<filename>')
def get_report_content(filename):
    # Security: ensure it's in recon_storage
    if '..' in filename or not filename.endswith('.md'):
        return "Access Denied", 403
    with open(os.path.join('recon_storage', filename), 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/api/health')
def health_check():
    from health_check import check_tools
    results = check_tools()
    return results

@app.route('/api/verify_tools')
def verify_tools():
    def generate():
        bin_dir = "./bin"
        tools = {
            "subfinder": ["-version"],
            "assetfinder": ["-h"],
            "amass": ["version"],
            "dnsx": ["-version"],
            "httpx": ["-version"],
            "naabu": ["-h"],
            "katana": ["-version"]
        }
        
        yield "data: 🔍 STARTING LIVE TOOLCHAIN AUDIT...\n\n"
        
        for tool, cmd in tools.items():
            path = os.path.join(bin_dir, tool)
            if os.name == 'nt': path += ".exe"
            
            yield f"data: > Testing {tool.upper()}...\n\n"
            try:
                process = subprocess.run([path] + cmd, capture_output=True, text=True, timeout=10)
                output = process.stdout.strip() or process.stderr.strip()
                yield f"data: ✅ {tool.upper()} RESPONSED: {output[:60]}...\n\n"
            except Exception as e:
                yield f"data: ❌ {tool.upper()} FAILED: {str(e)}\n\n"
            time.sleep(0.5)
            
        yield "data: ✅ AUDIT COMPLETE. ALL TOOLS VERIFIED.\n\n"

    return Response(generate(), mimetype='text/event-stream', headers={'X-Accel-Buffering': 'no'})

@app.route('/scan')
def scan():
    target = request.args.get('target', 'replit.com')
    
    if target in running_scans:
        return Response("data: ⚠️ Scan already in progress for this target. Streaming is locked.\n\n", mimetype='text/event-stream')

    def generate():
        running_scans.add(target)
        try:
            yield f"data: 🚀 Starting 7-Tool Scan for {target}...\n\n"
            
            import queue
            log_queue = queue.Queue()

            def read_output(pipe, q):
                for line in iter(pipe.readline, ''):
                    if line.strip():
                        q.put(line.strip())
                pipe.close()

            process = subprocess.Popen(
                ['python', '-u', 'recon_engine.py', target],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            import threading
            t = threading.Thread(target=read_output, args=(process.stdout, log_queue))
            t.daemon = True
            t.start()

            while process.poll() is None or not log_queue.empty():
                try:
                    # Wait for output with a 30s timeout for heartbeat
                    line = log_queue.get(timeout=30)
                    yield f"data: {line}\n\n"
                except queue.Empty:
                    # Send heartbeat if no output for 30s
                    yield f"data: 🔍 [MISSION CHRONOMETER] Scan in progress... ({target})\n\n"

            process.wait()
            yield f"data: ✅ Scan Complete.\n\n"
        finally:
            running_scans.discard(target)

    response = Response(generate(), mimetype='text/event-stream')
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Cache-Control'] = 'no-cache'
    return response

@app.route('/api/upload', methods=['POST'])
def upload_report():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file"}), 400
    
    if file:
        filename = secure_filename(file.filename)
        # Allow any research-related markdown or JSON files
        if not (filename.lower().endswith('.md') or filename.lower().endswith('.json')):
            return jsonify({"status": "error", "message": "Invalid file type. Please upload .md or .json files."}), 400
            
        file.save(os.path.join(RECON_DIR, filename))
        return jsonify({"status": "success", "message": f"Successfully archived {filename}"})

if __name__ == '__main__':
    # Ensure recon_storage exists
    if not os.path.exists(RECON_DIR):
        os.makedirs(RECON_DIR)
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
