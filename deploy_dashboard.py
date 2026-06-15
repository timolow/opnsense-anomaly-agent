#!/usr/bin/env python3
"""Deploy dashboard server on remote host."""
import subprocess
import os

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return r.stdout, r.stderr, r.returncode

# Upload files
for f in ["server.py", "app.html"]:
    src = f"/Users/timolow/opnsense-anomaly-agent/{f}"
    dst = "tim@192.168.1.50:/home/tim/opnsense-anomaly-agent/"
    _, err, rc = run(f"scp -i ~/.ssh/id_rsa {src} {dst}")
    if rc != 0:
        print(f"FAIL scp {f}: {err}")
    else:
        print(f"OK scp {f}")

# Check psycopg2 on remote
stdout, stderr, rc = run("""
ssh -i ~/.ssh/id_rsa tim@192.168.1.50 "python3 -c 'import psycopg2; print(psycopg2.__version__)'" 2>&1
""")
print(f"psycopg2: {stdout.strip()}")

# Kill any existing server
run("""
ssh -i ~/.ssh/id_rsa tim@192.168.1.50 "pkill -f 'python3 server.py' || true; sleep 1"
""")

# Install psycopg2 if needed
stdout, stderr, rc = run("""
ssh -i ~/.ssh/id_rsa tim@192.168.1.50 "pip3 install psycopg2-binary 2>&1 | tail -3"
""")
print(f"pip install: {stdout.strip()}")

# Start server
stdout, stderr, rc = run("""
ssh -i ~/.ssh/id_rsa tim@192.168.1.50 "cd /home/tim/opnsense-anomaly-agent && nohup python3 server.py > /tmp/dashboard.log 2>&1 & echo \\$!"
""")
print(f"Server started (PID: {stdout.strip()})")

# Wait and test
import time
time.sleep(3)

# Test endpoints
import json
endpoints = ["/api/stats", "/api/heatmap", "/api/ip-flow", "/api/events", "/api/geo", "/api/health", "/api/alerts"]
for ep in endpoints:
    _, err, rc = run(f"""
ssh -i ~/.ssh/id_rsa tim@192.168.1.50 "curl -s http://localhost:8766{ep}"
""")
    if rc == 0:
        try:
            data = json.loads(err or stdout)
            if isinstance(data, dict):
                print(f"OK {ep}: {list(data.keys())}")
            elif isinstance(data, list):
                print(f"OK {ep}: {len(data)} items")
            else:
                print(f"OK {ep}: {str(data)[:100]}")
        except:
            print(f"OK {ep}: {str(err or stdout)[:100]}")
    else:
        print(f"FAIL {ep}")
