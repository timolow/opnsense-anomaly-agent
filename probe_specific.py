#!/usr/bin/env python3
"""Probe specific endpoints for dhcp, unbound, ntp, openvpn, wireguard."""
import os, json, subprocess

OPN_HOST = os.getenv("OPN_HOST", "192.168.1.1")
OPN_PORT = os.getenv("OPN_PORT", "6666")
OPN_KEY = os.getenv("OPN_API_KEY", "")
OPN_SEC = os.getenv("OPN_API_SECRET", "")

if not OPN_KEY or not OPN_SEC:
    print("Error: OPN_API_KEY and OPN_API_SECRET must be set in environment.")
    exit(1)

def probe(endpoint):
    cmd = [
        "curl", "-s", "-w", "\\n%{http_code}",
        "--user", f"{OPN_KEY}:{OPN_SEC}",
        "-H", "Accept: application/json",
        "--insecure",
        f"https://{OPN_HOST}:{OPN_PORT}{endpoint}"
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        lines = r.stdout.rsplit("\n", 1)
        raw = lines[0]
        code = int(lines[-1]) if lines else -1
        data = None
        if raw:
            try: data = json.loads(raw)
            except: pass
        return code, data
    except Exception as e:
        return None, None

def describe_schema(data, depth=0, max_depth=2):
    if depth >= max_depth: return f"<{type(data).__name__}>[max]"
    if data is None: return "null"
    if isinstance(data, bool): return f"bool({data})"
    if isinstance(data, (int, float)): return f"num({data})"
    if isinstance(data, str): return f'str("{data[:40]}...")' if len(data) > 40 else f'str("{data}")'
    if isinstance(data, list):
        if len(data) == 0: return "array[]"
        if len(data) > 5: return f"arr[{len(data)}]"
        return f"arr[{len(data)}]: [{', '.join(describe_schema(d, depth+1, max_depth) for d in data)}]"
    if isinstance(data, dict):
        if len(data) == 0: return "obj{}"
        if len(data) > 5:
            ks = ", ".join(f"{k}:{describe_schema(v, depth+1, max_depth)}" for k, v in list(data.items())[:3])
            return f"obj{{{ks}, ...+{len(data)-3}}}"
        return f"obj{{{', '.join(f'{k}:{describe_schema(v, depth+1, max_depth)}' for k, v in data.items())}}}"
    return type(data).__name__

# From terraform-provider-opnsense source structure
CONTROLLERS = {
    "unbound": ["general", "status", "settings", "forward", "host-alias", "host-override", "acl"],
    "openvpn": ["status", "settings", "csc", "client"],
    "wireguard": ["settings", "client", "server", "peers"],
    "ntp": ["general", "status", "settings"],
    "dhcp": ["settings", "status", "leases", "server", "dhcpleases", "dhcpranges"],
}

print(f"Probing endpoints on https://{OPN_HOST}:{OPN_PORT}/api")
print("=" * 70)

for module, controllers in CONTROLLERS.items():
    print(f"\n[{module.upper()}]")
    for ctrl in controllers:
        for action in ["get", "search", "status"]:
            ep = f"/api/{module}/{ctrl}/{action}"
            code, data = probe(ep)
            symbol = "✅" if code == 200 else "❌" if code == 404 else "⚠️"
            print(f"  {symbol} {ep} -> {code}")
            if code == 200 and data:
                print(f"     schema: {describe_schema(data)}")
                print(f"     keys: {list(data.keys())[:8]}")
                # Try nested controllers
                for key, val in data.items():
                    if isinstance(val, dict) and len(val) > 0:
                        sub_ep = f"/api/{module}/{ctrl}/{key}/{action}"
                        sub_code, sub_data = probe(sub_ep)
                        sub_sym = "✅" if sub_code == 200 else "❌"
                        print(f"       {sub_sym} -> /api/{module}/{ctrl}/{key}/{action}: {sub_code}")
                        if sub_code == 200 and sub_data:
                            print(f"           schema: {describe_schema(sub_data)}")

print("\n" + "=" * 70)
print("DONE")
