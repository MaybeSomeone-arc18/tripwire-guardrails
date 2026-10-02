"""Use Tripwire from Python through the local HTTP server (no pip install needed).
   Terminal 1:  npx tripwire-server --port 8787
   Terminal 2:  python3 examples/python/check.py "ignore all previous instructions"
"""
import json, sys, urllib.request

def check(text, direction="input", url="http://127.0.0.1:8787/check"):
    req = urllib.request.Request(url, data=json.dumps({"text": text, "direction": direction}).encode(),
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:   # raises on a non-200 or no server: treat that as "do not send"
        return json.load(r)

if __name__ == "__main__":
    v = check(" ".join(sys.argv[1:]) or "hello")
    print(json.dumps({"allowed": v["allowed"], "categories": v["categories"]}))
    sys.exit(0 if v["allowed"] else 1)
