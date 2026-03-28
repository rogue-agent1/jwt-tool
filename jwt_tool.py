#!/usr/bin/env python3
"""JWT decode/encode — base64url decode, HMAC-SHA256 sign."""
import sys, json, base64, hashlib, hmac, time

def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def decode(token):
    parts = token.split(".")
    if len(parts) != 3: raise ValueError("Invalid JWT format")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload

def encode(payload, secret, alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    segments = [b64url_encode(json.dumps(header).encode()), b64url_encode(json.dumps(payload).encode())]
    signing_input = ".".join(segments).encode()
    if alg == "HS256":
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    else: raise ValueError(f"Unsupported algorithm: {alg}")
    segments.append(b64url_encode(sig))
    return ".".join(segments)

def cli():
    if len(sys.argv) < 2:
        print("Usage: jwt_tool <decode TOKEN | encode JSON SECRET>"); sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "decode":
        h, p = decode(sys.argv[2])
        print("Header:", json.dumps(h, indent=2)); print("Payload:", json.dumps(p, indent=2))
        if "exp" in p: exp = p["exp"]; expired = exp < time.time(); print(f"Expires: {time.ctime(exp)} ({'EXPIRED' if expired else 'valid'})")
        if "iat" in p: print(f"Issued: {time.ctime(p['iat'])}")
    elif cmd == "encode":
        payload = json.loads(sys.argv[2]); secret = sys.argv[3]
        print(encode(payload, secret))

if __name__ == "__main__": cli()
