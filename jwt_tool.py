#!/usr/bin/env python3
"""JWT — encode, decode, validate JSON Web Tokens."""
import json, hashlib, hmac, base64, time, sys

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def jwt_encode(payload, secret, algorithm="HS256"):
    header = {"alg": algorithm, "typ": "JWT"}
    h = b64url_encode(json.dumps(header))
    p = b64url_encode(json.dumps(payload))
    sig_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"

def jwt_decode(token, secret=None, verify=True):
    parts = token.split(".")
    if len(parts) != 3: raise ValueError("Invalid JWT")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    if verify and secret:
        sig_input = f"{parts[0]}.{parts[1]}".encode()
        expected = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
        actual = b64url_decode(parts[2])
        if not hmac.compare_digest(expected, actual):
            raise ValueError("Invalid signature")
    if "exp" in payload and payload["exp"] < time.time():
        raise ValueError("Token expired")
    return header, payload

if __name__ == "__main__":
    secret = "super-secret-key"
    payload = {"sub": "user123", "name": "Alice", "iat": int(time.time()),
               "exp": int(time.time()) + 3600, "roles": ["admin", "user"]}
    token = jwt_encode(payload, secret)
    print(f"Token: {token[:50]}...\n")
    header, decoded = jwt_decode(token, secret)
    print(f"Header: {header}")
    print(f"Payload: {json.dumps(decoded, indent=2)}")
    try:
        jwt_decode(token, "wrong-key")
    except ValueError as e:
        print(f"\nBad key: {e}")
