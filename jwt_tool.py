#!/usr/bin/env python3
"""jwt_tool - JWT encode/decode from scratch (HS256)."""
import argparse, base64, json, hashlib, time

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def hmac_sha256(key, msg):
    bs = 64
    if len(key) > bs: key = hashlib.sha256(key).digest()
    key = key.ljust(bs, b'\x00')
    return hashlib.sha256(bytes(k^0x5c for k in key) + hashlib.sha256(bytes(k^0x36 for k in key) + msg).digest()).digest()

def encode_jwt(payload, secret):
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url_encode(json.dumps(payload).encode())
    sig = b64url_encode(hmac_sha256(secret.encode(), f"{header}.{body}".encode()))
    return f"{header}.{body}.{sig}"

def decode_jwt(token, secret=None):
    parts = token.split('.')
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    if secret:
        expected = b64url_encode(hmac_sha256(secret.encode(), f"{parts[0]}.{parts[1]}".encode()))
        valid = expected == parts[2]
    else:
        valid = None
    return header, payload, valid

def main():
    p = argparse.ArgumentParser(description="JWT tool")
    sub = p.add_subparsers(dest="cmd")
    enc = sub.add_parser("encode")
    enc.add_argument("payload", help="JSON payload")
    enc.add_argument("-s", "--secret", required=True)
    enc.add_argument("--exp", type=int, help="Expiry in seconds")
    dec = sub.add_parser("decode")
    dec.add_argument("token")
    dec.add_argument("-s", "--secret", help="Verify signature")
    args = p.parse_args()
    if args.cmd == "encode":
        payload = json.loads(args.payload)
        if args.exp: payload["exp"] = int(time.time()) + args.exp
        print(encode_jwt(payload, args.secret))
    elif args.cmd == "decode":
        header, payload, valid = decode_jwt(args.token, args.secret)
        print(f"Header: {json.dumps(header, indent=2)}")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        if valid is not None: print(f"Signature valid: {valid}")

if __name__ == "__main__":
    main()
