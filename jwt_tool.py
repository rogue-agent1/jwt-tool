#!/usr/bin/env python3
"""jwt_tool - JWT creation, decoding, and validation (HS256)."""
import json, hmac, hashlib, base64, sys, time, argparse

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def create_token(payload, secret, exp_seconds=None):
    header = {"alg":"HS256","typ":"JWT"}
    if exp_seconds:
        payload = {**payload, "exp": int(time.time()) + exp_seconds, "iat": int(time.time())}
    h = b64url_encode(json.dumps(header))
    p = b64url_encode(json.dumps(payload))
    msg = f"{h}.{p}"
    sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    return f"{msg}.{b64url_encode(sig)}"

def decode_token(token, secret=None, verify=True):
    parts = token.split(".")
    if len(parts) != 3: raise ValueError("Invalid JWT format")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    if verify and secret:
        msg = f"{parts[0]}.{parts[1]}"
        expected = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
        actual = b64url_decode(parts[2])
        if not hmac.compare_digest(expected, actual):
            raise ValueError("Invalid signature")
        if "exp" in payload and payload["exp"] < time.time():
            raise ValueError(f"Token expired at {payload['exp']}")
    return {"header": header, "payload": payload}

def main():
    p = argparse.ArgumentParser(description="JWT tool (HS256)")
    sub = p.add_subparsers(dest="cmd")
    c = sub.add_parser("create")
    c.add_argument("payload", help="JSON payload")
    c.add_argument("-s", "--secret", required=True)
    c.add_argument("-e", "--exp", type=int, help="Expiry in seconds")
    d = sub.add_parser("decode")
    d.add_argument("token")
    d.add_argument("-s", "--secret", help="Secret for verification")
    d.add_argument("--no-verify", action="store_true")
    args = p.parse_args()
    if args.cmd == "create":
        payload = json.loads(args.payload)
        print(create_token(payload, args.secret, args.exp))
    elif args.cmd == "decode":
        try:
            result = decode_token(args.token, args.secret, not args.no_verify)
            print(json.dumps(result, indent=2))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
