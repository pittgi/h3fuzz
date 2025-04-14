# h3fuzz
Testing framework with integrated grammar- &amp; mutation-based fuzzer designed to test HTTP/3 (reverse) proxies for non-compliance with RFC 9114.

# Testing Workflow
h3fuzz generates malformed HTTP/3 requests, sends them to (reverse) proxies and collects the forwarded messages for further analysis.
We test for two kinds of RFC 9114 violations:
1. **Strong violations**: A request was forwarded without altering the malicious payload that rendered the request malformed.
2. **Weak violations**: A request was forwarded, but the malicious payload was removed (header sanitization).

# How to
1. Choose desired backend protocol version and run the desired backend server, e.g. `python3 h1server.py`
2. Configure (reverse) proxy to accept self-signed certificates
3. Run script as follows: `python3 main.py https://<proxy-address>/ -g experiment.json -t <timeout-duration-in-sec> -n <number-of-fuzzes>`


