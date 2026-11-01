import argparse
import logging
import os
import sys
import uuid
from urllib.parse import parse_qsl, urlencode, urlparse

import requests
from bs4 import BeautifulSoup
import tldextract

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ATTACK_VECTORS = {
    "xss": ["<script>alert('XSS')</script>", "\"<img src=x onerror=alert('XSS')>\"", "&lt;script&gt;alert('XSS')&lt;/script&gt;"],
    "sql_injection": ["'", "';", "1=1", "OR 1=1", "--", "/*", "*/"],
    "lfi": ["../etc/passwd", "../../etc/passwd", "/etc/passwd", "....//....//etc/passwd"],
    "open_redirect": ["//evil.com", "http://evil.com", "https://evil.com"],
    "git": ["/.git/config", "/.git/HEAD"],
    "default_creds": ["admin:admin", "root:root", "user:password"]
}

SQL_ERROR_MARKERS = ["sql syntax", "sqlite3", "operationalerror", "mysql_fetch", "unclosed quotation mark", "odbc", "syntax error in query"]
LFI_MARKERS = ["root:x:0:0:", "root:*:0:0:"]
MAX_PAGES = 50
MAX_DEPTH = 3

class FuzzUrlParameters:
    def __init__(self, url, output_dir="fuzz_results", crawl=False):
        self.url = url
        self.output_dir = output_dir
        self.crawl = crawl
        self.tested_urls = set()
        self.session = requests.Session()
        self.findings = []
        self.requests_made = 0
        self.requests_failed = 0
        if not self.is_valid_url(self.url):
            raise ValueError("Error: Invalid URL provided.")
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
                logging.info(f"Successfully created directory: {self.output_dir}")
            except OSError:
                logging.error(f"Error: Failed to create directory: {self.output_dir}")
                raise
        elif not os.path.isdir(self.output_dir):
            raise OSError(f"Error: Directory already exists as a file: {self.output_dir}")

    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def _record(self, ok):
        self.requests_made += 1
        if not ok:
            self.requests_failed += 1

    def _get(self, url, **kw):
        try:
            resp = self.session.get(url, timeout=10, **kw)
            self._record(True)
            return resp
        except requests.exceptions.RequestException as e:
            self._record(False)
            logging.error(f"Request failed for URL: {url}: {e}")
            return None

    def replace_parameter_value(self, url, param, value):
        parsed_url = urlparse(url)
        pairs = parse_qsl(parsed_url.query, keep_blank_values=True)
        new_pairs = []
        replaced = False
        for k, v in pairs:
            if k == param:
                new_pairs.append((k, value)); replaced = True
            else:
                new_pairs.append((k, v))
        if not replaced:
            new_pairs.append((param, value))
        return parsed_url._replace(query=urlencode(new_pairs)).geturl()

    def test_url(self, url, payload=None, attack_type=None, baseline_text=None, marker=None):
        if url in self.tested_urls:
            return None
        self.tested_urls.add(url)
        response = self._get(url, allow_redirects=True)
        if response is None:
            return None
        logging.info(f"URL: {url} - Status Code: {response.status_code}")
        body = response.text or ""
        baseline = baseline_text or ""
        if attack_type == "xss" and marker:
            if marker in body and marker not in baseline:
                msg = f"Possible XSS vulnerability detected at: {url} (unique marker reflected unencoded, absent from baseline)"
                logging.warning(msg); self.findings.append(msg)
        elif attack_type == "sql_injection":
            low, blow = body.lower(), baseline.lower()
            if any(m in low and m not in blow for m in SQL_ERROR_MARKERS):
                msg = f"Possible SQL injection vulnerability detected at: {url} (SQL error text in response, absent from baseline)"
                logging.warning(msg); self.findings.append(msg)
        elif attack_type == "lfi":
            if any(m in body and m not in baseline for m in LFI_MARKERS):
                msg = f"Possible local file inclusion vulnerability detected at: {url} (passwd-style content in response, absent from baseline)"
                logging.warning(msg); self.findings.append(msg)
        if response.history:
            for resp in response.history:
                msg = f"Possible Open Redirect to: {resp.headers.get('Location')} from {url}"
                logging.warning(msg)
        return response

    def fuzz_parameter(self, url, param, attack_vector, attack_type=None, baseline_text=None):
        marker = None
        payload = attack_vector
        if attack_type == "xss":
            marker = "SGXSS" + uuid.uuid4().hex[:12]
            payload = f"<script>alert('{marker}')</script>"
        fuzzed_url = self.replace_parameter_value(url, param, payload)
        self.test_url(fuzzed_url, payload=payload, attack_type=attack_type, baseline_text=baseline_text, marker=marker)

    def discover_links(self, url):
        response = self._get(url)
        if response is None:
            return []
        soup = BeautifulSoup(response.text, 'html.parser')
        from urllib.parse import urljoin
        links = []
        for a_tag in soup.find_all('a', href=True):
            link = urljoin(url, a_tag['href'])
            if self.is_same_domain(self.url, link) and link not in links:
                links.append(link)
        return links

    def is_same_domain(self, base_url, target_url):
        try:
            b = tldextract.extract(base_url); t = tldextract.extract(target_url)
            return (b.domain, b.suffix) == (t.domain, t.suffix)
        except Exception as e:
            logging.error(f"Error comparing domains: {e}")
            return False

    def check_for_git_directory(self, url):
        parsed = urlparse(url)
        git_config_url = f"{parsed.scheme}://{parsed.netloc}/.git/config"
        response = self._get(git_config_url)
        if response is None:
            return
        if response.status_code == 200:
            msg = f"Exposed .git/config found at: {git_config_url}"
            logging.warning(msg); self.findings.append(msg)
        else:
            logging.info(f"No exposed .git/config at site root (status {response.status_code}).")

    def check_default_credentials(self, url):
        baseline = self._get(url)
        if baseline is None:
            return
        base_body = baseline.text or ""
        base_cookies = set(baseline.cookies.get_dict().keys()) if baseline.cookies else set()
        base_url_final = baseline.url
        for cred in ATTACK_VECTORS["default_creds"]:
            user, password = cred.split(":", 1)
            try:
                response = self.session.get(url, auth=(user, password), timeout=10)
                self._record(True)
            except requests.exceptions.RequestException as e:
                self._record(False)
                logging.error(f"Error during default credential check for user {user} at {url}: {e}")
                continue
            new_cookies = set()
            try:
                new_cookies = set(response.cookies.get_dict().keys()) - base_cookies
            except Exception:
                pass
            # Also check raw Set-Cookie header for a session cookie the baseline did not set.
            set_cookie = response.headers.get("Set-Cookie", "")
            cookie_evidence = bool(new_cookies) or ("session" in set_cookie.lower() and "session" not in (baseline.headers.get("Set-Cookie", "").lower()))
            redirect_evidence = response.url != base_url_final
            body_evidence = (response.text or "") != base_body and ("authenticated" in (response.text or "").lower() or "dashboard" in (response.text or "").lower() or "welcome" in (response.text or "").lower())
            # A differing status alone counts only when the baseline was not already a success page with the same body.
            status_evidence = response.status_code != baseline.status_code and response.status_code < 400
            if response.status_code < 400 and (cookie_evidence or redirect_evidence or body_evidence or status_evidence):
                msg = f"Default credentials for user {user} appear to work at {url} (evidence: cookie={cookie_evidence}, redirect={redirect_evidence}, body={body_evidence}, status_change={status_evidence})"
                logging.warning(msg); self.findings.append(msg)
            else:
                logging.info(f"Default credentials for user {user} did not authenticate at {url}")

    def fuzz_all_parameters(self, url=None):
        target_url = url or self.url
        parsed_url = urlparse(target_url)
        if not parsed_url.query:
            logging.info("No parameters found in the URL.")
            return
        pairs = parse_qsl(parsed_url.query, keep_blank_values=True)
        params = []
        for k, _v in pairs:
            if k not in params: params.append(k)
        baseline_resp = self._get(target_url)
        baseline_text = baseline_resp.text if baseline_resp is not None else ""
        for param in params:
            logging.info(f"Fuzzing parameter: {param}")
            for attack_type, vectors in ATTACK_VECTORS.items():
                if attack_type == "default_creds":
                    continue
                for vector in vectors:
                    self.fuzz_parameter(target_url, param, vector, attack_type=attack_type, baseline_text=baseline_text)

    def crawl_and_fuzz(self):
        queue = [(self.url, 0)]
        seen_pages = set()
        pages = 0
        while queue and pages < MAX_PAGES:
            current_url, depth = queue.pop(0)
            if current_url in seen_pages:
                continue
            seen_pages.add(current_url); pages += 1
            logging.info(f"Crawling and fuzzing: {current_url}")
            self.fuzz_all_parameters(current_url)
            self.check_for_git_directory(current_url)
            self.check_default_credentials(current_url)
            if depth < MAX_DEPTH:
                for link in self.discover_links(current_url):
                    page_key = link.split("#")[0]
                    if page_key not in seen_pages and all(page_key != q[0] for q in queue):
                        queue.append((page_key, depth + 1))

    def write_results(self):
        path = os.path.join(self.output_dir, "results.txt")
        with open(path, "w") as f:
            f.write(f"Target: {self.url}\n")
            f.write(f"Requests made: {self.requests_made}\n")
            f.write(f"Requests failed: {self.requests_failed}\n")
            f.write(f"Findings: {len(self.findings)}\n")
            for finding in self.findings:
                f.write(f"- {finding}\n")
        logging.info(f"Results written to {path}")
        return path

    def run(self):
        logging.info(f"Starting vulnerability discovery automation for: {self.url}")
        if self.crawl:
            self.crawl_and_fuzz()
        else:
            self.fuzz_all_parameters()
            self.check_for_git_directory(self.url)
            self.check_default_credentials(self.url)
        self.write_results()
        if self.requests_made == 0 or self.requests_failed >= self.requests_made:
            logging.error("All requests failed; no testing was completed.")
            return False
        logging.info("Vulnerability discovery automation completed.")
        return True

def setup_argparse():
    parser = argparse.ArgumentParser(description='Fuzz URL parameters for vulnerability discovery.')
    parser.add_argument('url', help='The URL to fuzz.')
    parser.add_argument('-o', '--output', dest='output_dir', default='fuzz_results', help='The output directory to store results. Defaults to fuzz_results.')
    parser.add_argument('-c', '--crawl', action='store_true', help='Crawl the website and fuzz discovered URLs.')
    return parser

def main():
    parser = setup_argparse()
    args = parser.parse_args()
    try:
        fuzzer = FuzzUrlParameters(args.url, args.output_dir, args.crawl)
        ok = fuzzer.run()
    except ValueError as e:
        logging.error(e); return 1
    except OSError as e:
        logging.error(e); return 1
    except Exception as e:
        logging.exception("An unexpected error occurred: {}".format(e)); return 1
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
