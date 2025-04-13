import argparse
import requests
import logging
import re
from bs4 import BeautifulSoup
import tldextract
from urllib.parse import urlparse, urljoin
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Common attack vectors
ATTACK_VECTORS = {
    "xss": ["<script>alert('XSS')</script>", '"<img src=x onerror=alert(\'XSS\')>"', "&lt;script&gt;alert('XSS')&lt;/script&gt;"],
    "sql_injection": ["'", "';", "1=1", "OR 1=1", "--", "/*", "*/"],
    "lfi": ["../etc/passwd", "../../etc/passwd", "/etc/passwd", "....//....//etc/passwd"],
    "open_redirect": ["//evil.com", "http://evil.com", "https://evil.com"],
    "git": ["/.git/config", "/.git/HEAD"],
    "default_creds": ["admin:admin", "root:root", "user:password"] #Basic check, not comprehensive
}

# Error messages
ERROR_INVALID_URL = "Error: Invalid URL provided."
ERROR_REQUEST_FAILED = "Error: Request failed for URL: {} with status code: {}"
ERROR_DIRECTORY_EXISTS = "Error: Directory already exists: {}"
ERROR_CREATING_DIRECTORY = "Error: Failed to create directory: {}"
ERROR_PARSING_URL = "Error: Failed to parse URL: {}"

# Success messages
SUCCESS_DIRECTORY_CREATED = "Successfully created directory: {}"

class FuzzUrlParameters:
    """
    A class for fuzzing URL parameters to discover potential vulnerabilities.
    """

    def __init__(self, url, output_dir="fuzz_results", crawl=False):
        """
        Initializes the FuzzUrlParameters object.

        Args:
            url (str): The URL to fuzz.
            output_dir (str): The directory to store the results. Defaults to "fuzz_results".
            crawl (bool): Whether to crawl the website for more URLs. Defaults to False.
        """
        self.url = url
        self.output_dir = output_dir
        self.crawl = crawl
        self.tested_urls = set()  # Keep track of URLs already tested
        self.session = requests.Session()  # Use session for persistent connections

        # Input Validation
        if not self.is_valid_url(self.url):
            raise ValueError(ERROR_INVALID_URL)

        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
                logging.info(SUCCESS_DIRECTORY_CREATED.format(self.output_dir))
            except OSError as e:
                logging.error(ERROR_CREATING_DIRECTORY.format(self.output_dir))
                raise  # Re-raise the exception after logging

        elif not os.path.isdir(self.output_dir):
            raise OSError(ERROR_DIRECTORY_EXISTS.format(self.output_dir))


    def is_valid_url(self, url):
        """
        Validates the given URL.

        Args:
            url (str): The URL to validate.

        Returns:
            bool: True if the URL is valid, False otherwise.
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False


    def fuzz_parameter(self, url, param, attack_vector):
        """
        Fuzzes a single parameter with a given attack vector.

        Args:
            url (str): The base URL.
            param (str): The parameter to fuzz.
            attack_vector (str): The attack vector to use.
        """
        fuzzed_url = self.replace_parameter_value(url, param, attack_vector)
        self.test_url(fuzzed_url)

    def replace_parameter_value(self, url, param, value):
        """
        Replaces the value of a parameter in the URL.

        Args:
            url (str): The URL to modify.
            param (str): The parameter to replace.
            value (str): The new value for the parameter.

        Returns:
            str: The modified URL.
        """

        parsed_url = urlparse(url)
        query_params = dict(qp.split("=") for qp in parsed_url.query.split("&") if qp)

        if param in query_params:
            query_params[param] = value
        else:
            query_params[param] = value

        new_query = "&".join([f"{k}={v}" for k, v in query_params.items()])
        return parsed_url._replace(query=new_query).geturl()

    def test_url(self, url):
        """
        Tests the given URL and logs the response.

        Args:
            url (str): The URL to test.
        """
        if url in self.tested_urls:
            return # Skip already tested URLs

        try:
            response = self.session.get(url, allow_redirects=True, timeout=10)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            logging.info(f"URL: {url} - Status Code: {response.status_code}")
            self.tested_urls.add(url)

            # Basic check for XSS
            if "<script>" in response.text.lower():
                logging.warning(f"Possible XSS vulnerability detected at: {url}")

            # Basic check for open redirect
            if response.history:
                 for resp in response.history:
                      logging.warning(f"Possible Open Redirect to: {resp.headers.get('Location')} from {url}")

        except requests.exceptions.RequestException as e:
            logging.error(ERROR_REQUEST_FAILED.format(url, e))


    def discover_links(self, url):
        """
        Discovers links on a given webpage.

        Args:
            url (str): The URL to crawl.

        Returns:
            list: A list of discovered links.
        """
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            links = []
            for a_tag in soup.find_all('a', href=True):
                link = urljoin(url, a_tag['href'])
                if self.is_same_domain(self.url, link) and link not in self.tested_urls:
                    links.append(link)
                    self.tested_urls.add(link)  # Mark as tested
            return links
        except requests.exceptions.RequestException as e:
            logging.error(f"Error crawling {url}: {e}")
            return []


    def is_same_domain(self, base_url, target_url):
      """
      Checks if the target URL belongs to the same domain as the base URL.
      """
      try:
          base_domain = tldextract.extract(base_url).domain
          target_domain = tldextract.extract(target_url).domain
          return base_domain == target_domain
      except Exception as e:
          logging.error(f"Error comparing domains: {e}")
          return False

    def check_for_git_directory(self, url):
        """
        Checks for the existence of a .git directory.
        """
        git_config_url = urljoin(url, ".git/config")
        self.test_url(git_config_url)


    def check_default_credentials(self, url):
        """
        Attempts to authenticate with default credentials (very basic).
        """
        for cred in ATTACK_VECTORS["default_creds"]:
            user, password = cred.split(":")
            try:
                response = self.session.get(url, auth=(user, password), timeout=10)
                if response.status_code == 200: # Or another success code
                    logging.warning(f"Default credentials {user}:{password} worked at {url}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error during default credential check at {url}: {e}")

    def fuzz_all_parameters(self):
        """
        Fuzzes all parameters of the URL with common attack vectors.
        """
        parsed_url = urlparse(self.url)
        query_params = parsed_url.query

        if not query_params:
            logging.info("No parameters found in the URL.")
            return

        params = dict(qp.split("=") for qp in query_params.split("&") if qp)

        for param in params:
            logging.info(f"Fuzzing parameter: {param}")
            for attack_type, vectors in ATTACK_VECTORS.items():
                for vector in vectors:
                    self.fuzz_parameter(self.url, param, vector)

    def crawl_and_fuzz(self):
        """
        Crawls the website and fuzzes all discovered URLs.
        """
        urls_to_crawl = [self.url]
        while urls_to_crawl:
            current_url = urls_to_crawl.pop(0) #FIFO for breadth first search
            if current_url not in self.tested_urls:

                logging.info(f"Crawling and fuzzing: {current_url}")
                self.fuzz_all_parameters()
                self.check_for_git_directory(current_url)
                self.check_default_credentials(current_url)

                #Discover new links (crawl)
                new_links = self.discover_links(current_url)
                urls_to_crawl.extend(new_links)


    def run(self):
        """
        Runs the vulnerability discovery automation.
        """
        logging.info(f"Starting vulnerability discovery automation for: {self.url}")

        if self.crawl:
            self.crawl_and_fuzz()
        else:
            self.fuzz_all_parameters()
            self.check_for_git_directory(self.url)
            self.check_default_credentials(self.url)

        logging.info("Vulnerability discovery automation completed.")



def setup_argparse():
    """
    Sets up the argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description='Fuzz URL parameters for vulnerability discovery.')
    parser.add_argument('url', help='The URL to fuzz.')
    parser.add_argument('-o', '--output', dest='output_dir', default='fuzz_results',
                        help='The output directory to store results. Defaults to fuzz_results.')
    parser.add_argument('-c', '--crawl', action='store_true', help='Crawl the website and fuzz discovered URLs.')
    return parser

def main():
    """
    Main function to parse arguments and run the fuzzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        fuzzer = FuzzUrlParameters(args.url, args.output_dir, args.crawl)
        fuzzer.run()
    except ValueError as e:
        logging.error(e)
    except OSError as e:
        logging.error(e)
    except Exception as e:
        logging.exception("An unexpected error occurred: {}".format(e)) # Using exception to log the full traceback



if __name__ == "__main__":
    main()

# Usage examples:
# python main.py "http://example.com/page.php?id=1"
# python main.py "http://example.com/page.php?id=1" -o my_results
# python main.py "http://example.com/" -c
# python main.py "http://example.com/page.php?id=1&name=test" -c -o crawl_results