# vda-FuzzUrlParameters

A command-line tool that fuzzes the parameters of a URL with a dictionary of attack vectors and logs responses that differ from a baseline response of the same page in a way that indicates a vulnerability. The XSS check sends a probe carrying a unique marker and reports a finding only when that marker is reflected unencoded in the response and absent from the baseline. The SQL injection check reports only when SQL error text appears in a response and not in the baseline, and the file inclusion check reports only when passwd-style file content appears and was not in the baseline. The default credential check compares each attempt against an unauthenticated baseline and reports success only on positive evidence (a new session cookie, a redirect to a different location, a status change, or body text indicating an authenticated state); passwords are never logged or written to results, only the username and the outcome. It also probes for an exposed .git/config at the site root, and crawl mode fuzzes each discovered same-domain page once, with page and depth caps. Results are written to results.txt inside the output directory. The tool exits non-zero on an invalid URL, on a parameter parsing failure, or when every request fails.

## Install
`git clone https://github.com/ShadowGuard-AI/vda-fuzzurlparameters`

## Usage
`python main.py "http://example.com/page.php?id=1"`

## Parameters
- `-h`: Show help message and exit
- `-o`: The output directory to store results. Defaults to fuzz_results.
- `-c`: Crawl the website and fuzz discovered URLs.

## License
Copyright (c) ShadowGuard-AI
