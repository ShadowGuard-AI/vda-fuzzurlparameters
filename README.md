# vda-FuzzUrlParameters
A command-line tool that takes a URL as input and automatically generates variations of the URL by fuzzing its parameters. It adds, removes, and modifies parameter values with a dictionary of common attack vectors, logging any unusual server responses that may indicate vulnerabilities such as SQL injection or XSS. - Focused on Automates the discovery of common web application vulnerabilities like open redirects, exposed .git directories, and default credentials by crawling web applications and performing basic checks. Aims to reduce manual reconnaissance efforts.

## Install
`git clone https://github.com/ShadowStrikeHQ/vda-fuzzurlparameters`

## Usage
`./vda-fuzzurlparameters [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: The output directory to store results. Defaults to fuzz_results.
- `-c`: Crawl the website and fuzz discovered URLs.

## License
Copyright (c) ShadowStrikeHQ
