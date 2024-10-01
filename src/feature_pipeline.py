import pandas as pd
import re
from urllib.parse import urlparse, urljoin
import ssl
import socket
from datetime import datetime
import whois
import tldextract
import requests
from bs4 import BeautifulSoup
import argparse
import os
import json
from typing import List, Optional
import logging
import base64

# from dotenv import load_dotenv
# load_dotenv()

def load_data(file_path: str) -> pd.DataFrame:
    df = pd.read_csv(file_path)
    df = df.astype('int64')
    return df

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    df['Result'] = df['Result'].replace(-1,0)
    return df

def preprocess_data(df: pd.DataFrame) -> pd.DataFrame:
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values
    return X, y

class FeatureExtractor:
    def __init__(self, url: str):
        self._prepare_url(url)
        self._get_url_content()

    def _prepare_url(self, url: str) -> None:
        self.tld_info = tldextract.extract(url)
        if not self.tld_info.suffix:
            raise ValueError(f"Invalid URL format: {url}")
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                self.input_url = url
                url = 'http://' + url
                parsed = urlparse(url)
            self.url = url
            self.parsed_url = parsed
            self.tld_info = tldextract.extract(self.url)
            self.subdomain = self.tld_info.subdomain
            self.hostname = self.parsed_url.netloc.split(':')[0].lower()
            self.domain = self.tld_info.domain + '.' + self.tld_info.suffix
            # self.domain = self.parsed_url.netloc.split(':')[0].lower() #self.parsed_url.hostname #
            # self.subdomain = self.tld_info.subdomain.replace('www.', '')
            # print(self.parsed_url)
            # print(self.tld_info)
            # print(f"Scheme: {self.parsed_url.scheme}")
            # print(f"Subdomain: {self.subdomain}")
            # print(f"Domain: {self.domain}")
            # print(f"Suffix: {self.tld_info.suffix}")
            # print(f"Hostname: {self.hostname}")
            # print(f"URL: {self.url}")
            # print(f"New self.url: {self.url}")
            logging.info(f"URL: {self.url}")    
        except Exception as e:
            # print(f"Invalid URL {url} - {e}")
            raise ValueError(f"Invalid URL {url} - {e}")

    def _get_url_content(self) -> None:
        try:
            self.response = requests.get(self.url, timeout=5)
            if self.response.status_code != 200:
                raise ValueError(f"Unable to access {self.url}, HTTP Status: {self.response.status_code}")
            if self.response.history:
                for resp in self.response.history:
                    logging.info(f"Redirected: {resp.url} -> {self.response.url}")
                    self._prepare_url(self.response.url)
            self.soup = BeautifulSoup(self.response.content, 'html.parser')
            self._get_whois_info()
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Invalid URL {self.parsed_url.netloc} - {e}")

    def _get_whois_info(self) -> int:
        try:
            self.whois = whois.whois(self.domain)
        except Exception as e:
            raise ValueError(f"Error with WHOIS for {self.domain}: {e}")

    def has_ip_address(self) -> int:
        """
        Check if the domain part of the URL is an IP address (decimal or hexadecimal).
        Returns:
            -1 if IP address is used (Phishing)
             1 otherwise (Legitimate)
        """
        # Regular expression to match IPv4 addresses
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

        # Regular expression to match hexadecimal IP addresses
        hex_ip_pattern = re.compile(r'^(0x[0-9A-Fa-f]+\.){3}0x[0-9A-Fa-f]+$')

        if ipv4_pattern.match(self.domain) or hex_ip_pattern.match(self.domain):
            return -1  # Phishing
        else:
            return 1   # Legitimate

    def url_length(self) -> int:
        """
        Classify the URL based on its length.
        Returns:
            1  if URL length < 54 (Legitimate)
            0  if 54 <= URL length <= 75 (Suspicious)
           -1  if URL length > 75 (Phishing)
        """
        length = len(self.url)
        if length < 54:
            return 1  # Legitimate
        elif 54 <= length <= 75:
            return 0  # Suspicious
        else:
            return -1  # Phishing

    def uses_shortening_service(self) -> int:
        """
        Check if the URL uses a known URL shortening service.
        Returns:
            -1 if a shortening service is used (Phishing)
             1 otherwise (Legitimate)
        """
        shortening_services = {
            'tinyurl.com',
            'bit.ly',
            'goo.gl',
            'ow.ly',
            't.co',
            'is.gd',
            'buff.ly',
            'adf.ly',
            'bit.do',
            'cutt.ly'
        }

        if self.domain in shortening_services:
            return -1  # Phishing
        else:
            return 1   # Legitimate

    def has_at_symbol(self) -> int:
        """
        Check if the URL contains the '@' symbol.
        Returns:
            -1 if '@' is present (Phishing)
             1 otherwise (Legitimate)
        """
        return -1 if '@' in self.url else 1

    def has_multiple_slashes(self) -> int:
        """
        Check the position of the last occurrence of '//' in the URL.
        Returns:
            -1 if the last '//' is after the expected position (Phishing)
             1 otherwise (Legitimate)
        """
        # Find all occurrences of '//'
        indices = [m.start() for m in re.finditer(r'//', self.url)]

        if not indices:
            return 1  # Legitimate if '//' not found

        last_slash_index = indices[-1]

        # Determine expected position based on scheme
        scheme = self.parsed_url.scheme.lower()

        if scheme == 'http':
            expected_position = 5  # 'http:'
        elif scheme == 'https':
            expected_position = 6  # 'https:'
        else:
            # If scheme is neither http nor https, set expected_position to 0
            expected_position = 0

        if last_slash_index > expected_position + 1:
            return -1  # Phishing
        else:
            return 1   # Legitimate

    def has_hyphen_in_domain(self) -> int:
        """
        Check if the domain part of the URL contains a hyphen ('-').
        Returns:
            -1 if hyphen is present (Phishing)
             1 otherwise (Legitimate)
        """
        return -1 if '-' in self.domain else 1

    def count_subdomains(self) -> int:
        """
        Count the number of subdomains in the URL.
        Returns:
            1 if subdomain == 1 (Legitimate)
            0 if subdomain == 2 (Suspicious)
           -1 if subdomain > 2 (Phishing)
        """
        if self.subdomain:
            subdomain_count = len(self.subdomain.split('.'))
        else:
            subdomain_count = 0

        if subdomain_count == 0:
            return 1  # Legitimate
        elif subdomain_count == 1:
            return 0  # Suspicious
        else:
            return -1  # Phishing
    
    def check_https_cert(self) -> int:
        """
        Check if the URL uses HTTPS and if the SSL certificate is valid.
        Returns:
            1 if HTTPS is used and the certificate is valid (Legitimate)
            0 if HTTPS is used but the certificate is invalid or untrusted (Suspicious)
        -1 otherwise (Phishing)
        """
        # Check if URL uses HTTPS
        if not self.url.lower().startswith("https://"):
            return "Phishing"

        # Set default port for HTTPS
        port = 443

        # Create a socket and establish SSL connection
        context = ssl.create_default_context()
        logging.info(f"Checking SSL in: {self.hostname}")
        try:
            # Create a socket connection with server
            with socket.create_connection((self.hostname, port), timeout=5) as sock:           
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # The SSL certificate is validated upon wrapping the socket
                    # If there's an issue, an exception will be raised
                    cert = ssock.getpeercert()
                    return 1  # Legitimate
        except ssl.CertificateError:
            logging.info("Certificate is invalid or does not match the hostname")
            return 0  # Suspicious
        except (ssl.SSLError, socket.error, socket.timeout):
            logging.info("SSL or socket-related errors")
            return -1  # Phishing
        except Exception as e:
            logging.info(f"Unexpected error: {e}")
            return -1  # Phishing

    def domain_registration_length(self) -> int:
        """
        Check the domain's registration length.
        Returns:
            -1 if domain expires in <=1 year (Phishing)
             1 otherwise (Legitimate)
        """
        try:
            expiration_date = self.whois.expiration_date

            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]  # Take the first expiration date

            if not expiration_date:
                return -1  # Phishing

            days_remaining = (expiration_date - datetime.utcnow()).days
            years_remaining = days_remaining / 365.25

            if years_remaining <= 1:
                return -1  # Phishing
            else:
                return 1   # Legitimate
        except Exception as e:
            # In case of any exception (e.g., domain not found), classify as Phishing
            return -1  # Phishing

    def favicon_external(self) -> int:
        """
        Check if the favicon is loaded from an external domain.
        Returns:
            -1 if favicon is from external domain (Phishing)
             1 otherwise (Legitimate)
        """
        icon_link = self.soup.find('link', rel=lambda x: x and 'icon' in x.lower())
        if icon_link and icon_link.get('href'):
            favicon_url = urljoin(self.url, icon_link.get('href'))
            favicon_domain = urlparse(favicon_url).hostname.lower()

            if favicon_domain and favicon_domain != self.domain:
                return -1  # Phishing
            else:
                return 1   # Legitimate
        else:
            # If no favicon found, consider as Legitimate
            return 1
    
    def uses_non_standard_port(self) -> int:
        """
        Check if the URL uses a non-standard port.
        Preferred Ports:
            21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3389
        Preferred Status:
            Open: 80, 443
            Close: 21, 22, 23, 445, 1433, 1521, 3306, 3389
        Rule:
            IF port is in preferred ports and status is Open → Legitimate
            IF port is in preferred ports and status is Close → Legitimate
            IF port is not in preferred ports → Phishing
        Returns:
            1  if port is preferred (Open or Close) or no port specified (Legitimate)
        -1  if port is non-standard (Phishing)
        """
        preferred_ports = {21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3389}
        port = self.parsed_url.port

        if port is None:
            return 1  # No port specified, assume standard (Legitimate)

        if port in preferred_ports:
            return 1  # Preferred port (Legitimate)
        else:
            return -1  # Non-standard port (Phishing)

    def has_https_token_in_domain(self) -> int:
        """
        Check if the hostname part of the URL contains the 'https' token.
        Rule:
            IF 'https' is present in the hostname → Phishing
            ELSE → Legitimate
        Returns:
            -1 if 'https' is present in the hostname (Phishing)
            1 otherwise (Legitimate)
        """
        return -1 if 'https' in self.hostname else 1

    def request_url(self) -> int:
        """
        Calculate the percentage of external request URLs in the webpage.
        Rule:
            IF % < 22% → Legitimate
            IF 22% <= % < 61% → Suspicious
            ELSE → Phishing
        Returns:
            1  if percentage < 22% (Legitimate)
            0  if 22% <= percentage < 61% (Suspicious)
        -1  if percentage >= 61% (Phishing)
        """
        external_requests = 0
        total_requests = 0

        # Common external resources tags
        resource_tags = {
            'img': 'src',
            'video': 'src',
            'audio': 'src',
            'iframe': 'src',
            'embed': 'src',
            'source': 'src',
            'script': 'src',
            'link': 'href'
        }

        for tag, attr in resource_tags.items():
            for resource in self.soup.find_all(tag):
                url = resource.get(attr)
                if url:
                    total_requests += 1
                    resource_domain = tldextract.extract(urljoin(self.url, url))
                    resource_domain = resource_domain.domain + '.' + resource_domain.suffix
                    if resource_domain and resource_domain != self.domain:
                        external_requests += 1

        if total_requests == 0:
            percentage = 0
        else:
            percentage = (external_requests / total_requests) * 100
        if percentage < 22:
            return 1  # Legitimate
        elif 22 <= percentage < 61:
            return 0  # Suspicious
        else:
            return -1  # Phishing

    def anchor_url(self) -> int:
        """
        Calculate the percentage of external anchor URLs in the webpage.
        Rule:
            IF % < 31% → Legitimate
            IF 31% <= % <= 67% → Suspicious
            ELSE → Phishing
        Returns:
            1  if percentage < 31% (Legitimate)
            0  if 31% <= percentage <= 67% (Suspicious)
        -1  if percentage > 67% (Phishing)
        """
        external_anchors = 0
        total_anchors = 0

        for a_tag in self.soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith('#') or href.lower().startswith('javascript:'):
                continue  # Ignore non-navigational anchors

            total_anchors += 1
            anchor_domain = tldextract.extract(urljoin(self.url, href))
            anchor_domain = anchor_domain.domain + '.' + anchor_domain.suffix
            if anchor_domain and anchor_domain != self.domain:
                external_anchors += 1
        if total_anchors == 0:
            percentage = 0
        else:
            percentage = (external_anchors / total_anchors) * 100
        if percentage < 31:
            return 1  # Legitimate
        elif 31 <= percentage <= 67:
            return 0  # Suspicious
        else:
            return -1  # Phishing

    def links_in_tags(self) -> int:
        """
        Calculate the percentage of external links in <meta>, <script>, and <link> tags.
        Rule:
            IF % < 17% → Legitimate
            IF 17% <= % <= 81% → Suspicious
            ELSE → Phishing
        Returns:
            1  if percentage < 17% (Legitimate)
            0  if 17% <= percentage <= 81% (Suspicious)
        -1  if percentage > 81% (Phishing)
        """
        external_links = 0
        total_links = 0

        # Tags to inspect
        tags_to_inspect = {
            'meta': 'content',
            'script': 'src',
            'link': 'href'
        }

        for tag, attr in tags_to_inspect.items():
            for element in self.soup.find_all(tag):
                url = element.get(attr)
                if url:
                    total_links += 1
                    link_domain = tldextract.extract(urljoin(self.url, url))
                    link_domain = link_domain.domain + '.' + link_domain.suffix
                    if link_domain and link_domain != self.domain:
                        external_links += 1

        if total_links == 0:
            percentage = 0
        else:
            percentage = (external_links / total_links) * 100

        if percentage < 17:
            return 1  # Legitimate
        elif 17 <= percentage <= 81:
            return 0  # Suspicious
        else:
            return -1  # Phishing

    def server_form_handler(self) -> int:
        """
        Check the server form handler (SFH) of all forms in the webpage.
        Rule:
            IF SFH is "about:blank" or empty → Phishing
            IF SFH refers to a different domain → Suspicious
            ELSE → Legitimate
        Returns:
            -1  if SFH is "about:blank" or empty (Phishing)
            0  if SFH refers to a different domain (Suspicious)
            1  otherwise (Legitimate)
        """
        forms = self.soup.find_all('form')
        if not forms:
            return 1  # No forms, consider Legitimate

        results = []
        for form in forms:
            action = form.get('action')
            if not action or action.strip().lower() == 'about:blank':
                results.append(-1)  # Phishing
                continue

            action_domain = tldextract.extract(urljoin(self.url, action))
            action_domain = action_domain.domain + '.' + action_domain.suffix
            if action_domain and action_domain != self.domain:
                results.append(0)  # Suspicious
            else:
                results.append(1)  # Legitimate

        # Aggregate results
        if any(result == -1 for result in results):
            return -1  # Phishing if any form is phishing
        elif any(result == 0 for result in results):
            return 0  # Suspicious if any form is suspicious
        else:
            return 1  # Legitimate

    def submitting_info_to_email(self) -> int:
        """
        Check if the webpage submits information using 'mail()' in PHP or 'mailto:' links.
        Rule:
            IF 'mail()' or 'mailto:' is used → Phishing
            ELSE → Legitimate
        Returns:
            -1  if 'mail()' or 'mailto:' is used (Phishing)
            1  otherwise (Legitimate)
        """

        content = self.response.text.lower()

        # Check for 'mail()' in scripts or server-side code
        if 'mail()' in content:
            return -1  # Phishing

        # Check for 'mailto:' in links
        soup = self.soup
        mailto_links = soup.find_all('a', href=lambda x: x and x.lower().startswith('mailto:'))
        if mailto_links:
            return -1  # Phishing

        return 1  # Legitimate
   
    def abnormal_url(self) -> int:
        """
        Check if the host name is included in the URL outside the domain part.
        Returns:
            -1 if host name is not included in the URL (Phishing)
             1 otherwise (Legitimate)
        """
        return 1 if self.subdomain else -1

    def website_forwarding(self) -> int:
        """
        Check the number of redirects the URL undergoes.
        Returns:
            1  if redirects <=1 (Legitimate)
            0  if 2 <= redirects <4 (Suspicious)
           -1  if redirects >=4 (Phishing)
        """
        redirect_count = len(self.response.history)
        if redirect_count <= 1:
            return 1  # Legitimate
        elif 2 <= redirect_count < 4:
            return 0  # Suspicious
        else:
            return -1  # Phishing

    def status_bar_customization(self) -> int:
        """
        Check if the webpage changes the status bar using onMouseOver events.
        Returns:
            -1 if status bar is changed (Phishing)
             1 otherwise (Legitimate)
        """
        try:
            page_content = self.response.text.lower()
            
            # Search for onmouseover attributes that modify window.status
            # Example patterns: onmouseover="window.status='...'; return true;"
            pattern = re.compile(r'onmouseover\s*=\s*"[^"]*window\.status\s*=')
            if pattern.search(page_content):
                return -1  # Phishing
            else:
                return 1   # Legitimate
        except Exception:
            return -1  # Phishing in case of any exception
        
    def disabling_right_click(self) -> int:
        """
        Check if the webpage disables right-click using JavaScript.
        Returns:
            -1 if right-click is disabled (Phishing)
             1 otherwise (Legitimate)
        """
        try:
            page_content = self.response.text.lower()
            
            # Search for JavaScript that disables right-click, e.g., event.button==2
            pattern = re.compile(r'event\.button\s*==\s*2')
            if pattern.search(page_content):
                return -1  # Phishing
            else:
                return 1   # Legitimate
        except Exception:
            return -1  # Phishing in case of any exception

    def using_popup_window(self) -> int:
        """
        Check if pop-up windows contain text fields.
        Returns:
            -1 if pop-up contains text fields (Phishing)
             1 otherwise (Legitimate)
        """
        scripts = self.soup.find_all('script')
        popup_with_text = False
        
        for script in scripts:
            if script.string:
                # Search for window.open with HTML content containing input fields
                if 'window.open' in script.string:
                    # Simple heuristic: look for 'input' tags in the popup
                    if re.search(r'<input[^>]*>', script.string):
                        popup_with_text = True
                        break
        
        return -1 if popup_with_text else 1

    def iframe_redirection(self) -> int:
        """
        Check if the webpage uses <iframe> tags.
        Returns:
            -1 if <iframe> is used (Phishing)
            1 otherwise (Legitimate)
        """
        if self.soup.find('iframe'):
            return -1  # Phishing
        else:
            return 1   # Legitimate

    def age_of_domain(self) -> int:
        """
        Check the age of the domain.
        Returns:
            1  if domain age >=6 months (Legitimate)
           -1  if domain age <6 months (Phishing)
        """
        creation_date = self.whois.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if not creation_date:
            return -1  # Phishing
        
        if isinstance(creation_date, datetime):
            domain_age_days = (datetime.utcnow() - creation_date).days
            domain_age_months = domain_age_days / 30.44  # Approximate
        
            if domain_age_months >= 6:
                return 1  # Legitimate
            else:
                return -1  # Phishing
        else:
            return -1  # Phishing if creation_date is not datetime

    def dns_record(self) -> int:
        """
        Check if the domain has a DNS record.
        Returns:
            -1 if no DNS record is found (Phishing)
             1 otherwise (Legitimate)
        """
        try:
            socket.gethostbyname(self.domain)
            return 1  # Legitimate
        except socket.gaierror:
            return -1  # Phishing
        except Exception:
            return -1  # Phishing in case of any exception

    def website_traffic(self) -> int:
        """
        Checks the website rank from the Tranco API and classifies it.

        Parameters:
            domain (str): The domain to check (e.g., 'example.com').
            username (str): Your Tranco API username.
            password (str): Your Tranco API password.

        Returns:
            int: 
                1  if rank < 100,000 (Legitimate)
                0  if 100,000 <= rank < Some Upper Limit (Suspicious)
            -1  otherwise (Phishing)
        """
        try:
            TRANCO_URL = f"https://tranco-list.eu/api/ranks/domain/{self.domain}"
            TRANCO_API_USERNAME = os.getenv('TRANCO_API_USERNAME')
            TRANCO_API_PASSWORD = os.getenv('TRANCO_API_PASSWORD')

            if not TRANCO_API_USERNAME or not TRANCO_API_PASSWORD:
                logging.error("TRANCO keys not found")
                return -1  # Phishing if API credentials not set

            response = requests.get(TRANCO_URL, auth=(TRANCO_API_USERNAME, TRANCO_API_PASSWORD))

            if response.status_code != 200:
                logging.error(f"API request failed with status code {response.status_code}: {response.text}")
                return -1  # Phishing
            
            data = response.json()
            ranks = data.get('ranks', [])
            if not ranks:
                logging.warning(f"No rank data available for domain: {self.domain}")
                return -1  # Phishing
            rank_today = sorted(ranks, key=lambda x: x['date'], reverse=True)[0].get('rank')
            logging.info(f"Rank for {self.domain}: {rank_today}")

            if rank_today < 100000:
                return 1  # Legitimate
            elif rank_today >= 100000:
                return 0  # Suspicious
            else:
                return -1  # Phishing

        except Exception as e:
            logging.error(f"Error: {e}")
            return -1  # Phishing

    def pagerank(self) -> int:
        """
        Retrieves the PageRank of the domain and classifies it according to the rule:
        If PageRank < 0.2 --> 0 'Phishing'
        Otherwise --> 1 'Legitimate'

        Returns:
            str: 0 or 1 based on the evaluation.
        """
        try:
            OPENRANK_URL = "https://openpagerank.com/api/v1.0/getPageRank"
            OPENRANK_KEY = os.getenv('OPENRANK_KEY')
            if not OPENRANK_KEY:
                logging.error("OPENRANK keys not found")
                return -1  # Phishing if API credentials not set
            
            headers = {
                "API-OPR":OPENRANK_KEY
            }
            params = {
                "domains[]": self.domain
            }
            response = requests.get(OPENRANK_URL, headers=headers, params=params)
            data = response.json()

            if response.status_code == 200 and 'response' in data:
                page_rank = data['response'][0].get('page_rank_decimal', None)
                if page_rank is None:
                    logging.warning(f"Could not obtain the PageRank of {self.domain}")
                    return 0
                if page_rank < 0.2:
                    return 0
                else:
                    return 1
            else:
                logging.error(f"OPENRANK API Error: {data}")
                return 0

        except Exception as e:
            logging.error(f"Error: {e}")
            return 0

    def google_index(self) -> int:
        """
        Check if the webpage is indexed by Google using the Google Custom Search API.
        Rule:
            IF Indexed → Legitimate
            ELSE → Phishing
        Returns:
            1  if indexed (Legitimate)
        -1  otherwise (Phishing)
        """
        try:
            GOOGLE_API_URL = "https://www.googleapis.com/customsearch/v1"
            GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
            GOOGLE_CSE_ID = os.getenv('GOOGLE_CSE_ID')
            if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
                logging.error("Google keys not found")
                return -1  # Phishing if API credentials not set

            query = f"site:{self.domain}"
            params = {
                'key': GOOGLE_API_KEY,
                'cx': GOOGLE_CSE_ID,
                'q': query
            }

            response = requests.get(GOOGLE_API_URL, params=params, timeout=5)
            if response.status_code != 200:
                logging.error("GOOGLE API call failed")
                return -1  # Phishing if API call fails
            data = response.json()
            if 'items' in data and len(data['items']) > 0:
                return 1  # Legitimate
            else:
                return -1  # Phishing
        except Exception:
            logging.error(f"GOOGLE API Error: {e}")
            return -1  # Phishing in case of any exception

    def number_of_links_pointing_to_page(self) -> int:
        """
        Check the number of external links pointing to the webpage using the Moz Link Explorer API.
        Rule:
            IF #Links = 0 → Phishing
            IF 0 < #Links <=2 → Suspicious
            ELSE → Legitimate
        Returns:
            -1 if #Links = 0 (Phishing)
             0 if 0 < #Links <=2 (Suspicious)
             1 if #Links >2 (Legitimate)
        """
        try:
            RAPIDAPI_HOST = os.getenv('RAPIDAPI_HOST')
            RAPIDAPI_KEY = os.getenv('RAPIDAPI_KEY')
            RAPIDAPI_URL = "https://best-backlink-checker-api.p.rapidapi.com/excatbacklinks_noneng.php"
            if not RAPIDAPI_HOST or not RAPIDAPI_KEY:
                logging.error("Rapid API keys not found")
                return -1  # Phishing if API credentials not set

            query = {"domain":self.url}
            headers = {
                "x-rapidapi-key": RAPIDAPI_KEY,
                "x-rapidapi-host": RAPIDAPI_HOST
            }

            response = requests.get(RAPIDAPI_URL, headers=headers, params=query)
            if response.status_code != 200:
                logging.error("RAPIDAPI call failed")
                return -1  # Phishing if API call fails

            data = response.json()
            print(data)
            external_links = len(data)
            print(f"RAPIDAPI len: {external_links}")
            if external_links == 0:
                return -1  # Phishing
            elif 0 < external_links <= 2:
                return 0   # Suspicious
            else:
                return 1   # Legitimate
        except Exception as e:
            logging.error(f"Error: {e}")
            return -1  # Phishing in case of any exception

    def statistical_reports_based(self) -> int:
        """
        Check if the host belongs to top phishing IPs or top phishing domains.
        Returns:
            -1 if host is in top phishing IPs or domains (Phishing)
             1 otherwise (Legitimate)
        """
        try:
            PHISH_URL = "https://checkurl.phishtank.com/checkurl/"
            headers = {
                "User-Agent": 'phishtank/swatty'
            }
            params = {
                "url": base64.b64encode(self.url.encode()).decode(),
                "format": 'json',
                "app_key": ''
            }

            response = requests.post(PHISH_URL, params=params, headers=headers)
            soup = BeautifulSoup(response.content, 'lxml-xml')
            in_database_tag = soup.find('in_database')
            in_database_value = in_database_tag.text.strip().lower()

            if in_database_value == 'true':
                return -1
            else: 
                return 1
        except Exception as e:
            logging.error(f"Error: {e}")
            return -1  # Phishing in case of any exception

    def extract_all_features(self) -> List[int]:
        # Extract all features and return them as a list.
        features = [
            self.has_ip_address(),                  # Feature 1: Using the IP Address
            self.url_length(),                      # Feature 2: Long URL to Hide the Suspicious Part
            self.uses_shortening_service(),                    # Feature 3: Using URL Shortening Services “TinyURL”
            self.has_at_symbol(),                   # Feature 4: URL’s having “@” Symbol
            self.has_multiple_slashes(),            # Feature 5: Redirecting using “//”
            self.has_hyphen_in_domain(),            # Feature 6: Adding Prefix or Suffix Separated by (-) to the Domain
            self.count_subdomains(),                # Feature 7: Sub Domain and Multi Sub Domains
            self.check_https_cert(),                # Feature 8: HTTPS with Certificate Checks
            self.domain_registration_length(),      # Feature 9: Domain Registration Length
            self.favicon_external(),                # Feature 10: Favicon
            self.uses_non_standard_port(),          # Feature 11: Using Non-Standard Port
            self.has_https_token_in_domain(),       # Feature 12: Existence of “HTTPS” Token in the Domain Part of the URL
            self.request_url(),                     # Feature 13: Request URL
            self.anchor_url(),                      # Feature 14: URL of Anchor
            self.links_in_tags(),                   # Feature 15: Links in <Meta>, <Script>, and <Link> Tags
            self.server_form_handler(),             # Feature 16: Server Form Handler (SFH)
            self.submitting_info_to_email(),        # Feature 17: Submitting Information to Email
            self.abnormal_url(),                    # Feature 18: Abnormal URL
            self.website_forwarding(),              # Feature 19: Website Forwarding
            self.status_bar_customization(),        # Feature 20: Status Bar Customization
            self.disabling_right_click(),           # Feature 21: Disabling Right Click
            self.using_popup_window(),              # Feature 22: Using Pop-up Window
            self.iframe_redirection(),              # Feature 23: IFrame Redirection
            self.age_of_domain(),                   # Feature 24: Age of Domain
            self.dns_record(),                      # Feature 25: DNS Record
            self.website_traffic(),                 # Feature 26: Website Traffic
            self.pagerank(),                        # Feature 27: PageRank
            self.google_index(),                    # Feature 28: Google Index
            self.number_of_links_pointing_to_page(),# Feature 29: Number of Links Pointing to Page
            self.statistical_reports_based()        # Feature 30: Statistical-Reports Based Feature
        ]
        return [features]

def parse_features(features: list) -> str:
    parsed_features = []
    for i in range(len(FEATURES)):
        if i < len(features[0]):
            parsed_features.append(f"{i+1}: {features[0][i]}\t{FEATURES[i]}\n")
        else:
            parsed_features.append(f"{i+1}: N/A\t{FEATURES[i]}\n")
    
    return ''.join(parsed_features)

FEATURES=[
            'has_ip_address',
            'url_length',
            'uses_shortening_service',
            'has_at_symbol',
            'has_multiple_slashes',
            'has_hyphen_in_domain',
            'count_subdomains',
            'check_https_cert',
            'domain_registration_length',
            'favicon_external',
            'uses_non_standard_port',
            'has_https_token_in_domain',
            'request_url',
            'anchor_url',
            'links_in_tags',
            'server_form_handler',
            'submitting_info_to_email',
            'abnormal_url',
            'website_forwarding',
            'status_bar_customization',
            'disabling_right_click',
            'using_popup_window',
            'iframe_redirection',
            'age_of_domain',
            'dns_record',
            'website_traffic',
            'pagerank',
            'google_index',
            'number_of_links_pointing_to_page',
            'statistical_reports_based'
            ]

if __name__ == "__main__":
    from inference_pipeline import predict
    parser = argparse.ArgumentParser(description="Run the feature extractor with a URL")
    parser.add_argument('url', help='URL to extract features from')
    args = parser.parse_args()

    # Create a FeatureExtractor instance and call the process method
    try:
        extractor = FeatureExtractor(args.url)
        all_features = extractor.extract_all_features()
        print(parse_features(all_features))
        prediction = predict(all_features)
        print(f"Prediction: {prediction[0]}, Probability: {prediction[1]*100}")
    except ValueError as e:
        print(f"Unable to extract features: {e}")