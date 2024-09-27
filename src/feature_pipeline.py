import pandas as pd
import arff
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
        parsed = urlparse(url)
        if not parsed.scheme:
            self.input_url = url
            url = 'http://' + url
            parsed = urlparse(url)
        self.url = url
        self.parsed_url = parsed
        self.domain = self.parsed_url.netloc.split(':')[0].lower() #self.parsed_url.hostname #
        self.tld_info = tldextract.extract(self.domain)
        self.subdomain = self.tld_info.subdomain.replace('www.', '')
        # print(self.parsed_url)
        # print(tldextract.extract(url))

    def _get_url_content(self) -> None:
        try:
            self.response = requests.get(self.url, timeout=5)
            if self.response.status_code != 200:
                raise ValueError(f"Unable to access {self.url}, HTTP Status: {self.response.status_code}")
            if self.response.history:
                for resp in self.response.history:
                    print(f"Redirected: {resp.url} -> {self.response.url}")
                    self._prepare_url(self.response.url)
                    print(f"New self.url: {self.url}")
            self.soup = BeautifulSoup(self.response.content, 'html.parser')
            self._get_whois_info()
        except requests.exceptions.RequestException as e:
            # raise ValueError(f"Error requesting URL: {e}")
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

    def url_length_feature(self) -> int:
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

    def uses_tinyurl(self) -> int:
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
        Count the number of subdomains in the domain part of the URL.
        Returns:
            1 if dots in domain part == 1 (Legitimate)
            0 if dots in domain part == 2 (Suspicious)
           -1 if dots in domain part > 2 (Phishing)
        """
        if self.subdomain:
            dot_count = self.subdomain.count('.')
        else:
            dot_count = 0

        if dot_count == 0:
            return 1  # Legitimate
        elif dot_count == 1:
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
        parsed_url = self.parsed_url
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        context = ssl.create_default_context()
        domain = self.domain
        print(f"Domain: {domain}")
        try:
            # Create a socket connection with server
            with socket.create_connection((domain, port), timeout=5) as sock:           
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # The SSL certificate is validated upon wrapping the socket
                    # If there's an issue, an exception will be raised
                    cert = ssock.getpeercert()
                return 1  # Legitimate
        except ssl.CertificateError:
            print("Certificate is invalid or does not match the hostname")
            return 0  # Suspicious
        except (ssl.SSLError, socket.error, socket.timeout):
            print("SSL or socket-related errors")
            return -1  # Phishing
        except Exception as e:
            print(f"Unexpected error: {e}")
            return -1  # Phishing

    def domain_registration_length(self) -> int:
        """
        Check the domain's registration length.
        Returns:
            -1 if domain expires in <=1 year (Phishing)
             1 otherwise (Legitimate)
        """
        domain = self.parsed_url.hostname
        if not domain:
            return -1  # Phishing

        try:
            # print(self.whois)
            expiration_date = self.whois.expiration_date
            # print("expiration_date: ",expiration_date)

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
        soup = self.soup
        icon_link = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
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
        Check if the domain part of the URL contains the 'https' token.
        Rule:
            IF 'https' is present in the domain → Phishing
            ELSE → Legitimate
        Returns:
            -1 if 'https' is present in the domain (Phishing)
            1 otherwise (Legitimate)
        """
        return -1 if 'https' in self.domain else 1

    def request_url_feature(self) -> int:
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
        soup = self.soup
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
            for resource in soup.find_all(tag):
                url = resource.get(attr)
                if url:
                    total_requests += 1
                    resource_domain = urlparse(urljoin(self.url, url)).netloc
                    # print(f"urlparse(urljoin({self.url}, {url}))")
                    # print(f"netloc: {urlparse(urljoin(self.url, url)).netloc}")
                    if resource_domain and resource_domain != self.domain:
                        external_requests += 1
                    # print(f"{resource_domain} != {self.domain}")

        if total_requests == 0:
            percentage = 0
        else:
            percentage = (external_requests / total_requests) * 100
        # print(f"{external_requests} / {total_requests}")
        if percentage < 22:
            return 1  # Legitimate
        elif 22 <= percentage < 61:
            return 0  # Suspicious
        else:
            return -1  # Phishing

    def anchor_url_feature(self) -> int:
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
        soup = self.soup
        external_anchors = 0
        total_anchors = 0

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith('#') or href.lower().startswith('javascript:'):
                continue  # Ignore non-navigational anchors

            total_anchors += 1
            anchor_domain = urlparse(urljoin(self.url, href)).netloc
            if anchor_domain and anchor_domain != self.domain:
                external_anchors += 1
            # print(f"{anchor_domain} != {self.domain}")
        if total_anchors == 0:
            percentage = 0
        else:
            percentage = (external_anchors / total_anchors) * 100
        # print(f"{external_anchors} / {total_anchors}")
        if percentage < 31:
            return 1  # Legitimate
        elif 31 <= percentage <= 67:
            return 0  # Suspicious
        else:
            return -1  # Phishing

    def links_in_tags_feature(self) -> int:
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
        soup = self.soup
        external_links = 0
        total_links = 0

        # Tags to inspect
        tags_to_inspect = {
            'meta': 'content',
            'script': 'src',
            'link': 'href'
        }

        for tag, attr in tags_to_inspect.items():
            for element in soup.find_all(tag):
                url = element.get(attr)
                if url:
                    total_links += 1
                    link_domain = urlparse(urljoin(self.url, url)).netloc
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

    def server_form_handler_feature(self) -> int:
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
        soup = self.soup
        forms = soup.find_all('form')
        if not forms:
            return 1  # No forms, consider Legitimate

        results = []
        for form in forms:
            action = form.get('action')
            if not action or action.strip().lower() == 'about:blank':
                results.append(-1)  # Phishing
                continue

            action_domain = urlparse(urljoin(self.url, action)).netloc
            # print(f"{action_domain} != {self.domain}")
            if action_domain and action_domain != self.domain:
                results.append(0)  # Suspicious
            else:
                results.append(1)  # Legitimate
        # print(results)
        # Aggregate results
        if any(result == -1 for result in results):
            return -1  # Phishing if any form is phishing
        elif any(result == 0 for result in results):
            return 0  # Suspicious if any form is suspicious
        else:
            return 1  # Legitimate

    def submitting_info_to_email_feature(self) -> int:
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
   
    def abnormal_url_feature(self) -> int:
        """
        Check if the host name is included in the URL outside the domain part.
        Returns:
            -1 if host name is included elsewhere in the URL (Phishing)
             1 otherwise (Legitimate)
        """
        try:
            main_domain = self.tld_info.domain
            suffix = self.tld_info.suffix
            host_name = f"{main_domain}.{suffix}"
            
            # Check if the host name appears in the path, query, or fragment
            url_components = [
                self.parsed_url.path.lower(),
                self.parsed_url.query.lower(),
                self.parsed_url.fragment.lower()
            ]
            host_in_url = any(host_name.lower() in component for component in url_components)
            
            return -1 if host_in_url else 1
        except Exception:
            return -1  # Phishing in case of any exception

    def website_forwarding_feature(self) -> int:
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

    def status_bar_customization_feature(self) -> int:
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
        
    def disabling_right_click_feature(self) -> int:
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

    def using_popup_window_feature(self) -> int:
        """
        Check if pop-up windows contain text fields.
        Returns:
            -1 if pop-up contains text fields (Phishing)
             1 otherwise (Legitimate)
        """
        soup = self.soup
        scripts = soup.find_all('script')
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

    def iframe_redirection_feature(self) -> int:
        """
        Check if the webpage uses <iframe> tags.
        Returns:
            -1 if <iframe> is used (Phishing)
            1 otherwise (Legitimate)
        """
        soup = self.soup 
        if soup.find('iframe'):
            return -1  # Phishing
        else:
            return 1   # Legitimate

    def age_of_domain_feature(self) -> int:
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

    def dns_record_feature(self) -> int:
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

    def website_traffic_feature(self) -> int:
        """
        Check the website's traffic rank using the SimilarWeb API.
        Rule:
            IF Website Rank < 100,000 → Legitimate
            IF 100,000 <= Website Rank → Suspicious
            ELSE → Phishing
        Returns:
            1  if rank < 100,000 (Legitimate)
            0  if 100,000 <= rank < Some Upper Limit (Suspicious)
           -1  otherwise (Phishing)
        """
        similarweb_api_key = os.getenv('SIMILARWEB_API_KEY')
        if not similarweb_api_key:
            return -1  # Phishing if API key not set

        try:
            import requests
            url = f"https://api.similarweb.com/v1/website/{self.domain}/total-traffic-and-engagement/visits?api_key={similarweb_api_key}&start=2023&end=2023&country=world&granularity=monthly"
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return -1  # Phishing if API call fails

            data = response.json()
            # Assuming 'visits' is a list of monthly visit counts
            total_visits = sum(month['visits'] for month in data.get('visits', []))
            # Simple heuristic: higher total visits imply higher rank
            # In reality, SimilarWeb provides a separate ranking
            # Placeholder logic:
            if total_visits == 0:
                return -1  # Phishing
            elif total_visits < 100000:
                return 1   # Legitimate
            else:
                return 0   # Suspicious
        except Exception:
            return -1  # Phishing in case of any exception

    def pagerank_feature(self) -> int:
        """
        Check the PageRank of the domain using the Moz API.
        Rule:
            IF PageRank < 0.2 → Phishing
            ELSE → Legitimate
        Returns:
            -1 if PageRank < 0.2 (Phishing)
             1 otherwise (Legitimate)
        """
        moz_access_id = os.getenv('MOZ_ACCESS_ID')
        moz_secret_key = os.getenv('MOZ_SECRET_KEY')
        if not moz_access_id or not moz_secret_key:
            return -1  # Phishing if API credentials not set

        try:
            import requests
            import base64
            import hashlib
            import hmac
            from datetime import datetime, timedelta

            # Construct the Moz API request
            expires = int((datetime.utcnow() + timedelta(minutes=5)).timestamp())
            string_to_sign = f"{moz_access_id}\n{expires}"
            signature = base64.b64encode(hmac.new(moz_secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1).digest()).rstrip()

            url = f"https://lsapi.seomoz.com/linkscape/url-metrics/{self.domain}"
            params = {
                'Cols': '68719476736'  # PR metric
            }
            headers = {
                'Authorization': f"AccessID={moz_access_id}; Expires={expires}; Signature={signature.decode()}"
            }

            response = requests.get(url, params=params, headers=headers, timeout=10)
            if response.status_code != 200:
                return -1  # Phishing if API call fails

            data = response.json()
            pagerank = data.get('pda', 0) / 10  # Normalize to 0-1 scale

            if pagerank < 0.2:
                return -1  # Phishing
            else:
                return 1   # Legitimate
        except Exception:
            return -1  # Phishing in case of any exception

    def google_index_feature(self) -> int:
        """
        Check if the webpage is indexed by Google using the Google Custom Search API.
        Rule:
            IF Indexed → Legitimate
            ELSE → Phishing
        Returns:
            1  if indexed (Legitimate)
           -1  otherwise (Phishing)
        """
        google_api_key = os.getenv('GOOGLE_API_KEY')
        google_cse_id = os.getenv('GOOGLE_CSE_ID')
        if not google_api_key or not google_cse_id:
            return -1  # Phishing if API credentials not set

        try:
            import requests
            query = f"site:{self.domain}"
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                'key': google_api_key,
                'cx': google_cse_id,
                'q': query
            }
            response = requests.get(url, params=params, timeout=10)
            if response.status_code != 200:
                return -1  # Phishing if API call fails

            data = response.json()
            if 'items' in data and len(data['items']) > 0:
                return 1  # Legitimate
            else:
                return -1  # Phishing
        except Exception:
            return -1  # Phishing in case of any exception

    def number_of_links_pointing_to_page_feature(self) -> int:
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
        moz_access_id = os.getenv('MOZ_ACCESS_ID')
        moz_secret_key = os.getenv('MOZ_SECRET_KEY')
        if not moz_access_id or not moz_secret_key:
            return -1  # Phishing if API credentials not set

        try:
            import requests
            import base64
            import hashlib
            import hmac
            from datetime import datetime, timedelta

            # Construct the Moz API request
            expires = int((datetime.utcnow() + timedelta(minutes=5)).timestamp())
            string_to_sign = f"{moz_access_id}\n{expires}"
            signature = base64.b64encode(hmac.new(moz_secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1).digest()).rstrip()

            url = f"https://lsapi.seomoz.com/linkscape/url-metrics/{self.domain}"
            params = {
                'Cols': '128'  # External Links
            }
            headers = {
                'Authorization': f"AccessID={moz_access_id}; Expires={expires}; Signature={signature.decode()}"
            }

            response = requests.get(url, params=params, headers=headers, timeout=10)
            if response.status_code != 200:
                return -1  # Phishing if API call fails

            data = response.json()
            external_links = data.get('uid', 0)  # Placeholder for actual external links count

            # Note: Adjust the key based on the API's actual response structure
            # This is a placeholder and may need to be updated accordingly

            if external_links == 0:
                return -1  # Phishing
            elif 0 < external_links <= 2:
                return 0   # Suspicious
            else:
                return 1   # Legitimate
        except Exception:
            return -1  # Phishing in case of any exception

    def statistical_reports_based_feature(self) -> int:
        """
        Check if the host belongs to top phishing IPs or top phishing domains.
        Returns:
            -1 if host is in top phishing IPs or domains (Phishing)
             1 otherwise (Legitimate)
        """
        # Load the lists from local files or a database
        # Example assumes you have two sets: top_phishing_ips and top_phishing_domains
        try:
            # Example: Load from JSON files
            top_phishing_ips = set()
            top_phishing_domains = set()
            
            with open('data/top_phishing_ips.json', 'r') as f:
                top_phishing_ips = set(json.load(f))
            
            with open('data/top_phishing_domains.json', 'r') as f:
                top_phishing_domains = set(json.load(f))
            
            # Check if the domain's IP is in top phishing IPs
            try:
                ip_address = socket.gethostbyname(self.domain)
                if ip_address in top_phishing_ips:
                    return -1  # Phishing
            except socket.gaierror:
                pass  # Ignore DNS errors here
                
            # Check if the domain is in top phishing domains
            if self.domain in top_phishing_domains:
                return -1  # Phishing
            
            return 1  # Legitimate
        except Exception:
            return -1  # Phishing in case of any exception

    def extract_all_features(self) -> List[int]:
        """Extract all features and return them as a list."""
        features = [
            self.has_ip_address(),                  # Feature 1: Using the IP Address
            self.url_length_feature(),              # Feature 2: Long URL to Hide the Suspicious Part
            self.uses_tinyurl(),                    # Feature 3: Using URL Shortening Services “TinyURL”
            self.has_at_symbol(),                   # Feature 4: URL’s having “@” Symbol
            self.has_multiple_slashes(),            # Feature 5: Redirecting using “//”
            self.has_hyphen_in_domain(),            # Feature 6: Adding Prefix or Suffix Separated by (-) to the Domain
            self.count_subdomains(),                # Feature 7: Sub Domain and Multi Sub Domains
            self.check_https_cert(),                # Feature 8: HTTPS with Certificate Checks
            self.domain_registration_length(),      # Feature 9: Domain Registration Length
            self.favicon_external(),                # Feature 10: Favicon
            self.uses_non_standard_port(),          # Feature 11: Using Non-Standard Port
            self.has_https_token_in_domain(),       # Feature 12: Existence of “HTTPS” Token in the Domain Part of the URL
            self.request_url_feature(),             # Feature 13: Request URL
            self.anchor_url_feature(),              # Feature 14: URL of Anchor
            self.links_in_tags_feature(),           # Feature 15: Links in <Meta>, <Script>, and <Link> Tags
            self.server_form_handler_feature(),     # Feature 16: Server Form Handler (SFH)
            self.submitting_info_to_email_feature(),# Feature 17: Submitting Information to Email
            self.abnormal_url_feature(),            # Feature 18: Abnormal URL
            self.website_forwarding_feature(),      # Feature 19: Website Forwarding
            self.status_bar_customization_feature(),# Feature 20: Status Bar Customization
            self.disabling_right_click_feature(),   # Feature 21: Disabling Right Click
            self.using_popup_window_feature(),      # Feature 22: Using Pop-up Window
            self.iframe_redirection_feature(),      # Feature 23: IFrame Redirection
            self.age_of_domain_feature(),           # Feature 24: Age of Domain
            self.dns_record_feature(),              # Feature 25: DNS Record
            self.website_traffic_feature(),         # Feature 26: Website Traffic
            self.pagerank_feature(),                # Feature 27: PageRank
            self.google_index_feature(),            # Feature 28: Google Index
            self.number_of_links_pointing_to_page_feature(),  # Feature 29: Number of Links Pointing to Page
            self.statistical_reports_based_feature()# Feature 30: Statistical-Reports Based Feature

            # Add more feature method calls here as needed
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
            'url_length_feature',
            'uses_tinyurl',
            'has_at_symbol',
            'has_multiple_slashes',
            'has_hyphen_in_domain',
            'count_subdomains',
            'check_https_cert',
            'domain_registration_length',
            'favicon_external',
            'uses_non_standard_port',
            'has_https_token_in_domain',
            'request_url_feature',
            'anchor_url_feature',
            'links_in_tags_feature',
            'server_form_handler_feature',
            'submitting_info_to_email_feature',
            'abnormal_url_feature',
            'website_forwarding_feature',
            'status_bar_customization_feature',
            'disabling_right_click_feature',
            'using_popup_window_feature',
            'iframe_redirection_feature',
            'age_of_domain_feature',
            'dns_record_feature',
            'website_traffic_feature',
            'pagerank_feature',
            'google_index_feature',
            'number_of_links_pointing_to_page_feature',
            'statistical_reports_based_feature'
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
        print(len(all_features))
        print(f"URL: {args.url}")
        print(parse_features(all_features))
        prediction = predict(all_features)
        print(f"Prediction: {prediction[0]}, Probability: {prediction[1]*100}")
    except ValueError as e:
        print(f"Unable to extract features: {e}")