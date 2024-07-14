from mitmproxy import http
from mitmproxy import ctx
import re
import os

class ProxyAddon:
    def __init__(self):
        self.blocked_ips = self.load_blocked_ips()
        self.ad_domains = self.load_ad_domains()
        self.blocked_websites = self.load_blocked_websites()

    def load_blocked_ips(self):
        blocked_ips = set()
        try:
            with open('blocked_ips.txt', 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        blocked_ips.add(ip)
        except FileNotFoundError:
            ctx.log.warn("Blocked IPs file 'blocked_ips.txt' not found.")
        return blocked_ips

    def load_ad_domains(self):
        ad_domains = set()
        try:
            with open('ad_domains.txt', 'r') as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        ad_domains.add(domain)
        except FileNotFoundError:
            ctx.log.warn("Ad domains file 'ad_domains.txt' not found.")
        return ad_domains

    def load_blocked_websites(self):
        blocked_websites = set()
        try:
            with open('blocked_websites.txt', 'r') as f:
                for line in f:
                    website = line.strip()
                    if website:
                        blocked_websites.add(website)
        except FileNotFoundError:
            ctx.log.warn("Blocked websites file 'blocked_websites.txt' not found.")
        return blocked_websites

    def is_content_filtering_enabled(self):
        return os.path.exists("content_filtering_enabled.txt")
    
    def is_script_filter_enabled(self):
        return os.path.exists("script_filtering.txt")
    
    def is_image_filter_enabled(self):
        return os.path.exists("image_filtering.txt")
    
    def request(self, flow: http.HTTPFlow) -> None:
        client_ip = flow.client_conn.address[0]
        host = flow.request.host

        # Apply caching
        if self.flow_filter(host):
            flow.intercept()

        # Block by IP
        if client_ip in self.blocked_ips:
            flow.response = http.Response.make(
                403, b"Blocked IP address", {"Content-Type": "text/html"}
            )
            return

        # Block ads
        if host in self.ad_domains or any(re.search(pattern, host) for pattern in self.ad_regex_patterns):
            flow.response = http.Response.make(
                403, b"Blocked ad domain", {"Content-Type": "text/html"}
            )
            return

        # Block websites
        if host in self.blocked_websites:
            flow.response = http.Response.make(
                403, b"Blocked website", {"Content-Type": "text/html"}
            )
            return

    def response(self, flow: http.HTTPFlow) -> None:
        content_type = flow.response.headers.get("Content-Type", "")
        if "text/html" in content_type:
            if self.is_script_filter_enabled():
                # Remove <script> tags
                flow.response.text = re.sub(r'<script.*?>.*?</script>', '', flow.response.text, flags=re.DOTALL)
                flow.response.text = re.sub(r'<script.*?>', '<script type="javascript/blocked">', flow.response.text)
            if self.is_image_filter_enabled():
                # Remove <img> tags
                flow.response.text = re.sub(r'<img.*?>', '', flow.response.text, flags=re.DOTALL)

    @property
    def ad_regex_patterns(self):
        return [
            re.compile(r"(\.|^)googleadservices\.net$"),
            re.compile(r"(\.|^)googleads\.g\.doubleclick\.net$"),
            re.compile(r"(\.|^)googleadservices\.com$")
        ]

addons = [
    ProxyAddon()
]
