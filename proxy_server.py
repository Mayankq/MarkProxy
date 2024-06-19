import os
import socket
import ssl
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import tempfile
import select
from urllib.parse import urlparse
import re
import argparse
import logging
from collections import OrderedDict

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()  # This will keep logging to the console
    ]
)

logger = logging.getLogger(__name__)

class LRUCache:
    def __init__(self, capacity: int):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.file = 'cached_sites.txt'
        self.load_cache()

    def load_cache(self):
        if os.path.exists(self.file):
            with open(self.file, 'r') as f:
                for line in f:
                    url = line.strip()
                    self.cache[url] = None
            while len(self.cache) > self.capacity:
                self.cache.popitem(last=False)

    def save_cache(self):
        with open(self.file, 'w') as f:
            for url in self.cache.keys():
                f.write(f"{url}\n")

    def get(self, url: str):
        if url in self.cache:
            self.cache.move_to_end(url)
            return True
        return False

    def put(self, url: str):
        if url in self.cache:
            self.cache.move_to_end(url)
        else:
            if len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)
            self.cache[url] = None
        self.save_cache()
        print("Cached item")

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    ad_regex_patterns = [
        re.compile(r"(\.|^)googleadservices\.net$"),
        re.compile(r"(\.|^)googleads\.g\.doubleclick\.net$"),
        re.compile(r"(\.|^)googleadservices\.com$")
    ]

    def is_ad_domain(self, hostname):
        for pattern in self.ad_regex_patterns:
            if pattern.search(hostname):
                return True
        return hostname in self.ad_domains

    def __init__(self, *args, **kwargs):
        self.log_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.log_address = ('localhost', 9999)  # Set the logging server address and port
        self.blocked_ips_file = 'blocked_ips.txt'  # Adjust the file name if necessary
        self.blocked_ips = self.load_blocked_ips()  # Initialize blocked_ips attribute
        self.ad_domains_file = 'ad_domains.txt'  # File name for ad domains
        self.ad_domains = self.load_ad_domains()
        self.cache = LRUCache(20)  # Initialize the LRU cache with a capacity of 20
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        message = "%s - - [%s] %s\n" % (
            self.client_address[0],
            self.log_date_time_string(),
            format % args)
        
        # Send log message to the log receiver
        self.log_socket.sendto(message.encode('utf-8'), self.log_address)

    def load_ad_domains(self):
        ad_domains = set()
        try:
            with open(self.ad_domains_file, 'r') as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        ad_domains.add(domain)
        except FileNotFoundError:
            logger.warning(f"Ad domains file '{self.ad_domains_file}' not found.")
        return ad_domains

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD, TRACE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Expose-Headers', '*')
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Referrer-Policy', 'no-referrer')
        super().end_headers()

    def do_OPTIONS(self):
        # Handle CORS preflight requests
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD, TRACE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Expose-Headers', '*')
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()

    def do_CONNECT(self):
        hostname = self.path.split(':')[0]
        logger.debug(f"Received CONNECT request for {hostname}")

        if self.is_ad_domain(hostname):
            self.send_error(403, "Blocked ad domain")
            logger.debug(f"Blocked ad domain: {hostname}")
            self.connection.close()
            return

        cert_pem, key_pem = self.generate_cert(hostname)
        
        self.send_response(200, "Connection established")
        self.end_headers()

        with tempfile.NamedTemporaryFile(delete=False) as certfile, tempfile.NamedTemporaryFile(delete=False) as keyfile:
            certfile.write(cert_pem)
            keyfile.write(key_pem)
            certfile.flush()
            keyfile.flush()
            certfile_path = certfile.name
            keyfile_path = keyfile.name

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:RSA+AESGCM:RSA+CHACHA20')

            self.connection = context.wrap_socket(self.connection, server_side=True)
            logger.debug("SSL handshake with client succeeded")

            self.intercept_request()
        except Exception as e:
            logger.debug(f"Error during SSL handshake or interception: {e}")
        finally:
            os.remove(certfile_path)
            os.remove(keyfile_path)

    def intercept_request(self):
        try:
            hostname = self.path.split(':')[0]
            remote_socket = socket.create_connection((hostname, 443))
            
            context = ssl.create_default_context()
            remote_socket = context.wrap_socket(remote_socket, server_hostname=hostname)
            logger.debug(f"SSL handshake with {hostname} succeeded")

            self.connection.setblocking(0)
            remote_socket.setblocking(0)

            while True:
                read_ready, _, except_ready = select.select([self.connection, remote_socket], [], [self.connection, remote_socket], 1)

                if self.connection in read_ready:
                    try:
                        data = self.connection.recv(4096)
                        if data:
                            remote_socket.sendall(data)
                        else:
                            logger.debug("Client closed connection")
                            break
                    except ssl.SSLWantReadError:
                        continue
                    except ssl.SSLWantWriteError:
                        continue
                    except Exception as e:
                        logger.debug(f"Error reading from client: {e}")
                        break

                if remote_socket in read_ready:
                    try:
                        data = remote_socket.recv(4096)
                        if data:
                            self.connection.sendall(data)
                        else:
                            logger.debug("Remote server closed connection")
                            break
                    except ssl.SSLWantReadError:
                        continue
                    except ssl.SSLWantWriteError:
                        continue
                    except Exception as e:
                        logger.debug(f"Error reading from remote server: {e}")
                        break

                if self.connection in except_ready or remote_socket in except_ready:
                    logger.debug("Exception in sockets")
                    break

        except Exception as e:
            logger.debug(f"Error intercepting request: {e}")
        finally:
            remote_socket.close()
            self.connection.close()

    def generate_cert(self, common_name):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        san = x509.SubjectAlternativeName([x509.DNSName(common_name)])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.load_root_cert().subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            san, critical=False
        ).sign(self.load_root_key(), hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        return cert_pem, key_pem

    def load_root_key(self):
        with open('rootCA.key', 'rb') as f:
            root_key = serialization.load_pem_private_key(f.read(), password=None)
        return root_key
    
    def load_root_cert(self):
        with open('rootCA.pem', 'rb') as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
        return root_cert

    def forward_request(self):
        try:
            url = self.path
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            path = parsed_url.path or '/'
            query = parsed_url.query

            # Ad blocking
            if any(ad_domain in host for ad_domain in self.ad_domains):
                self.send_error(403, "Blocked ad domain")
                logger.debug(f"Blocked ad domain: {host}")
                return

            if query:
                path += '?' + query

            if ':' in host:
                hostname, port = host.split(':')
                port = int(port)
            else:
                hostname = host
                port = 443 if parsed_url.scheme == "https" else 80

            if self.is_ad_domain(hostname):
                self.send_error(403, "Request blocked by ad blocker")
                return

            client_ip = self.client_address[0]
            remote_ip = socket.gethostbyname(hostname)

            if client_ip in self.blocked_ips or remote_ip in self.blocked_ips:
                self.send_error(403, "Blocked IP address")
                logger.debug(f"Blocked request from/to IP: {client_ip} / {remote_ip}")
                return

            remote_socket = socket.create_connection((hostname, port))
            if parsed_url.scheme == "https":
                context = ssl.create_default_context()
                remote_socket = context.wrap_socket(remote_socket, server_hostname=hostname)

            # Forward the initial request line
            request_line = f"{self.command} {path} {self.request_version}\r\n"
            remote_socket.sendall(request_line.encode())
            logger.debug(f"Forwarded request line: {request_line.strip()}")

            # Forward headers
            for header in self.headers:
                header_line = f"{header}: {self.headers[header]}\r\n"
                remote_socket.sendall(header_line.encode())
                logger.debug(f"Forwarded header: {header_line.strip()}")
        
            remote_socket.sendall(b"\r\n")

            # Forward request body if present
            if self.command in ["POST", "PUT", "PATCH"]:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length:
                    body = self.rfile.read(content_length)
                    remote_socket.sendall(body)
                    logger.debug(f"Forwarded body: {body}")

            # Read and forward the response back to the client
            response = b""
            while True:
                chunk = remote_socket.recv(4096)
                if len(chunk) == 0:
                    break
                response += chunk

            # Disable scripts and images in the response
            response = self.disable_scripts_and_images(response)

            self.wfile.write(response)
            logger.debug(f"Received and forwarded response: {len(response)} bytes")
            self.cache.put(url)

            remote_socket.close()

            # Update the cache with the URL
        except Exception as e:
            self.send_error(500, f"Error forwarding request: {e}")
            logger.debug(f"Error forwarding request: {e}")

    def disable_scripts_and_images(self, response):
        content_type = self.headers.get('Content-Type', '')
        if 'text/html' in content_type:
            # Remove <script> tags
            response = re.sub(b'<script.*?>.*?</script>', b'', response, flags=re.DOTALL)
            response = re.sub(b'<script.*?>', b'<script type="javascript/blocked">', response)
            # Remove <img> tags
            response = re.sub(b'<img.*?>', b'', response, flags=re.DOTALL)
        return response

    def handle_upgrade_request(self):
        """Handle WebSocket Upgrade Requests"""
        try:
            url = self.path
            protocol, rest = url.split("://", 1)
            host, path = rest.split("/", 1)
            path = "/" + path

            if ':' in host:
                hostname, port = host.split(':')
                port = int(port)
            else:
                hostname = host
                port = 443 if protocol == "https" else 80

            remote_socket = socket.create_connection((hostname, port))
            if protocol == "https":
                context = ssl.create_default_context()
                remote_socket = context.wrap_socket(remote_socket, server_hostname=hostname)

            self.send_response(101, 'Switching Protocols')
            self.send_header('Connection', 'Upgrade')
            self.send_header('Upgrade', 'websocket')
            self.end_headers()

            remote_socket.sendall(f"{self.command} {path} {self.request_version}\r\n".encode())
            for header in self.headers:
                remote_socket.sendall(f"{header}: {self.headers[header]}\r\n".encode())
            remote_socket.sendall(b"\r\n")

            self.connection.setblocking(0)
            remote_socket.setblocking(0)

            while True:
                read_ready, _, except_ready = select.select([self.connection, remote_socket], [], [self.connection, remote_socket], 1)

                if self.connection in read_ready:
                    try:
                        data = self.connection.recv(4096)
                        if data:
                            remote_socket.sendall(data)
                        else:
                            logger.debug("Client closed connection")
                            break
                    except ssl.SSLWantReadError:
                        continue
                    except ssl.SSLWantWriteError:
                        continue
                    except Exception as e:
                        logger.debug(f"Error reading from client: {e}")
                        break

                if remote_socket in read_ready:
                    try:
                        data = remote_socket.recv(4096)
                        if data:
                            self.connection.sendall(data)
                        else:
                            logger.debug("Remote server closed connection")
                            break
                    except ssl.SSLWantReadError:
                        continue
                    except ssl.SSLWantWriteError:
                        continue
                    except Exception as e:
                        logger.debug(f"Error reading from remote server: {e}")
                        break

                if self.connection in except_ready or remote_socket in except_ready:
                    logger.debug("Exception in sockets")
                    break

        except Exception as e:
            logger.debug(f"Error handling WebSocket upgrade: {e}")
        finally:
            remote_socket.close()
            self.connection.close()

    def do_GET(self):
        if 'Upgrade' in self.headers and self.headers['Upgrade'].lower() == 'websocket':
            self.handle_upgrade_request()
        else:
            self.forward_request()

    def do_POST(self):
        self.forward_request()

    def do_PUT(self):
        self.forward_request()

    def do_DELETE(self):
        self.forward_request()

    def do_HEAD(self):
        self.forward_request()

    def do_PATCH(self):
        self.forward_request()

    def do_TRACE(self):
        self.forward_request()

    def load_blocked_ips(self):
        blocked_ips = set()
        try:
            with open(self.blocked_ips_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        blocked_ips.add(ip)
        except FileNotFoundError:
            logger.warning(f"Blocked IPs file '{self.blocked_ips_file}' not found.")
        return blocked_ips

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def start_proxy_server():
    global server
    server = ThreadedHTTPServer(('0.0.0.0', 8080), ProxyHTTPRequestHandler)
    logger.debug('Starting server on port 8080...')
    server.serve_forever()

def stop_proxy_server(server):
    logger.debug('Stopping server...')
    server.shutdown()
    server.server_close()
    logger.debug('Server stopped.')
