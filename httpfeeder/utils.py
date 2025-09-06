import re
import socket
import httpx
from . import logger
import time
from .mitm_proxy import MITMProxy
import threading
import traceback
import asyncio
import ast
import gzip


class HTTPRequest:
    def __init__(self, protocol, host, port, method, path, http_version, headers, body):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.method = method
        self.path = path
        self.http_version = http_version
        self.headers = headers
        self.body = body

    def add_body(self, body):
        if self.body is None:
            self.body = body
        else:
            self.body = self.body + body

    def __str__(self):
        return f"Host: {self.host}\nPort: {self.port}\nMethod: {self.method}\nPath: {self.path}\nHTTP version: {self.http_version}\nHeaders: {self.headers}\nBody: {self.body}"


class HTTPResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def add_body(self, body):
        if self.body is None:
            self.body = body
        else:
            self.body = self.body + body

    def __str__(self):
        return f"Status: {self.status}\nHeaders: {self.headers}\nBody: {self.body}"


class SocketPacket:
    def __init__(self, request=None, response=None, client=None):
        self.request = request
        self.response = response
        self.client = client

    def __str__(self):
        return f"Request: {self.request}\nResponse: {self.response}"


def parse_http_request(request):
    # Parse the raw request
    headers = {}
    body = None

    host = extract_host_from_request(request)

    lines = request.split("\r\n")
    request_line = lines[0].split()
    method = request_line[0]
    path = request_line[1]
    http_version = request_line[2]

    # Extract headers
    # First empty line separates headers and body
    body_index = lines.index('')
    header_lines = lines[1:body_index]

    for line in header_lines:
        match = re.match(r"([^:]+): (.+)", line)
        if match:
            headers[match.group(1)] = match.group(2)

    # Remaining lines are the body
    extracted_body = "\r\n".join(lines[body_index + 1:])

    if extracted_body != "":
        body = extracted_body
        if extracted_body[0] == 'b':
            body = ast.literal_eval(extracted_body)

    return host, method, path, http_version, headers, body


def parse_http_response(raw_response):
    """Parses a raw HTTP response string into status code, headers, and body."""
    headers = {}
    body = None

    lines = raw_response.split("\r\n")

    # Extract status code (e.g., HTTP/1.1 200 OK -> 200)
    status_line = lines[0]
    match = re.match(r"HTTP/\d\.\d (\d+)", status_line)
    status_code = int(match.group(1)) if match else 200

    # Extract headers
    index = 1
    while index < len(lines) and lines[index]:
        key, value = lines[index].split(":", 1)
        headers[key.strip()] = value.strip()
        index += 1

    # Extract body (after the blank line)
    extracted_body = "\r\n".join(lines[index+1:])
    if extracted_body != "":
        body = extracted_body
        if extracted_body[0] == 'b':
            body = ast.literal_eval(extracted_body)

    return status_code, headers, body


def build_http2_request(request):
    host = None
    verb = None
    path = None
    headers = {}
    body = None

    match = re.search(r"header field \":authority\" = \"(.*)\"", request)
    if match == None:
        raise Exception(
            "header field \":authority\" (host) was not found in the request")
    host = match.group(1)

    match = re.search(r"header field \":method\" = \"(.*)\"", request)
    if match == None:
        raise Exception(
            "header field \":method\" was not found in the request")
    verb = match.group(1)

    match = re.search(r"header field \":path\" = \"(.*)\"", request)
    if match == None:
        raise Exception("header field \":path\" was not found in the request")
    path = match.group(1)

    headers_without_pseudo_headers = re.findall(
        r"header field \"[^:].*\" = \".*\"", request)

    for header in headers_without_pseudo_headers:
        match = re.match(r"header field \"(.*)\" = \"(.*)\"", header)
        if match == None:
            raise Exception(f"header field could not be matched: {header}")

        headers[match.group(1)] = match.group(2)

    extracted_body = request.split("\n\n")[1]
    if extracted_body != "":
        body = extracted_body
        if extracted_body[0] == 'b':
            body = ast.literal_eval(extracted_body)

    return host, verb, path, headers, body


def build_http2_response(response):
    status = None
    headers = {}
    body = None

    # print(response)

    match = re.search(r"header field \":status\" = \"(.*)\"", response)
    if match == None:
        raise Exception(
            "header field \":status\" was not found in the response")
    status = match.group(1)

    headers_without_pseudo_headers = re.findall(
        r"header field \"[^:].*\" = \".*\"", response)

    for header in headers_without_pseudo_headers:
        match = re.match(r"header field \"(.*)\" = \"(.*)\"", header)
        if match == None:
            raise Exception(f"header field could not be matched: {header}")

        headers[match.group(1)] = match.group(2)

    extracted_body = response.split("\n\n")[1]
    if extracted_body != "":
        body = extracted_body
        if extracted_body[0] == 'b':
            body = ast.literal_eval(extracted_body)

    return status, headers, body


def extract_host_from_request(request):
    m = re.search(r'Host: (.+?)\r\n', request)
    if m:
        return m.group(1)

    return None


async def send_http_request_through_proxy(protocol, host, port, method, path, http_version, headers, body, pair_id_header_name, pair_id_header_value, proxy_address, proxy_port):
    headers[pair_id_header_name] = pair_id_header_value

    # host = headers.get("Host")
    url = f"{protocol}://{host}:{port}{path}"

    proxy = f"http://{proxy_address}:{proxy_port}"

    # Map HTTP version string to httpx format
    http_versions_1 = {
        "HTTP/1"
        "HTTP/1.0",
        "HTTP/1.1"
    }
    http_versions_2 = {
        "HTTP/2"
    }

    http1 = False
    http2 = False

    if http_version in http_versions_1:
        http1 = True
    elif http_version in http_versions_2:
        http2 = True

    if "Content-Encoding" in headers:
        if headers["Content-Encoding"] == "gzip":
            if type(body) is bytes:
                body = gzip.compress(body)
            else:
                body = gzip.compress(bytes(body, 'utf-8'))

    if "Content-Length" in headers:
        del headers["Content-Length"]

    # Send the request using httpx with the specified HTTP version and proxy
    with httpx.Client(proxy=proxy, http1=http1, http2=http2, verify=False) as client:
        del client.headers["user-agent"]
        del client.headers["accept-encoding"]

        try:
            response = client.request(
                method, url, headers=headers, content=body, timeout=60)
        except httpx.ReadTimeout as e:
            raise Exception(
                f"Timeout error when sending request to proxy: {e}")
            logger.error(f"Timeout error when sending request to proxy: {e}")
            return None

        if "<title>Burp Suite Professional</title>" in response.text:
            raise Exception(f"Error in Burp Proxy.")

    return response


def setup_proxy_connection(mitmproxy_address, mitmproxy_port, header_name, proxy_connection_test_pair_id, data_sockets, proxy_protocol, proxy_address, proxy_port):
    """Setup and start all necessary services, and check end-to-end connection."""
    logger.info(f"Setting up and starting all necessary services...")
    # logger.info(f"Setting up mitmproxy...")
    mitmproxy = MITMProxy(mitmproxy_address, mitmproxy_port,
                          header_name, proxy_connection_test_pair_id, data_sockets)

    mitmproxy_thread = threading.Thread(
        target=mitmproxy.start, args=[], daemon=False)
    mitmproxy_thread.start()

    time.sleep(1)
    if mitmproxy_thread.is_alive() == False:
        logger.error(f"mitmproxy failed to execute.")
        logger.info(f"Exiting...")
        mitmproxy.stop()
        return None, None

    logger.info(f"mitmproxy is running!")

    logger.info(
        f"Testing connection to proxy at {proxy_protocol}://{proxy_address}:{proxy_port}")
    try:
        response = asyncio.run(send_http_request_through_proxy("https", "www.google.com", 443, "GET", "/",  "HTTP/1.1",
                                                               {"Host": "www.google.com", "Accept": "*/*"}, None, header_name, proxy_connection_test_pair_id, proxy_address, proxy_port))

        if response.status_code != 200 or response.text != "This is a custom response from mitmproxy!":
            logger.error(
                f"Connection to proxy was sucessfull but the whole chain is not setup. Probably Burp Suite is not configured to use the mitmproxy upstream proxy.")
            logger.debug(
                f"Received the status code {response.status} with the following text: {response.text}")
            logger.info("Exiting...")
            mitmproxy.stop()
            return None, None
    except Exception as e:
        logger.error(f"Proxy connection test failed: {e}")
        logger.debug(traceback.format_exc())
        logger.info(f"Exiting...")
        mitmproxy.stop()
        return None, None

    logger.info(
        f"Proxy connection test was successful and whole chain is setup.")

    return mitmproxy, mitmproxy_thread
