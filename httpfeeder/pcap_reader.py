import logging
import json
from .utils import SocketPacket, parse_http_request, parse_http_response, extract_host_from_request, build_http2_request, build_http2_response, HTTPRequest, HTTPResponse, send_http_request_through_proxy, setup_proxy_connection
import traceback
import threading
from . import logger
import asyncio


class PCAPReader:
    def __init__(self):
        self.running = False
        self.data_sockets = {}
        self.proxy_protocol = "http"
        self.proxy_address = "127.0.0.1"
        self.proxy_port = 8080

        self.mitmproxy_address = "127.0.0.1"
        self.mitmproxy_port = 8081
        self.mitmproxy = None
        self.mitmproxy_thread = None

        self.header_name = "HTTPFeeder-Pair-ID"
        self.proxy_connection_test_pair_id = "-1"

    def start(self):
        logger.info(f"Setting up and starting all necessary services...")

        self.mitmproxy, self.mitmproxy_thread = setup_proxy_connection(
            self.mitmproxy_address, self.mitmproxy_port, self.header_name,
            self.proxy_connection_test_pair_id, self.data_sockets,
            self.proxy_protocol, self.proxy_address, self.proxy_port)

        if self.mitmproxy is None or self.mitmproxy_thread is None:
            return 1

        self.running = True

        logger.info(f"Ready for connections!")
        return 0

    def stop(self):
        """Stop the servers and close all connections."""
        self.running = False

        # Shutdown MITM Proxy
        if self.mitmproxy:
            self.mitmproxy.stop()

        if self.mitmproxy_thread:
            self.mitmproxy_thread.join()

        logger.info("HTTPFeeder stopped")

    def process_file(self, file):
        line_num = 0
        with open(file) as f:
            try:
                for line in f:
                    line_num += 1

                    try:
                        packet = json.loads(line)
                    except json.JSONDecodeError:
                        logger.error(
                            f"Invalid JSON on line ({line_num}). Skipping...")
                        continue

                    if 'layers' not in packet:
                        logger.debug(
                            f"JSON on line ({line_num}) does not containen the \"layers\" object. Skipping...")
                        continue

                    layers = packet["layers"]

                    http = None
                    http2 = None
                    if 'http' in layers:
                        http = layers['http']
                    elif 'http2' in layers:
                        http2 = layers['http2']
                    else:
                        logger.debug(
                            f"JSON on line ({line_num}) does not container the \"http\" or \"http2\" object. Skipping...")
                        continue

                    frame_number = layers["frame"]["frame_frame_number"]
                    logger.debug(
                        f"Processing frame {frame_number} on line {line_num}")

                    if http:
                        is_request = False
                        is_response = False

                        if "http_http_request" in http:
                            is_request = True
                        elif "http_http_response" in http:
                            is_response = True
                        else:
                            logger.error(
                                f"Frame {frame_number} on line {line_num} is neither request or response. Skipping...")
                            continue

                        if is_request:
                            pair_id = frame_number

                            request = f'{http["http_http_request_method"]} {http["http_http_request_uri"]} {http["http_http_request_version"]}\r\n{''.join(http["http_http_request_line"])}\r\n'

                            if "http_http_file_data" in http:
                                body = http["http_http_file_data"]
                                request = f'{request}{bytes.fromhex(body.replace(':', ''))}'

                            host, method, path, http_version, headers, body = parse_http_request(
                                request)

                            protocol = None
                            if 'tcp:http' in layers["frame"]["frame_frame_protocols"]:
                                protocol = "http"
                            elif 'tls:http' in layers["frame"]["frame_frame_protocols"]:
                                protocol = "https"
                            elif 'tls:http2' in layers["frame"]["frame_frame_protocols"]:
                                protocol = "https"
                            else:
                                logger.error(
                                    f"Frame {frame_number} on line {line_num} is neither HTTP or HTTPS: {layers["frame"]["frame_frame_protocols"]}. Skipping...")
                                continue

                            request = HTTPRequest(
                                protocol, host, layers["tcp"]["tcp_tcp_dstport"], method, path, http_version, headers, body)

                            self.data_sockets[pair_id] = SocketPacket(
                                request, None)

                            logger.info(
                                f"Received request for {request.host}:{request.port} - {request.method} {request.path} {request.http_version}. PairID: {pair_id}")
                            logger.debug(request)

                        elif is_response:
                            pair_id = http["http_http_request_in"]

                            if pair_id not in self.data_sockets:
                                logger.error(
                                    f"Received response without a matching request. PairID: {pair_id}")
                                continue

                            request = self.data_sockets[pair_id].request

                            response = f'{http["http_http_response_version"]} {http["http_http_response_code"]} {http["http_http_response_phrase"]}\r\n{''.join(http["http_http_response_line"])}\r\n'

                            if "http_http_file_data" in http:
                                body = http["http_http_file_data"]
                                response = f'{response}{bytes.fromhex(body.replace(':', ''))}'

                            status_code, headers, body = parse_http_response(
                                response)

                            response = HTTPResponse(status_code, headers, body)

                            self.data_sockets[pair_id].response = response

                            logger.info(
                                f"Received response for {request.host}:{request.port} - {request.method} {request.path} {request.http_version}. PairID: {pair_id}")
                            logger.debug(response)

                    elif http2:
                        if isinstance(http2, dict):
                            http2 = [http2]

                        for http2_frame in http2:
                            is_request = False
                            is_response = False

                            # HTTP2 frame types
                            # 0x0: DATA frame (this contains the body, possibly chunked or binary)
                            # 0x1: HEADERS frame
                            # 0x4: SETTINGS
                            # 0x8: WINDOW_UPDATES
                            try:
                                if http2_frame["http2_http2_type"] != "0" and http2_frame["http2_http2_type"] != "1":
                                    logger.debug(
                                        f"SETTINGS or WINDOW_UPDATE frame: {http2_frame["http2_http2_type"]}. Skipping...")
                                    continue
                            except KeyError as e:
                                logger.error(
                                    "No HTTP2 frame identified. Skipping...")
                                continue

                            pair_id = self.get_stream_key(packet)
                            ip_src = layers["ip"]["ip_ip_src"]
                            port_src = layers["tcp"]["tcp_tcp_srcport"]

                            # 0x1: HEADERS frame
                            if http2_frame["http2_http2_type"] == "1":
                                if ":method" in http2_frame["http2_http2_header_name"]:
                                    is_request = True
                                elif ":status" in http2_frame["http2_http2_header_name"]:
                                    is_response = True
                                else:
                                    logger.error(
                                        "Packet is neither request or response.")
                                    continue

                                if is_request:
                                    values = dict(zip(
                                        http2_frame["http2_http2_header_name"], http2_frame["http2_http2_header_value"]))

                                    request = ""
                                    for key, val in values.items():
                                        request = f'{request}header field \"{key}\" = \"{val}\"\n'
                                    request = request + "\n"

                                    try:
                                        host, method, path, headers, body = build_http2_request(
                                            request)
                                    except Exception as e:
                                        logger.error(
                                            f"Error building request: {e}. PairID: {pair_id}")
                                        continue

                                    request = HTTPRequest(
                                        "https", host, layers["tcp"]["tcp_tcp_dstport"], method, path, "HTTP/2", headers, body)

                                    self.data_sockets[pair_id] = SocketPacket(
                                        request, None, (ip_src, port_src))

                                    logger.info(
                                        f"Received request HEADERS frame for {request.host}:{request.port} - {request.method} {request.path} {request.http_version}. PairID: {pair_id}")
                                    logger.debug(request)

                                elif is_response:
                                    if pair_id not in self.data_sockets:
                                        logger.error(
                                            f"Received response without a matching request. PairID: {pair_id}")
                                        continue

                                    request = self.data_sockets[pair_id].request

                                    values = dict(zip(
                                        http2_frame["http2_http2_header_name"], http2_frame["http2_http2_header_value"]))

                                    response = ""
                                    for key, val in values.items():
                                        response = f'{response}header field \"{key}\" = \"{val}\"\n'
                                    response = response + "\n"

                                    try:
                                        status, headers, body = build_http2_response(
                                            response)
                                    except Exception as e:
                                        logger.error(
                                            f"Error building response: {e}. PairID: {pair_id}")
                                        continue

                                    response = HTTPResponse(
                                        status, headers, body)

                                    self.data_sockets[pair_id].response = response

                                    logger.info(
                                        f"Received response HEADERS frame for {request.host}:{request.port} - {request.method} {request.path} {request.http_version}. PairID: {pair_id}")
                                    logger.debug(response)

                            # 0x0: DATA frame
                            elif http2_frame["http2_http2_type"] == "0":
                                if self.data_sockets[pair_id].client == (ip_src, port_src):
                                    is_request = True
                                else:
                                    is_response = True

                                if is_request:
                                    request = self.data_sockets[pair_id].request

                                    body = bytes.fromhex(
                                        http2_frame["http2_http2_data_data"].replace(':', ''))

                                    self.data_sockets[pair_id].request.add_body(
                                        body)

                                    logger.info(
                                        f"Received request DATA frame for {request.host}:{request.port} - {request.method} {request.path} {request.http_version}. PairID: {pair_id}")
                                    logger.debug(request)

                                elif is_response:
                                    if pair_id not in self.data_sockets:
                                        logger.error(
                                            f"Received response without a matching request. PairID: {pair_id}")
                                        continue

                                    request = self.data_sockets[pair_id].request

                                    body = bytes.fromhex(
                                        http2_frame["http2_http2_data_data"].replace(':', ''))

                                    self.data_sockets[pair_id].response.add_body(
                                        body)

                                    logger.info(
                                        f"Received response DATA frame for {request.host}:{request.port} - {request.method} {request.path} {request.http_version}. PairID: {pair_id}")
                                    logger.debug(request)

                                else:
                                    logger.error(
                                        "Packet is neither request or response.")
                                    continue

                    if is_response:
                        if http2:
                            if http2_frame["http2_http2_flags_end_stream"] == False:
                                continue

                        request = self.data_sockets[pair_id].request

                        if request.host == None:
                            logger.error(
                                f"Couldn't find host. Not sending request. PairID: {pair_id}")
                            continue

                        logger.info(
                            f"Sending request to proxy: {request.host}:{request.port}{request.path}. PairID: {pair_id}")
                        asyncio.run(send_http_request_through_proxy(request.protocol, request.host, request.port, request.method, request.path,
                                    request.http_version, request.headers, request.body, self.header_name, pair_id, self.proxy_address, self.proxy_port))

                        logger.info(
                            "Successfully received response from proxy")
                        # logger.debug(
                        #     f"Received response for {request.host}:{request.port}{request.path}. PairID: {pair_id}")

                        del self.data_sockets[pair_id]
            except KeyboardInterrupt:
                logger.info("Shutdown signal received...")

    def get_stream_key(self, pkt):
        layers = pkt["layers"]
        ip_src = layers["ip"]["ip_ip_src"]
        ip_dst = layers["ip"]["ip_ip_dst"]
        port_src = layers["tcp"]["tcp_tcp_srcport"]
        port_dst = layers["tcp"]["tcp_tcp_dstport"]
        stream_id = layers["http2"]["http2_http2_streamid"]

        if None in (ip_src, port_src, ip_dst, port_dst, stream_id):
            return None

        # print(ip_src)
        # print(ip_dst)
        # print(port_src)
        # print(port_dst)
        # print(stream_id)

        # Make connection direction-agnostic by sorting IP:port pairs
        conn_tuple = sorted([ip_src, port_src, ip_dst, port_dst, stream_id])
        conn_id = ':'.join(conn_tuple)

        # print(conn_id)

        return conn_id
