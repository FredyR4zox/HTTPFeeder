#!/usr/bin/env python3

import socket
import json
from typing import Dict, Any, Optional
import asyncio
import traceback
import threading
import re
import sys
from .utils import SocketPacket, parse_http_request, parse_http_response, extract_host_from_request, build_http2_request, build_http2_response, HTTPRequest, HTTPResponse, send_http_request_through_proxy, setup_proxy_connection
from . import logger


class RealTimeTCPServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8079, buffer_size: int = 16384):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.server_socket = None
        self.running = False
        self.client_socket = None
        self.data_sockets = {}
        self.proxy_protocol = "http"
        self.proxy_address = "127.0.0.1"
        self.proxy_port = 8080

        self.coms_default_protocol = "http"
        self.coms_default_port = 443

        self.mitmproxy_address = "127.0.0.1"
        self.mitmproxy_port = 8081
        self.mitmproxy = None
        self.mitmproxy_thread = None

        self.header_name = "HTTPFeeder-Pair-ID"
        self.proxy_connection_test_pair_id = "-1"

        self.http2_request_problems = ["Not Supported HEADERS Frame with CONTINUATION frames\n",
                                       "Incorrect HPACK context, Please use PCAP mode to get correct header fields ...\n"]

        self.http2_response_problems = ["Incorrect HPACK context, Please use PCAP mode to get correct header fields ...\n",
                                        "Not Supported HEADERS Frame with CONTINUATION frames\n", "Partial entity body with gzip encoding ... "]

    def start(self):
        """Setup and start all necessary services, and check end-to-end connection."""
        logger.info(f"Setting up and starting all necessary services...")
        # logger.info(f"Setting up mitmproxy...")
        self.mitmproxy, self.mitmproxy_thread = setup_proxy_connection(
            self.mitmproxy_address, self.mitmproxy_port, self.header_name,
            self.proxy_connection_test_pair_id, self.data_sockets,
            self.proxy_protocol, self.proxy_address, self.proxy_port)

        if self.mitmproxy is None or self.mitmproxy_thread is None:
            return 1

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True

        logger.info(f"Server started on {self.host}:{self.port}")

        logger.info(f"Ready for connections!")

        try:
            while self.running:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"New connection from {client_address}")
                self.client_socket = client_socket
                self.handle_client(client_socket, client_address)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received...")

        return 0

    def stop(self):
        """Stop the servers and close all connections."""
        self.running = False

        # Close all client connections
        try:
            self.client_socket.close()
        except:
            pass

        # Close server socket
        if self.server_socket:
            logger.info("Server shutting down...")
            self.server_socket.close()

        # Shutdown MITM Proxy
        if self.mitmproxy:
            self.mitmproxy.stop()

        if self.mitmproxy_thread:
            self.mitmproxy_thread.join()

        logger.info("HTTPFeeder stopped")

    def handle_client(self, client_socket: socket.socket, client_address: tuple):
        buffer = b""

        while self.running:
            try:
                data = client_socket.recv(self.buffer_size)
                if not data:
                    logger.info(f"Connection closed by {client_address}")
                    break

                # Add received data to buffer
                buffer += data
                # try:
                #     buffer += data
                # except UnicodeDecodeError as e:
                #     logger.error(f"Unicode error: {e}. Continuing reading")
                #     print(data)
                #     print(data[16370:16390])
                #     time.sleep(60)
                #     sys.exit(1)

                while True:
                    # Process complete JSON objects from the buffer
                    buffer, progress = self.process_network_buffer(buffer)

                    if progress == False:
                        break

                # print(buffer)
            # except socket.timeout as e:
            #     logger.error(f"Socket timeout {client_address}: {str(e)}")
            except Exception as e:
                logger.error(
                    f"Error handling client {client_address}: {str(e)}")
                logger.error(traceback.format_exc())
                break

        client_socket.close()

    def process_network_buffer(self, buffer: str) -> str:
        """Process the buffer to extract and handle complete JSON objects.

        Args:
            buffer: Current string buffer containing received data

        Returns:
            Updated buffer with processed JSONs removed
        """
        index = buffer.find(b"\n")
        if index == -1:
            logger.debug("Newline not found. Continuing receiving data...")
            return buffer, False

        # Extract and process the JSON
        json_str = buffer[:index]
        # print(json_str)

        try:
            json_obj = json.loads(json_str, strict=False)
            asyncio.run(self.handle_json(json_obj))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")

        buffer = buffer[index+1:]
        return buffer, True

        # # Keep processing until we can't find any more complete JSONs
        # while True:
        #     try:
        #         # Try to find a complete JSON in the buffer
        #         # This is a simple approach - for more complex implementations,
        #         # you might need a more sophisticated JSON stream parser
        #         json_end = 0
        #         json_start = buffer.find('{')

        #         if json_start == -1:
        #             # No JSON start found, clear non-JSON content
        #             return ""

        #         # Parse the JSON by tracking braces
        #         brace_count = 0
        #         in_string = False
        #         escape_next = False

        #         for i in range(json_start, len(buffer)):
        #             char = buffer[i]

        #             # Handle string escape sequences
        #             if in_string:
        #                 if escape_next:
        #                     escape_next = False
        #                 elif char == '\\':
        #                     escape_next = True
        #                 elif char == '"':
        #                     in_string = False
        #             else:
        #                 if char == '"':
        #                     in_string = True
        #                 elif char == '{':
        #                     brace_count += 1
        #                 elif char == '}':
        #                     brace_count -= 1

        #                     # If we've found the end of a JSON object
        #                     if brace_count == 0:
        #                         json_end = i + 1
        #                         break

        #         if json_end == 0:
        #             # No complete JSON found yet
        #             return buffer

        #         # Extract and process the JSON
        #         json_str = buffer[json_start:json_end]
        #         # print(json_str)
        #         try:
        #             json_obj = json.loads(json_str, strict=False)
        #             asyncio.run(self.handle_json(json_obj))
        #         except json.JSONDecodeError as e:
        #             logger.error(f"Failed to parse JSON: {e}")

        #     except Exception as e:
        #         logger.error(f"Error processing buffer: {str(e)}")
        #         logger.debug(traceback.format_exc())

        #     finally:
        #         # Remove the processed JSON from the buffer
        #         buffer = buffer[json_end:]
        #         return buffer

    async def handle_json(self, json_obj: Dict[str, Any]):
        """Handle a received JSON object.

        Args:
            json_obj: The parsed JSON object
        """
        # logger.debug(f"Received JSON from {client_address}: {json_obj}")

        header = json_obj["message"].split('\n', 1)[0]
        data = json_obj["message"].split('\n', 1)[1]

        request_type = header.split(',')[1].split(':')[1]
        pair_id = header.split('_')[1]
        # pair_id = header.split(':')[1].split('_')[0]

        # logger.debug(
        #     f"Received payload from {client_address}:\n{header}\n{data}")

        if request_type == "HTTPRequest":
            host, method, path, http_version, headers, body = parse_http_request(
                data)

            request = HTTPRequest(self.coms_default_protocol, host,
                                  self.coms_default_port, method, path, http_version, headers, body)

            self.data_sockets[pair_id] = SocketPacket(request, None)

            logger.info(
                f"Received request for {request.host}:{request.port} - {request.method} {request.path} {request.http_version}. PairID: {pair_id}")
            logger.debug(request)

        elif request_type == "HTTPResponse":
            if pair_id not in self.data_sockets:
                logger.error(
                    f"Received response without a matching request. PairID: {pair_id}")
                return

            request = self.data_sockets[pair_id].request

            status, headers, body = parse_http_response(data)

            response = HTTPResponse(
                status, headers, body)
            self.data_sockets[pair_id].response = response

            logger.info(
                f"Received response for {request.host}:{request.port} - {request.method} {request.path} {request.http_version}. PairID: {pair_id}")
            logger.debug(response)

        elif request_type == "HTTP2Request":
            if pair_id not in self.data_sockets:
                self.data_sockets[pair_id] = SocketPacket(None, None)

            request = ""

            headers = re.findall(r"header field .*", data)

            request = request + "\n".join(headers) + "\n\n"

            match = re.findall(
                r'Frame Type\t=>\tDATA\nFrame StreamID\t=>\t[0-9]+\nFrame Length\t=>\t[0-9]+\n(.*)\n', data)

            if match:
                for m in match:
                    if m not in self.http2_request_problems:
                        request = request + m

            match = re.findall(
                r"Merged Data Frame, StreamID\t=>\t[0-9]+\nMerged Data Frame, Final Length\t=>\t[0-9]+\n\n(.*)\n", data)

            if match:
                request = request + "\n".join(match)

            try:
                host, method, path, headers, body = build_http2_request(
                    request)
            except Exception as e:
                logger.error(f"Error building request: {e}. PairID: {pair_id}")
                return

            request = HTTPRequest(self.coms_default_protocol, host,
                                  self.coms_default_port, method, path, "HTTP/2", headers, body)

            self.data_sockets[pair_id].request = request

            logger.info(
                f"Received request for {request.host}:{request.port} - {request.method} {request.path} {request.http_version}. PairID: {pair_id}")
            logger.debug(request)

        elif request_type == "HTTP2Response":
            if pair_id not in self.data_sockets:
                logger.error(
                    f"Received response without a matching request. Probably HTTP/2 auxiliary frames. PairID: {pair_id}")
                return
            # if pair_id not in self.data_sockets:
            #     self.data_sockets[pair_id] = SocketPacket(None, None)
            # TIrar isto dps de dar debug

            request = self.data_sockets[pair_id].request

            response = ""

            headers = re.findall(r"header field .*", data)

            response = response + "\n".join(headers) + "\n\n"

            match = re.findall(
                r'Frame Type\t=>\tDATA\nFrame StreamID\t=>\t[0-9]+\nFrame Length\t=>\t[0-9]+\n(.*)\n', data)

            if match:
                for m in match:
                    if m not in self.http2_response_problems:
                        response = response + m

            match = re.findall(
                r"Merged Data Frame, StreamID\t=>\t[0-9]+\nMerged Data Frame, Final Length\t=>\t[0-9]+\n\n(.*)\n", data)

            if match:
                response = response + "\n".join(match)

            try:
                status, headers, body = build_http2_response(response)
            except Exception as e:
                logger.error(
                    f"Error building response: {e}. PairID: {pair_id}")
                return

            response = HTTPResponse(status, headers, body)
            self.data_sockets[pair_id].response = response

            # logger.debug(
            #     f"Built the following HTTP/2 response:\nStatus: {status}\nHeaders: {headers}\nBody: {body}")
            # Quando der debug, descomentar em baixo e eliminar em cima
            logger.info(
                f"Received response for {request.host}:{request.port} - {request.method} {request.path} {request.http_version}. PairID: {pair_id}")
            logger.debug(response)

            # quando esta função dá erro e retorna, ele nao dá update ao buffer acho eu

        if request_type == "HTTPResponse" or request_type == "HTTP2Response":
            request = self.data_sockets[pair_id].request

            if request.host == None:
                logger.error(
                    f"Couldn't find host. Not sending request. PairID: {pair_id}")
                return

            logger.info(
                f"Sending request to proxy: {request.host}:{request.port}{request.path}. PairID: {pair_id}")
            await send_http_request_through_proxy(request.protocol, request.host, request.port, request.method, request.path, request.http_version, request.headers, request.body, self.header_name, pair_id, self.proxy_address, self.proxy_port)

            logger.info("Successfully received response from proxy")
            # logger.info(
            #     f"Received response for {request.host}:{request.port}{request.path}. PairID: {pair_id}")

            del self.data_sockets[pair_id]
