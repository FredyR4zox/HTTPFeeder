from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from mitmproxy import http
import asyncio
import traceback
from . import interceptor_logger


class MITMProxy:
    def __init__(self, listen_host, listen_port, header_name, proxy_connection_test_pair_id, data_sockets):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.header_name = header_name
        self.proxy_connection_test_pair_id = proxy_connection_test_pair_id
        self.data_sockets = data_sockets

        self.mitmproxy_dumpmaster = None

    async def run_mitmproxy(self):
        """Runs mitmproxy asynchronously."""
        options = Options(listen_host=self.listen_host,
                          listen_port=self.listen_port)
        self.mitmproxy_dumpmaster = DumpMaster(
            options, with_termlog=False, with_dumper=False)

        # Add custom addon
        self.mitmproxy_dumpmaster.addons.add(Interceptor(
            self.header_name, self.proxy_connection_test_pair_id, self.data_sockets))

        try:
            interceptor_logger.info("Starting up mitmproxy...")
            loop = asyncio.get_running_loop()
            await self.mitmproxy_dumpmaster.run()
        except Exception as e:
            interceptor_logger.error(f"mitmproxy stopped: {e}")

    def start(self):
        """Starts mitmproxy in a background thread with its own asyncio event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.run_mitmproxy())

    def stop(self):
        # Shutdown MITM Proxy
        if self.mitmproxy_dumpmaster:
            interceptor_logger.info("mitmproxy shutting down...")
            try:
                self.mitmproxy_dumpmaster.shutdown()
            except RuntimeError as e:
                interceptor_logger.error(
                    "Exception occurred. mitmproxy was already down...")


class Interceptor:
    def __init__(self, header_name, proxy_connection_test_pair_id, data_sockets):
        self.header_name = header_name
        self.proxy_connection_test_pair_id = proxy_connection_test_pair_id
        self.data_sockets = data_sockets

    def request(self, flow: http.HTTPFlow):
        if self.header_name not in flow.request.headers:
            interceptor_logger.info(
                f"Received request without {self.header_name} header. Sending real request and return real response.")
            return

        pair_id = str(flow.request.headers[self.header_name])

        interceptor_logger.info(
            f"Received request with Pair id {pair_id}")

        if pair_id == self.proxy_connection_test_pair_id:
            status = 200
            headers = {"Content-Type": "text/plain"}
            body = "This is a custom response from mitmproxy!"

            interceptor_logger.debug(
                f"Sending proxy testing response:\nStatus code: {status}\nHeaders: {headers}\nBody: {body}")
            flow.response = http.Response.make(
                status,
                body,
                headers
            )
        elif pair_id not in self.data_sockets:
            interceptor_logger.error(
                f"Pair ID {pair_id} does not exist... Returning empty response...")
            flow.response = http.Response.make(
                404,
                "mitmproxy error. Request/Response pair with Pair ID {pair_id} does not exist.",
                {"Content-Type": "text/plain"}
            )
        else:
            response = self.data_sockets[pair_id].response

            interceptor_logger.debug(
                f"Sending response with Pair ID {pair_id}:\nStatus code: {response.status}\nHeaders: {response.headers}\nBody: {response.body}")

            body = response.body
            if body is None:
                body = b''
            flow.response = http.Response.make(
                int(response.status),
                body,
                response.headers
            )

        interceptor_logger.info(
            f"Sending response with Pair ID {pair_id}")
