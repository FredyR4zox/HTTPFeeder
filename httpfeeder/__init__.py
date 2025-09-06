import logging

# Configure logging
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Configure logging for main program
logger = logging.getLogger("HTTPFeeder")
logger.setLevel(logging.INFO)
logger.propagate = False

log_handler = logging.StreamHandler()
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log_handler.setFormatter(formatter)

logger.addHandler(log_handler)

# Configure logging for mitmproxy addon
interceptor_logger = logging.getLogger("MITMInterceptor")
interceptor_logger.setLevel(logging.INFO)
interceptor_logger.propagate = False

interceptor_log_handler = logging.StreamHandler()
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
interceptor_log_handler.setFormatter(formatter)

interceptor_logger.addHandler(interceptor_log_handler)

from httpfeeder.realtimetcpserver import RealTimeTCPServer
from httpfeeder.pcap_reader import PCAPReader
