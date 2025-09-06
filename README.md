# HTTPFeeder

HTTPFeeder is a HTTP traffic tool that processes captured HTTP traffic and mirrors it to user-defined HTTP proxies such as Burp Suite. Acting as an intermediary, it mirrors HTTP requests and responses, making them visible and fully inspectable in your chosen proxy tool.

## Overview

HTTPFeeder creates a bridge between captured network traffic and HTTP analysis tools by spinning up a local intermediary proxy. This setup ensures that HTTP traffic can be properly analyzed, modified, and inspected using familiar proxy tools, without playing it back to the original destination server. To achieve this, HTTPFeeder spins up an HTTP proxy, which the user-defined proxy must use as its upstream. Matching HTTP responses are then returned through this chain, effectively mirroring the captured traffic in the user’s proxy.

### Key Features

- **Real-time Traffic Processing**: Connects directly with eCapture for live HTTP traffic mirroring
- **PCAP File Analysis**: Processes existing PcapNG files converted to Elasticsearch-Kibana (EK) format
- **Proxy Integration**: Seamlessly forwards traffic to tools like Burp Suite, OWASP ZAP, or custom proxies
- **Multiple HTTP Versions**: Supports HTTP 0.9, 1.0, 1.1, and 2 protocols (HTTP/3 is in the works)
- **Flexible Architecture**: Configurable hostnames and ports for different network setups

## Installation

### Prerequisites

- Python 3.7+
- eCapture (for realtime mode or to generate PcapNG file)
- tshark/Wireshark (for PCAP processing)
- HTTP proxy tool (e.g., Burp Suite, OWASP ZAP)

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd httpfeeder
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Command Line Options

```
usage: httpfeeder.py [-h] -m MODE -p PROXY [-ih INTERMEDIATE_PROXY_HOSTNAME] [-ip INTERMEDIATE_PROXY_PORT] [-th TCP_EVENT_SERVER_HOSTNAME] [-tp TCP_EVENT_SERVER_PORT] [-f FILE] [-v] [-vv]

Required Arguments:
  -m, --mode {realtime,pcap}    Mode of operation
  -p, --proxy PROXY_URL         Proxy address (e.g., http://127.0.0.1:8080)

Optional Arguments:
  -ih, --intermediate-proxy-hostname HOST
                                Intermediate proxy hostname (default: 127.0.0.1)
  -ip, --intermediate-proxy-port PORT  
                                Intermediate proxy port (default: 8081)
  -th, --tcp-event-server-hostname HOST
                                Event server hostname (default: 0.0.0.0) (for realtime mode)
  -tp, --tcp-event-server-port PORT
                                Event server port (default: 8079) (for realtime mode)
  -f, --file FILE               EK file for PCAP mode
  -v, --verbose                 Enable verbose output
  -vv, --vverbose               Enable very verbose output
  -h, --help                    Show help message
```

### Mode Details

#### Realtime Mode

##### Architecture
```
ecapture -> :8079 (HTTPFeeder TCP server) -> :8080 (Burp Suite HTTP proxy) -> :8081 (HTTPFeeder intermediary HTTP proxy)
```

Starts a TCP server that eCapture can connect to for live traffic mirroring:
```bash
python httpfeeder.py -m realtime -p http://127.0.0.1:8080
```

Use with eCapture:
```bash
./ecapture tls -m text --eventaddr=tcp://127.0.0.1:8079
```

#### PCAP Mode

##### Architecture
```
HTTPFeeder PCAP reader -> :8080 (Burp Suite HTTP proxy) -> :8081 (HTTPFeeder intermediary HTTP proxy)
```

Analyzes existing PcapNG files that have been converted to EK format:
```bash
python httpfeeder.py -m pcap -p http://127.0.0.1:8080 -f http_output.ek
```

##### Creating EK Files from PcapNG

Extract HTTP packets from the PcapNG file and convert it to the required EK format using tshark:
```bash
tshark -r ecapture.pcapng -Y "http or http2 or quic" -T ek > http_output.ek
```

## Examples

### Basic Realtime Analysis with Burp Suite

1. Start your HTTP proxy tool (e.g., Burp Suite) on port 8080 and configure it to use HTTPFeeder's intermediary proxy (default: 127.0.0.1:8081) as an HTTP upstream proxy (e.g., Burp -> Settings -> Network -> Connections -> Upstream Proxy Servers)
2. Run HTTPFeeder in realtime mode (it will spin up a TCP server on port 0.0.0.0:8079 by default):
```bash
python httpfeeder.py -m realtime -p http://127.0.0.1:8080
```
3. Start eCapture with the event address pointing to HTTPFeeder:
```bash
./ecapture tls -m text --eventaddr=tcp://127.0.0.1:8079
```

### Analyzing Existing PcapNG Files

1. Run eCapture or other program that captures plaintext HTTP traffic into a PcapNG file
```bash
./ecapture tls -m pcap -i wlan0 --pcapfile=capture.pcapng
```
2. Extract HTTP packets from the PcapNG file and convert it to EK format:
```bash
tshark -r capture.pcapng -Y "http or http2 or quic" -T ek > http_traffic.ek
```
3. Start your HTTP proxy tool (e.g., Burp Suite) on port 8080 and configure it to use HTTPFeeder's intermediary proxy (default: 127.0.0.1:8081) as an HTTP upstream proxy (e.g., Burp -> Settings -> Network -> Connections -> Upstream Proxy Servers)
4. Run HTTPFeeder in PCAP mode and specify the EK file:
```bash
python httpfeeder.py -m pcap -p http://127.0.0.1:8080 -f http_traffic.ek
```

### Custom Network Configuration

For different network setups, you can customize the listening addresses:
```bash
python httpfeeder.py \
  -m realtime \
  -p http://127.0.0.1:8080 \
  -ih 127.0.0.1 \
  -ip 8081 \
  -th 0.0.0.0 \
  -tp 8079 \
  -v
```

## Configuration

### Default Ports
- **TCP Event Server**: 8079 (for eCapture events)
- **Target Proxy**: 8080 (your HTTP proxy tool (e.g., Burp Suite))
- **Intermediary Proxy**: 8081 (HTTPFeeder's Man-in-the-Middle proxy)

## Troubleshooting

### Common Issues

**"PCAP mode needs to have the EK file specified"**
- Ensure you provide the `-f` flag with a valid EK file when using PCAP mode

**Connection refused errors**
- Verify that your target proxy (e.g., Burp Suite) is running and listening on the specified port
- Check that the specified hostnames and ports are accessible

## Integration with other tools

### Custom Proxies
HTTPFeeder can forward to any HTTP proxy that accepts standard HTTP CONNECT requests.

## Support

For issues and questions:
- Create an issue in the project repository
- Check the troubleshooting section above
- Review the verbose logs for detailed error information

## ToDo
- Implement HTTP/3 support
