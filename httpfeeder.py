from httpfeeder import RealTimeTCPServer, PCAPReader, logger, interceptor_logger
import argparse
import logging
import sys


def main():
    parser = argparse.ArgumentParser(
        description="""HTTPFeeder processes captured HTTP traffic and forwards it to a user-defined HTTP proxy (e.g., Burp Suite).
It spins up a local intermediary proxy, which should be configured as the upstream proxy in your chosen HTTP proxy.
This setup ensures that real HTTP requests and responses are visible and inspectable within your proxy tool.
HTTPFeeder is primarily designed to work alongside ecapture's event capture, or to analyze existing PcapNG/EK files.

Architecture for the Realtime TCP Server mode: ecapture -> :8079 (HTTPFeeder TCP server) -> :8080 (Burp Suite HTTP proxy) -> :8081 (HTTPFeeder intermediary HTTP proxy)
Architecture for the PcapNG/EK Reader mode: HTTPFeeder PcapNG/EK reader -> :8080 (Burp Suite HTTP proxy) -> :8081 (HTTPFeeder intermediary HTTP proxy)""",
        epilog="""Example usage: python %(prog)s -m realtime -p http://127.0.0.1:8080
               python %(prog)s -m pcap -p http://127.0.0.1:8080 -f http_output.ek""",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        '-m', '--mode',
        type=str,
        default='realtime',
        required=True,
        help="""Mode of operation:
    "realtime" (RealtimeTCPServer): Starts a TCP server for eCapture to connect to, using the flag --eventaddr=tcp://<hostname>:<port> (e.g., --eventaddr=tcp://127.0.0.1:8079).
    "pcap" (PCAPReader): Parses an Elasticsearch-Kibana (EK) file, derived from a PcapNG file, containing cleartext HTTP traffic, such as one generated using eCapture's pcap mode."""
    )

    parser.add_argument(
        '-p', '--proxy',
        type=str,
        required=True,
        help='proxy address where the requests should be sent to (e.g., Burp Suite) <protocol>://<hostname>:<port>(e.g., http://127.0.0.1:8080)'
    )

    # parser.add_argument(
    #     '-pp', '--proxy-port',
    #     type=int,
    #     required=True,
    #     help='port of the proxy the requests should be sent to (e.g., Burp Suite) (e.g.,: 8080)'
    # )

    parser.add_argument(
        '-ih', '--intermediate-proxy-hostname',
        type=str,
        default='127.0.0.1',
        help='hostname where the intermediate proxy should listen on (default: 127.0.0.1)'
    )

    parser.add_argument(
        '-ip', '--intermediate-proxy-port',
        type=int,
        default=8081,
        help='port where the intermediate proxy should listen on (default: 8081)'
    )

    parser.add_argument(
        '-th', '--tcp-event-server-hostname',
        type=str,
        default='0.0.0.0',
        help='hostname where the event server should listen on (default: 0.0.0.0) (for realtime mode)'
    )

    parser.add_argument(
        '-tp', '--tcp-event-server-port',
        type=int,
        default=8079,
        help='port where the event server should listen on (default: 8079) (for realtime mode)'
    )

    parser.add_argument(
        '-f', '--file',
        type=str,
        help="""Elasticsearch-Kibana (EK) newline-delimited JSON format file (.ek) to analyze. This file should only contain HTTP 0.9/1.0/1.1/2 traffic (for pcap mode).
This can be achieved by using tshark to process the PCAP file outputed by ecapure:
    tshark -r capture.pcapng -Y "http or http2 or quic" -T ek > http_output.ek"""
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='enable verbose output'
    )

    parser.add_argument(
        '-vv', '--vverbose',
        action='store_true',
        help='enable very verbose output'
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.vverbose:
        interceptor_logger.setLevel(logging.DEBUG)

    if args.mode == "pcap" and args.file == None:
        print("Error: PCAP mode needs to have the Elasticsearch-Kibana (EK) file to analyze specified. Please read the instructions on how to generate this file using -h/--help.")
        sys.exit(1)

    if args.mode == "realtime":
        server = RealTimeTCPServer()
        try:
            server.start()
        except KeyboardInterrupt:
            pass
        finally:
            server.stop()
    elif args.mode == "pcap":
        reader = PCAPReader()
        try:
            ret = reader.start()
            if ret != 0:
                sys.exit(1)
            reader.process_file(args.file)
        except KeyboardInterrupt:
            pass
        finally:
            reader.stop()
    else:
        print(
            f"Error: Mode {args.mode} invalid. Should be \"realtime\" or \"pcap\".")
        sys.exit(1)


if __name__ == "__main__":
    main()

# TODO: Implement HTTP/3 support

