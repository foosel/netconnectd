from __future__ import (print_function, absolute_import)

import argparse

from netconnectd.protocol import (StartApMessage, StopApMessage, ListWifiMessage, ConfigureWifiMessage,
                                  SelectWifiMessage, ForgetWifiMessage, ResetMessage, StatusMessage, Response)
from netconnectd.util import (common_arguments, parse_configfile, InvalidConfig, default_config)


def client_start_ap(address, args):
    client_send_message(address, StartApMessage())


def client_stop_ap(address, args):
    client_send_message(address, StopApMessage())


def client_list_wifi(address, args):
    client_send_message(address, ListWifiMessage(force=args.force))


def client_configure_wifi(address, args):
    client_send_message(address, ConfigureWifiMessage(ssid=args.ssid, psk=args.psk, force=args.force))


def client_select_wifi(address, args):
    client_send_message(address, SelectWifiMessage())


def client_forget_wifi(address, args):
    client_send_message(address, ForgetWifiMessage())


def client_reset(address, args):
    client_send_message(address, ResetMessage())


def client_status(address, args):
    client_send_message(address, StatusMessage())


def client_send_message(address, message):
    if message is None:
        return

    import socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(address)
    try:
        sock.sendall(str(message) + '\x00')
        buffer = []
        while True:
            chunk = sock.recv(16)
            if chunk:
                buffer.append(chunk)
                if chunk.endswith('\x00'):
                    break

        data = ''.join(buffer).strip()[:-1]

        response = Response.from_str(data.strip())
        if response:

            def print_result(result, sep='\t', indent=0):
                if isinstance(result, dict):
                    for key, value in result.items():
                        print(sep * indent + str(key) + ':')
                        print_result(value, sep=sep, indent=indent + 1)
                elif isinstance(result, (tuple, list)):
                    print(sep * indent + '[')
                    for v in result:
                        print_result(v, sep=sep, indent=indent + 1)
                    print(sep * indent + ']')
                else:
                    print(sep * (indent) + str(result))

            print("{type}:".format(type=response.__class__.__name__))
            print_result(response.content, sep='  ', indent=1)
    finally:
        sock.close()


def client():
    parser = argparse.ArgumentParser(parents=[common_arguments])

    subparsers = parser.add_subparsers(help="Client commands", dest="command")

    # version parser
    subparser = subparsers.add_parser("version", help="Display version information and exit")

    # start_ap parser
    subparser = subparsers.add_parser("start_ap", help="Starts the access point")
    subparser.set_defaults(func=client_start_ap)

    # stop_ap parser
    subparser = subparsers.add_parser("stop_ap", help="Stops the access point")
    subparser.set_defaults(func=client_stop_ap)

    # list_wifi parser
    subparser = subparsers.add_parser("list_wifi", help="Lists available access points")
    subparser.add_argument("-F", "--force", action="store_true", help="Force refresh of the wifi list, might cause a short disconnect if currently in AP mode")
    subparser.set_defaults(func=client_list_wifi)

    # configure_wifi parser
    subparser = subparsers.add_parser("configure_wifi", help="Configure WIFI access")
    subparser.add_argument("-F", "--force", action="store_true", help="Force refresh of the wifi list while configuring, might cause a short disconnect if currently in AP mode")
    subparser.add_argument("ssid", help="SSID of WIFI")
    subparser.add_argument("psk", default=None, help="Passphrase for WIFI")
    subparser.set_defaults(func=client_configure_wifi)

    # select_wifi parser
    subparser = subparsers.add_parser("select_wifi", help="Select WIFI connection")
    subparser.set_defaults(func=client_select_wifi)

    # forget_wifi parser
    subparser = subparsers.add_parser("forget_wifi", help="Forgets the configured WIFI connection")
    subparser.set_defaults(func=client_forget_wifi)

    # reset parser
    subparser = subparsers.add_parser("reset", help="Factory resets the daemon")
    subparser.set_defaults(func=client_reset)

    # status parser
    subparser = subparsers.add_parser("status", help="Display netconnectd status")
    subparser.set_defaults(func=client_status)

    args = parser.parse_args()

    if args.command == "version":
        from ._version import get_versions
        import sys
        print("Version: %s" % get_versions()["version"])
        sys.exit(0)

    import copy
    config = copy.deepcopy(default_config)

    if args.config:
        try:
            config = parse_configfile(args.config)
        except InvalidConfig as e:
            parser.error("Invalid configuration file: " + e.message)

    if args.address:
        config["socket"] = args.address

    if config["socket"] is None:
        parser.error("Socket address is missing, please provide either via --address or via --configfile")

    args.func(config["socket"], args)

if __name__ == "__main__":
    client()