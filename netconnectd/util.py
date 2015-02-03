from __future__ import (print_function, absolute_import)

import argparse
import subprocess
import yaml
import os


common_arguments = argparse.ArgumentParser(add_help=False)
common_arguments.add_argument("-a", "--address", type=str, help="Address of Unix Domain Socket used for communication")
common_arguments.add_argument("-c", "--config", type=str, help="Location of config file to use")


def has_link():
    link = False
    reachable_devs = set()

    output = subprocess.check_output(['/sbin/ip', 'neigh', 'show'])

    lines = output.split('\n')
    for line in lines:
        split_line = line.split()

        if not len(split_line) == 6:
            continue
        ip, dev_str, dev, addr_str, addr, state = split_line

        if not state.lower() in ['incomplete', 'failed', 'none']:
            link = True
            reachable_devs.add(dev)

    return link, reachable_devs


class InvalidConfig(Exception):
    pass


default_config = dict(
    socket="/var/run/netconnectd.sock",
    interfaces=dict(
        wifi=None,
        wired=None
    ),
    link_monitor=dict(
        enabled=True,
        max_link_down=3,
        interval=10
    ),
    ap=dict(
        name="netconnectd_ap",
        driver="nl80211",
        ssid=None,
        psk=None,
        channel=3,
        ip="10.250.250.1",
        network="10.250.250.0/24",
        range=("10.250.250.100", "10.250.250.200"),
        domain=None,
        forwarding_to_wired=False
    ),
    wifi=dict(
        name="netconnectd_wifi",
        free=False,
        kill=False,
    ),
    paths=dict(
        hostapd="/usr/sbin/hostapd",
        hostapd_conf="/etc/hostapd/conf.d",
        dnsmasq="/usr/sbin/dnsmasq",
        dnsmasq_conf="/etc/dnsmasq.conf.d",
        interfaces="/etc/network/interfaces"
    )
)


def parse_configfile(configfile):
    if not os.path.exists(configfile):
        return None

    mandatory = ("interface.wifi", "ap.ssid")

    try:
        with open(configfile, "r") as f:
            config = yaml.safe_load(f)
    except:
        raise InvalidConfig("error while loading config from file")

    def merge_config(default, config, mandatory, prefix=None):
        result = dict()
        for k, v in default.items():
            result[k] = v

            prefixed_key = "%s.%s" % (prefix, k) if prefix else k
            if isinstance(v, dict):
                result[k] = merge_config(v, config[k] if k in config else dict(), mandatory, prefixed_key)
            else:
                if k in config:
                    result[k] = config[k]

            if result[k] is None and prefixed_key in mandatory:
                raise InvalidConfig("mandatory key %s is missing" % k)
        return result

    return merge_config(default_config, config, mandatory)



