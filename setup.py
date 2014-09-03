# coding=utf-8
#!/usr/bin/env python

from setuptools import setup

import versioneer
versioneer.VCS = 'git'
versioneer.versionfile_source = 'netconnectd/_version.py'
versioneer.versionfile_build = 'netconnectd/_version.py'
versioneer.tag_prefix = ''
versioneer.parentdir_prefix = ''
versioneer.lookupfile = '.versioneer-lookup'

DESCRIPTION = "A daemon for staying connected"
LONG_DESCRIPTION = """netconnectd is a small Python daemon for ensuring a
network connection on headless Linux devices such as e.g. a Raspberry Pi
or other single-PCB-computers without displays and input capabilities.

It detects whether the system is currently connected to another network
and if not opens up an access point to allow connecting directly to it.

It also supports control, wifi configuration and status queries via a
JSON-based protocol over a unix domain socket.
"""


def get_cmdclass():
        cmdclass = versioneer.get_cmdclass()
        return cmdclass


def params():
    name = "netconnectd"
    version = versioneer.get_version()
    description = DESCRIPTION
    long_description = LONG_DESCRIPTION
    author = "Gina Häußge"
    author_email = "osd@foosel.net"
    url = "http://github.com/foosel/netconnectd"
    license = "AGPLV3"
    cmdclass = get_cmdclass()

    packages = ["netconnectd"]
    zip_safe = False

    dependency_links = [
        "git+https://github.com/foosel/wifi.git#egg=wifi-1.0.0"
    ]
    install_requires = [
        "wifi==1.0.0",
        "PyYaml",
        "netaddr"
    ]

    entry_points = {
        "console_scripts": {
            "netconnectd = netconnectd:server",
            "netconnectcli = netconnectd:client"
        }
    }

    return locals()

setup(**params())