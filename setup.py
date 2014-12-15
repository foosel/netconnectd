# coding=utf-8
#!/usr/bin/env python

from setuptools import setup, Command

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

EXTRAS_FOLDERS = [
    ('/etc/netconnectd', 0755),
    ('/etc/netconnectd/conf.d', 0755),
    ('/etc/netconnectd/conf.d/hostapd', 0755),
    ('/etc/netconnectd/conf.d/dnsmasq', 0755)
]

EXTRAS_FILES = [
    ('/etc/init.d/', [('extras/netconnectd.init', 'netconnectd', 0755)]),
    ('/etc/default/', [('extras/netconnectd.default', 'netconnectd', 0644)]),
    ('/etc/netconnectd/', [('extras/netconnectd.yaml', 'netconnectd.yaml', 0600)]),
    ('/etc/netconnectd/', [('extras/netconnectd.action', 'netconnectd.action', 0755)]),
    ('/etc/logrotate.d/', [('extras/netconnectd.logrotate', 'netconnectd', 0644)]),
]


def get_extra_tuple(entry):
    import os

    if isinstance(entry, (tuple, list)):
        if len(entry) == 2:
            path, mode = entry
            filename = os.path.basename(path)
        elif len(entry) == 3:
            path, filename, mode = entry
        elif len(entry) == 1:
            path = entry[0]
            filename = os.path.basename(path)
            mode = None
        else:
            return None

    else:
        path = entry
        filename = os.path.basename(path)
        mode = None

    return path, filename, mode


class InstallExtrasCommand(Command):
    description = "install extras like init scripts and config files"
    user_options = [("force", "F", "force overwriting files if they already exist")]

    def initialize_options(self):
        self.force = None

    def finalize_options(self):
        if self.force is None:
            self.force = False

    def run(self):
        global EXTRAS_FILES, EXTRAS_FOLDERS
        import shutil
        import os

        for folder, mode in EXTRAS_FOLDERS:
            try:
                if os.path.exists(folder):
                    os.chmod(folder, mode)
                else:
                    os.mkdir(folder, mode)
            except Exception as e:
                import sys

                print("Error while creating %s (%s), aborting" % (folder, e.message))
                sys.exit(-1)

        for target, files in EXTRAS_FILES:
            for entry in files:
                extra_tuple = get_extra_tuple(entry)
                if extra_tuple is None:
                    print("Can't parse entry for target %s, skipping it: %r" % (target, entry))
                    continue

                path, filename, mode = extra_tuple
                target_path = os.path.join(target, filename)

                path_exists = os.path.exists(target_path)
                if path_exists and not self.force:
                    print("Skipping copying %s to %s as it already exists, use --force to overwrite" % (path, target_path))
                    continue

                try:
                    shutil.copy(path, target_path)
                    if mode:
                        os.chmod(target_path, mode)
                        print("Copied %s to %s and changed mode to %o" % (path, target_path, mode))
                    else:
                        print("Copied %s to %s" % (path, target_path))
                except Exception as e:
                    if not path_exists and os.path.exists(target_path):
                        # we'll try to clean up again
                        try:
                            os.remove(target_path)
                        except:
                            pass

                    import sys
                    print("Error while copying %s to %s (%s), aborting" % (path, target_path, e.message))
                    sys.exit(-1)


class UninstallExtrasCommand(Command):
    description = "uninstall extras like init scripts and config files"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        global EXTRAS_FILES, EXTRAS_FOLDERS
        import os

        for target, files in EXTRAS_FILES:
            for entry in files:
                extra_tuple = get_extra_tuple(entry)
                if extra_tuple is None:
                    print("Can't parse entry for target %s, skipping it: %r" % (target, entry))

                path, filename, mode = extra_tuple
                target_path = os.path.join(target, filename)
                try:
                    os.remove(target_path)
                    print("Removed %s" % target_path)
                except Exception as e:
                    print("Error while deleting %s from %s (%s), please remove manually" % (filename, target, e.message))

        for folder, mode in EXTRAS_FOLDERS[::-1]:
            try:
                os.rmdir(folder)
            except Exception as e:
                print("Error while removing %s (%s), please remove manually" % (folder, e.message))


def get_cmdclass():
    cmdclass = versioneer.get_cmdclass()
    cmdclass.update({
        'install_extras': InstallExtrasCommand,
        'uninstall_extras': UninstallExtrasCommand
    })
    return cmdclass


def params():
    name = "netconnectd"
    version = versioneer.get_version()
    description = DESCRIPTION
    long_description = LONG_DESCRIPTION
    author = "Gina Haeussge"
    author_email = "osd@foosel.net"
    url = "http://github.com/foosel/netconnectd"
    license = "AGPLV3"
    cmdclass = get_cmdclass()

    packages = ["netconnectd"]
    zip_safe = False

    dependency_links = [
        "https://github.com/foosel/wifi/tarball/master#egg=wifi-1.0.1"
    ]
    install_requires = [
        "wifi==1.0.1",
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