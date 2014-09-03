# netconnectd

netconnectd is a small daemon that ensures connectivity for single-PCB devices such as the Raspberry Pi where you don't 
always have the means to setup your network interfaces by hand.

It monitors your current link status by checking if there are any other systems reachable and if not fires up an access 
point (via hostapd and dnsmasq). Additionally it allows control and configuration via a unix domain socket and a command 
line client/JSON based command protocol that allows listing available wifi cells and configuring a wifi network to use 
instead of the AP in the future.

It is intended to be used as part of a connectivity solution, acting as the backend to a frontend e.g. in a web 
application running on the device.

## Setup

Install the hostapd and dnsmasq packages:

    sudo apt-get install hostapd dnsmasq

Before you continue that hostapd works with your wifi card/dongle! To test, create a file /tmp/hostapd.conf with the 
following contents:

    interface=wlan0
    driver=nl80211
    ssid=TestAP
    channel=3
    wpa=3
    wpa_passphrase=MySuperSecretPassphrase
    wpa_key_mgmt=WPA-PSK
    wpa_pairwise=TKIP CCMP
    rsn_pairwise=CCMP

Then run 

    sudo hostapd -dd /tmp/hostapd.conf

This should not show any errors but start up a new access point named "TestAP" and with passphrase 
"MySuperSecretPassphrase", verify that with a different wifi enabled device (e.g. mobile phone).

If you run into errors in this step, solve them first, e.g. by googling your wifi dongle plus "hostapd". You might need 
a custom version of hostapd (e.g. for the [Edimax EW-7811Un or other RTL8188 based cards](http://jenssegers.be/blog/43/Realtek-RTL8188-based-access-point-on-Raspberry-Pi)) 
or a custom driver.

Then install `netconnectd`

    cd
    git clone https://github.com/foosel/netconnectd
    sudo python setup.py install
    sudo python setup.py install_extras

Modify `/etc/netconnectd.yaml` to your liking (at least change the passphrase/psk of your AP, you might also have to 
change the interface names of your wifi and wired network interfaces and also -- if your machine is NOT running 
NetworkManager -- set `wifi > free` to `false`).

Last, start netconnectd:

    sudo service netconnectd start

Verify that the logfile looks ok-ish:

    less /var/log/netconnectd.log

and that it's indeed running (error handling of the start up script still needs to be improved):

    netconnectcli status

Congratulations, `netconnectd` is now running and should detect when you don't have any connection available, starting the AP mode to change that.

You can control the daemon via `netconnectcli`:

  * `netconnectcli status` displays the current status (which interfaces are connected, is the AP running, etc)
  * `netconnectcli start_ap` manually starts the AP
  * `netconnectcli stop_ap` manually stops the AP
  * `netconnectcli list_wifi` shows the wifi cells currently in range
  * `netconnectcli configure_wifi <ssid> <psk>` configures the wifi connection (`<ssid>` = the wifi's SSID, `<psk>` = the wifi's passphrase)
  * `netconnectcli select_wifi` manually brings up the wifi configuration

You can always get help with `netconnectcli --help` or `netconnectcli <command> --help` for specific commands.

If everything looks alright, configure the service so that it starts at boot up:

    sudo update-rc.d netconnectd defaults 98

