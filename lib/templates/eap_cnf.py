#!/usr/bin/python3
# https://manpages.debian.org/experimental/wpasupplicant/wpa_supplicant.conf.5.en.html

wpa_supplicant_conf_template = '''
ctrl_interface=/var/run/wpa_supplicant
network={{
  ssid="{}"
  key_mgmt=WPA-EAP
  eap={}
  identity="{}"
  password="{}"
}}
'''

