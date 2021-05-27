#!/usr/bin/python3
import os

__version__ = '1.0'

# Directory Mapping
root_dir, conf_file = os.path.split(os.path.abspath(__file__))
working_dir = root_dir + '/tmp'

# template files
wpa_supplicant_conf_location = working_dir + '/wpa_supplicant.conf'

# Settings
default_live_capture_window = 360
default_timeout = 30
default_bssid = '00:11:22:33:44:00'
supported_eap_methods = [
	'MD5',
	'PEAP'
]
default_eap_methods = 'PEAP'
