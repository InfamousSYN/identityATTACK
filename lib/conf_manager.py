#!/usr/bin/python3

import config
from lib.templates import eap_cnf

class wpa_supplicant_conf(object):
    path = config.wpa_supplicant_conf_location
    template = eap_cnf.wpa_supplicant_conf_template

    @classmethod
    def configure(cls, ssid, eap, identity, password):
        try:
            with open(cls.path, 'w') as fd:
                fd.write(cls.template.format(
                        ssid,
                        eap,
                        identity,
                        password
                    )
                )
            return 0
        except Exception as e:
            print('[!] Error: {}'.format(e))
            return 1
