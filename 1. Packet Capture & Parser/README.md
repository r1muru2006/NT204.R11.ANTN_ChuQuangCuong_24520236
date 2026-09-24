# Packet Capture & Parser

## Support Features
### Packet Capture
- Live capture from a network interface.
- Importing and processing packets from a PCAP file.

#### Live Capture
Using library `Scapy` in python to allow the selection of a network interface and capture packets directly.  
Usage:
```
python main.py --interface eth0
python main.py --interface wlan0
```

#### PCAP Import
The program can read packets from a PCAP file and feed them into the same parsing pipeline used for live traffic.  
Usage:
```
python main.py --pcap test.pcap
```

