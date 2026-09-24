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

## Packet parsing and processing pipeline

Raw Packet (Live / PCAP)  
 ↓  
Network Parser (IPv4)  
 ↓  
Transport Parser (TCP / UDP)  
 ↓  
Application Protocol Detector (Payload + Port)  
 ↓  
Application Protocol Parser (HTTP / DNS / SMTP)  
 ↓  
Normalized IDS Event (Dict / JSON)  

## Logging
Format: JSON Lines. Example:  
```
{"packet_id":13,"timestamp":1790053524.2435367,"src_ip":null,"dst_ip":null,"ip_version":null,"transport":null,...}
{"packet_id":14,"timestamp":1790053524.2435775,"src_ip":null,"dst_ip":null,"ip_version":null,"transport":null,...}
{"packet_id":15,"timestamp":1790053533.3940134,"src_ip":"172.29.169.202","dst_ip":"99.86.18.61","ip_version":4,"transport":"TCP",...}
{"packet_id":16,"timestamp":1790053533.4711788,"src_ip":"172.29.169.202","dst_ip":"99.86.18.61","ip_version":4,"transport":"TCP",...}
```

### The fields that can exist in a JSON line:  
**General Information**
- `packet_id`: Unique ID of the packet.
- `timestamp`: Packet capture timestamp.
- `length`: Total length of the captured packet in bytes.  

**Network Layer — IPv4**
- `src_ip`: Source IPv4 address.
- `dst_ip`: Destination IPv4 address.
- `ip_protocol`: IP protocol number (e.g. `6` for TCP, `17` for UDP).
- `ttl`: IPv4 Time To Live value.  

**Transport Layer — TCP / UDP**
- `transport_protocol`: Transport protocol, such as `TCP` or `UDP`.
- `src_port`: Source port.
- `dst_port`: Destination port.  

**TCP-specific fields**
- `tcp_flags`: TCP flags such as `SYN`, `ACK`, `PSH`, `FIN`, `RST`.
- `seq`: TCP sequence number.
- `ack`: TCP acknowledgment number.
- `window`: TCP window size.  

**UDP-specific fields**
- `udp_length`: UDP datagram length.