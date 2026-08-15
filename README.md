# PCAP Visualizer

A Python-based tool for analyzing and visualizing network traffic from PCAP files.

The goal is to create a visual representation of network communication, including:

- Devices and IP addresses
- TCP and UDP connections
- Ports and protocols
- Communication direction
- Network traffic between hosts

## Development

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```
Install the project in editable mode:
`python -m pip install -e .`

Run the application:
`python -m pcap_visualizer.main`

## TODOs:
**The TODOs section will be removed.**
All pending tasks and improvements are now tracked and managed through GitHub Issues.

Parsing: 
- [x] IPv4
    - [x] TCP
    - [x] UDP
- [x] IPv6
    - [x] TCP
    - [x] UDP
- [x] ARP
- [x] ICMP
- [(x)] ICMPv6
- [ ] DNS


## Ideas

- Visualize all IP addresses as nodes with connections between them
- Show connection count / traffic size as weighted arrows
- Show packet transmission in chronological order with animation (similar to Packet Tracer's Simulation Mode)
- Renaming of nodes
- Interactive node movement
