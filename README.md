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

## Program flow

1. Ingestion: PCAP files are read and parsed into Scapy packets.
2. Mapping: Scapy packets are mapped to custom protocol layer models.
3. Information Extraction: Protocol-specific extractors process the custom models and extract standardized information, such as MAC addresses, IP addresses, ports, and protocol identifiers.
4. Analysis: The extracted information provides a foundation for further analysis and visualization.

PCAP ingestion -> Scapy packets -> mapping to custom models -> information extraction via extractors.

## Ideas

- Visualize all IP addresses as nodes with connections between them
- Show connection count / traffic size as weighted arrows
- Show packet transmission in chronological order with animation (similar to Packet Tracer's Simulation Mode)
- Renaming of nodes
- Interactive node movement
