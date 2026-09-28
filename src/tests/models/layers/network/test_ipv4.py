from pcap_visualizer.models.layers.network.ipv4 import (
	IPv4,
	IPv4Protocol,
)


def test_ipv4_creation():
	ipv4 = IPv4(
		source_ip="127.0.0.1",
		destination_ip="192.168.0.1",
		ttl=64,
		protocol=IPv4Protocol.TCP,
	)

	assert ipv4.source_ip == "127.0.0.1"
	assert ipv4.destination_ip == "192.168.0.1"
	assert ipv4.ttl == 64
	assert ipv4.protocol == IPv4Protocol.TCP

def test_ipv4_protocol_values():
	assert IPv4Protocol.ICMP == 1
	assert IPv4Protocol.TCP == 6
	assert IPv4Protocol.UDP == 17