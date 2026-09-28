from pcap_visualizer.models.layers.network.ipv6 import (
	IPv6,
	IPv6NextHeader,
)


def test_ipv6_creation():
	ipv6 = IPv6(
		source_ip="::1",
		destination_ip="fe80::",
		hop_limit=64,
		next_header=IPv6NextHeader.TCP,
	)

	assert ipv6.source_ip == "::1"
	assert ipv6.destination_ip == "fe80::"
	assert ipv6.hop_limit == 64
	assert ipv6.next_header == IPv6NextHeader.TCP

def test_ipv6_next_header_values():
	assert IPv6NextHeader.TCP == 6
	assert IPv6NextHeader.UDP == 17