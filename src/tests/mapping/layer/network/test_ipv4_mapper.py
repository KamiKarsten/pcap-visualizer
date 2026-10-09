import pytest
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP as ScapyIP

from pcap_visualizer.mapping import IPv4Mapper
from pcap_visualizer.models import IPv4, IPv4Protocol


def test_map_returns_none_when_packet_has_no_ipv4_layer():
	packet = ICMP()

	result = IPv4Mapper.map(packet)

	assert result is None

def test_map_returns_ipv4_object_when_packet_has_ipv4_layer():
	packet = ScapyIP(
		src="192.168.0.1",
		dst="192.168.0.2",
		ttl=64,
		proto=6
	)

	result = IPv4Mapper.map(packet)

	assert result is not None
	assert isinstance(result, IPv4)
	assert result.source_ip == "192.168.0.1"
	assert result.destination_ip == "192.168.0.2"
	assert result.ttl == 64
	assert result.protocol == IPv4Protocol.TCP

@pytest.mark.parametrize(
	("protocol_number", "expected_protocol"),
	[
		(1, IPv4Protocol.ICMP),
		(6, IPv4Protocol.TCP),
		(17, IPv4Protocol.UDP),
	],
)
def test_map_returns_ipv4_protocol(protocol_number, expected_protocol):
	packet = ScapyIP(
		src="192.168.0.1",
		dst="192.168.0.2",
		ttl=64,
		proto=protocol_number
	)

	result = IPv4Mapper.map(packet)

	assert result.protocol == expected_protocol