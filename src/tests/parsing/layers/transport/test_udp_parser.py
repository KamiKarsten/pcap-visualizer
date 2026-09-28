from scapy.layers.inet import IP
from scapy.layers.inet import UDP as ScapyUDP

from pcap_visualizer.models import UDP
from pcap_visualizer.parsing import UDPParser


def test_parse_returns_none_when_packet_has_no_udp_layer():
	packet = IP()

	result = UDPParser.parse(packet)

	assert result is None

def test_parse_returns_udp_object_when_packet_has_udp_layer():
	packet = ScapyUDP(
		sport = 1234,
		dport = 53,
		len = 123
	)

	result = UDPParser.parse(packet)

	assert result is not None
	assert isinstance(result, UDP)

	assert result.source_port == 1234
	assert result.destination_port == 53
	assert result.length == 123

