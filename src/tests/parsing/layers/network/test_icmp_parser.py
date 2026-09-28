import pytest
from scapy.layers.inet import ICMP as ScapyICMP
from scapy.layers.inet import IP

from pcap_visualizer.models import ICMP, ICMPType
from pcap_visualizer.parsing import ICMPParser


def test_parse_returns_none_when_packet_has_no_icmp_layer():
	packet = IP()

	result = ICMPParser.parse(packet)

	assert result is None

def test_parse_returns_icmp_object_when_packet_has_icmp_layer():
	packet = ScapyICMP(type=8, code=0)

	result = ICMPParser.parse(packet)

	assert result is not None
	assert isinstance(result, ICMP)

	assert result.type == ICMPType.ECHO_REQUEST
	assert result.code == 0

@pytest.mark.parametrize(
	("scapy_type", "expected_type"),
	[
		(3, ICMPType.DESTINATION_UNREACHABLE),
		(8, ICMPType.ECHO_REQUEST),
		(0, ICMPType.ECHO_REPLY),
	],
)
def test_parse_maps_icmp_type_and_code(scapy_type, expected_type):
	packet = ScapyICMP(
		type=scapy_type,
		code=0
	)

	result = ICMPParser.parse(packet)

	assert result.type == expected_type
