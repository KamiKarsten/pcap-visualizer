import pytest
from scapy.layers.inet import IP as ScapyIP
from scapy.layers.inet6 import IPv6 as ScapyIPv6

from pcap_visualizer.models import IPv6, IPv6NextHeader
from pcap_visualizer.parsing import IPv6Parser


def test_parse_returns_none_when_packet_has_no_ipv6_layer():
	packet = ScapyIP()

	result = IPv6Parser.parse(packet)

	assert result is None

def test_parse_returns_ipv6_object_when_packet_has_ipv6_layer():
	packet = ScapyIPv6(
		src="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		dst="2001:0db8:85a3:0000:0000:8a2e:0370:7335",
		hlim=64,
		nh=6
	)

	result = IPv6Parser.parse(packet)

	assert result is not None
	assert isinstance(result, IPv6)

	assert result.source_ip == "2001:db8:85a3::8a2e:370:7334"
	assert result.destination_ip == "2001:db8:85a3::8a2e:370:7335"
	assert result.hop_limit == 64
	assert result.next_header == IPv6NextHeader.TCP

@pytest.mark.parametrize(
	"next_header_value, expected_next_header",
	[
		(6, IPv6NextHeader.TCP),
		(17, IPv6NextHeader.UDP),
		(58, IPv6NextHeader.ICMPv6)
	]
)
def test_parse_correctly_maps_next_header_values(next_header_value, expected_next_header):
	packet = ScapyIPv6(
		src="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		dst="2001:0db8:85a3:0000:0000:8a2e:0370:7335",
		hlim=64,
		nh=next_header_value
	)

	result = IPv6Parser.parse(packet)

	assert result is not None
	assert result.next_header == expected_next_header