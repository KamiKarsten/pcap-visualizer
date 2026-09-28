import pytest
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from pcap_visualizer.models import Ethernet, EthernetType
from pcap_visualizer.parsing import EthernetParser


def test_parse_returns_none_when_packet_has_no_ethernet_layer():
	packet = IP()

	result = EthernetParser.parse(packet)

	assert result is None

def test_parse_returns_ethernet_object_when_packet_has_ethernet_layer():
	packet = Ether(
		src="00:11:22:33:44:55",
		dst="00:11:22:33:44:66",
		type=0x0800
	)

	result = EthernetParser.parse(packet)

	assert result is not None
	assert isinstance(result, Ethernet)

	assert result.source_mac == "00:11:22:33:44:55"
	assert result.destination_mac == "00:11:22:33:44:66"
	assert result.ether_type == EthernetType.IPV4


@pytest.mark.parametrize(
	("scapy_ether_type", "expected_ether_type"),
	[
		(0x0800, EthernetType.IPV4),
		(0x86DD, EthernetType.IPV6),
		(0x0806, EthernetType.ARP),
	],
)
def test_parse_maps_ether_type(scapy_ether_type, expected_ether_type):
	packet = Ether(
		src="00:11:22:33:44:55",
		dst="00:11:22:33:44:66",
		type=scapy_ether_type
	)

	result = EthernetParser.parse(packet)

	assert result is not None
	assert result.ether_type == expected_ether_type