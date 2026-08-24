import pytest
from scapy.layers.l2 import ARP as ScapyARP
from scapy.layers.l2 import Ether

from pcap_visualizer.models import ARP, ARPOperation
from pcap_visualizer.parsing import ARPParser


def test_parse_returns_none_when_packet_has_no_arp_layer():
	packet = Ether()

	result = ARPParser.parse(packet)

	assert result is None

def test_parse_returns_arp_object_when_packet_has_arp_layer():
	packet = ScapyARP(
		psrc="192.168.0.1",
		hwsrc="00:11:22:33:44:55",
		pdst="192.168.0.2",
		hwdst="00:11:22:33:44:66",
		op=1,
	)

	result = ARPParser.parse(packet)

	assert result is not None
	assert isinstance(result, ARP)

	assert result.source_ip == "192.168.0.1"
	assert result.source_mac == "00:11:22:33:44:55"
	assert result.destination_ip == "192.168.0.2"
	assert result.destination_mac == "00:11:22:33:44:66"
	assert result.operation == ARPOperation.REQUEST

@pytest.mark.parametrize(
	("scapy_operation", "expected_operation"),
	[
		(1, ARPOperation.REQUEST),
		(2, ARPOperation.REPLY),
	],
)
def test_parse_maps_arp_operation(scapy_operation, expected_operation):
	packet = ScapyARP(
		psrc="192.168.0.1",
		hwsrc="00:11:22:33:44:55",
		pdst="192.168.0.2",
		hwdst="00:11:22:33:44:66",
		op=scapy_operation,
	)

	result = ARPParser.parse(packet)

	assert result is not None
	assert result.operation == expected_operation