from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from pcap_visualizer.extractor.information_extractor import InformationExtractor
from pcap_visualizer.mapping import PacketMapper
from pcap_visualizer.models.information import (
	AddressInfo,
	MacAddressInfo,
	PortInfo,
	ProtocolInfo,
)


def test_extract_information_from_scapy_packet():
	scapy_packet = (
		Ether(
			src="00:11:22:33:44:55",
			dst="AA:BB:CC:DD:EE:FF",
			type=0x0800,
		)
		/ IP(
			src="192.168.1.10",
			dst="192.168.1.20",
			ttl=64,
		)
		/ TCP(
			sport=54321,
			dport=443,
			flags="S",
			seq=1000,
			window=65535,
		)
	)

	packet = PacketMapper.map(scapy_packet)
	result = InformationExtractor.extract(packet)

	assert result == [
		MacAddressInfo(
			source="00:11:22:33:44:55",
			destination="AA:BB:CC:DD:EE:FF",
		),
		AddressInfo(
			source="192.168.1.10",
			destination="192.168.1.20",
		),
		PortInfo(
			source=54321,
			destination=443,
		),
		ProtocolInfo(protocol="TCP"),
	]