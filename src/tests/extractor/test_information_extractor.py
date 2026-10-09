from datetime import datetime

from pcap_visualizer.extractor.information_extractor import InformationExtractor
from pcap_visualizer.models import (
	TCP,
	Ethernet,
	EthernetType,
	IPv4,
	IPv4Protocol,
	Layer,
	Packet,
	TCPFlags,
)
from pcap_visualizer.models.information import (
	AddressInfo,
	MacAddressInfo,
	PortInfo,
	ProtocolInfo,
)


def test_extract_returns_empty_list_for_packet_without_layer():
	packet = Packet(
		layer=None,
		size=0,
		timestamp=datetime.now(),
	)

	result = InformationExtractor.extract(packet)

	assert result == []


def test_extract_returns_information_and_protocol_for_single_layer():
	packet = Packet(
		layer=Ethernet(
			source_mac="00:11:22:33:44:55",
			destination_mac="AA:BB:CC:DD:EE:FF",
			ether_type=EthernetType.IPV4,
		),
		size=64,
		timestamp=datetime.now(),
	)

	result = InformationExtractor.extract(packet)

	assert result == [
		MacAddressInfo(
			source="00:11:22:33:44:55",
			destination="AA:BB:CC:DD:EE:FF",
		),
		ProtocolInfo(protocol="Ethernet"),
	]


def test_extract_collects_information_from_layer_chain():
	tcp = TCP(
		source_port=54321,
		destination_port=443,
		sequence_number=1000,
		acknowledgment_number=2000,
		flags=TCPFlags.SYN,
		window=65535,
	)
	ipv4 = IPv4(
		source_ip="192.168.1.10",
		destination_ip="192.168.1.20",
		ttl=64,
		protocol=IPv4Protocol.TCP,
		payload=tcp,
	)
	ethernet = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
		payload=ipv4,
	)
	packet = Packet(
		layer=ethernet,
		size=100,
		timestamp=datetime.now(),
	)

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


def test_extract_continues_after_unsupported_layer():
	class UnsupportedLayer(Layer):
		pass

	tcp = TCP(
		source_port=12345,
		destination_port=80,
		sequence_number=1,
		acknowledgment_number=0,
		flags=TCPFlags.SYN,
		window=8192,
	)
	unsupported = UnsupportedLayer(payload=tcp)
	packet = Packet(
		layer=unsupported,
		size=64,
		timestamp=datetime.now(),
	)

	result = InformationExtractor.extract(packet)

	assert result == [
		PortInfo(
			source=12345,
			destination=80,
		),
		ProtocolInfo(protocol="TCP"),
	]