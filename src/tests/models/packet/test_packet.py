from datetime import UTC, datetime

from pcap_visualizer.models.layer import Ethernet, EthernetType, IPv4
from pcap_visualizer.models.packet.packet import Packet

TIMESTAMP = datetime(2026, 10, 10, 1, 13, 35, 456789, tzinfo=UTC)

def test_packet_creation():
	ethernet = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
	)

	packet = Packet(
		layer=ethernet,
		size=100,
		timestamp=TIMESTAMP
	)

	assert packet.layer == ethernet
	assert packet.size == 100
	assert packet.timestamp == TIMESTAMP

def test_str_returns_layer():
	packet = Packet(
			layer=Ethernet(
				source_mac="00:11:22:33:44:55",
				destination_mac="AA:BB:CC:DD:EE:FF",
				ether_type=EthernetType.IPV6,
			),
			size=100,
			timestamp=TIMESTAMP
		)

	result = str(packet)

	assert result == "Ethernet (100 bytes)"

def test_get_layer_returns_matching_layer():
	ethernet = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
	)

	packet = Packet(
		layer=ethernet,
		size=100,
		timestamp=TIMESTAMP
	)

	result = packet.get_layer(Ethernet)

	assert result is ethernet


def test_get_layer_returns_none_when_layer_is_missing():
	ethernet = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
	)

	packet = Packet(
		layer=ethernet,
		size=100,
		timestamp=TIMESTAMP
	)

	result = packet.get_layer(IPv4)

	assert result is None


def test_has_layer_returns_true_when_layer_exists():
	ethernet = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
	)

	packet = Packet(
		layer=ethernet,
		size=100,
		timestamp=TIMESTAMP
	)

	assert packet.has_layer(Ethernet) is True


def test_has_layer_returns_false_when_layer_is_missing():
	ethernet = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
	)

	packet = Packet(
		layer=ethernet,
		size=100,
		timestamp=TIMESTAMP
	)

	assert packet.has_layer(IPv4) is False