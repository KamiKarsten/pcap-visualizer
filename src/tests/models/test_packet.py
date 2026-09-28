from pcap_visualizer.models.layers.data_link.ethernet import (
    Ethernet,
    EthernetType,
)
from pcap_visualizer.models.layers.network.ipv4 import IPv4
from pcap_visualizer.models.packet import Packet


def test_packet_creation():
	ethernet = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
	)

	packet = Packet(
		layers=[ethernet],
		size=100,
	)

	assert packet.layers == [ethernet]
	assert packet.size == 100


def test_get_layer_returns_matching_layer():
	ethernet = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
	)

	packet = Packet(
		layers=[ethernet],
		size=100,
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
		layers=[ethernet],
		size=100,
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
		layers=[ethernet],
		size=100,
	)

	assert packet.has_layer(Ethernet) is True


def test_has_layer_returns_false_when_layer_is_missing():
	ethernet = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
	)

	packet = Packet(
		layers=[ethernet],
		size=100,
	)

	assert packet.has_layer(IPv4) is False