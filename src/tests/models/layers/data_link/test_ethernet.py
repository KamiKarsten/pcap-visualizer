from pcap_visualizer.models.layers.data_link.ethernet import (
	Ethernet,
	EthernetType,
)


def test_ethernet_creation():
	ethernet = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
	)

	assert ethernet.source_mac == "00:11:22:33:44:55"
	assert ethernet.destination_mac == "AA:BB:CC:DD:EE:FF"
	assert ethernet.ether_type == EthernetType.IPV4

def test_ethernet_type_values():
    assert EthernetType.IPV4 == 0x0800
    assert EthernetType.ARP == 0x0806
    assert EthernetType.IPV6 == 0x086DD