from pcap_visualizer.models.layers.data_link.arp import (
	ARP,
	ARPOperation,
)


def test_arp_creation():
	arp = ARP(
		source_ip="127.0.0.1",
		source_mac="00:11:22:33:44:55",
		destination_ip="192.168.0.1",
		destination_mac="AA:BB:CC:DD:EE:FF",
		operation=ARPOperation.REQUEST,
	)

	assert arp.source_ip == "127.0.0.1"
	assert arp.source_mac == "00:11:22:33:44:55"
	assert arp.destination_ip == "192.168.0.1"
	assert arp.destination_mac == "AA:BB:CC:DD:EE:FF"
	assert arp.operation == ARPOperation.REQUEST

def test_arp_operation_values():
	assert ARPOperation.REQUEST == 1
	assert ARPOperation.REPLY == 2