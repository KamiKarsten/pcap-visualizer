from pcap_visualizer.extractor import ArpExtractor
from pcap_visualizer.models.information import AddressInfo, MacAddressInfo
from pcap_visualizer.models.layer import ARP


def test_extract_returns_mac_and_address_information():
	layer = ARP(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		source_ip="192.168.1.10",
		destination_ip="192.168.1.1",
		operation= 1
	)

	result = ArpExtractor().extract(layer)

	assert result == [
		MacAddressInfo(
			source="00:11:22:33:44:55",
			destination="AA:BB:CC:DD:EE:FF",
		),
		AddressInfo(
			source="192.168.1.10",
			destination="192.168.1.1",
		),
	]
