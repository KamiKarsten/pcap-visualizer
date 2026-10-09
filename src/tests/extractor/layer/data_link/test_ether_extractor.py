from pcap_visualizer.extractor import EtherExtractor
from pcap_visualizer.models.information import MacAddressInfo
from pcap_visualizer.models.layer import Ethernet, EthernetType


def test_extract_returns_mac_address_information():
	layer = Ethernet(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF",
		ether_type=EthernetType.IPV4,
	)

	result = EtherExtractor().extract(layer)

	assert result == [
		MacAddressInfo(
			source="00:11:22:33:44:55",
			destination="AA:BB:CC:DD:EE:FF",
		)
	]
