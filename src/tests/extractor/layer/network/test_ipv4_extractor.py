from pcap_visualizer.extractor import Ipv4Extractor
from pcap_visualizer.models.information import AddressInfo
from pcap_visualizer.models.layer import IPv4, IPv4Protocol


def test_extract_returns_address_information():
	layer = IPv4(
		source_ip="192.168.1.10",
		destination_ip="192.168.1.20",
		ttl=64,
		protocol=IPv4Protocol.TCP,
	)

	result = Ipv4Extractor().extract(layer)

	assert result == [
		AddressInfo(
			source="192.168.1.10",
			destination="192.168.1.20",
		)
	]