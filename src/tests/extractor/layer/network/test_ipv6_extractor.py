from pcap_visualizer.extractor import Ipv6Extractor
from pcap_visualizer.models.information import AddressInfo
from pcap_visualizer.models.layer import IPv6, IPv6NextHeader


def test_extract_returns_address_information():
	layer = IPv6(
		source_ip="2001:db8::1",
		destination_ip="2001:db8::2",
		hop_limit=64,
		next_header=IPv6NextHeader.TCP,
	)

	result = Ipv6Extractor().extract(layer)

	assert result == [
		AddressInfo(
			source="2001:db8::1",
			destination="2001:db8::2",
		)
	]