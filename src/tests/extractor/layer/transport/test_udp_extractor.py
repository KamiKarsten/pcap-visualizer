from pcap_visualizer.extractor import UDPExtractor
from pcap_visualizer.models.information import PortInfo
from pcap_visualizer.models.layer import UDP


def test_extract_returns_port_information():
	layer = UDP(
		source_port=5353,
		destination_port=53,
		length=32,
	)

	result = UDPExtractor().extract(layer)

	assert result == [
		PortInfo(
			source=5353,
			destination=53,
		)
	]