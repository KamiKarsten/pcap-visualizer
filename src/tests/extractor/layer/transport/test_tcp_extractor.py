from pcap_visualizer.extractor import TCPExtractor
from pcap_visualizer.models.information import PortInfo
from pcap_visualizer.models.layer import TCP, TCPFlags


def test_extract_returns_port_information():
	layer = TCP(
		source_port=54321,
		destination_port=443,
		sequence_number=1000,
		acknowledgment_number=2000,
		flags=TCPFlags.SYN | TCPFlags.ACK,
		window=65535,
	)

	result = TCPExtractor().extract(layer)

	assert result == [
		PortInfo(
			source=54321,
			destination=443,
		)
	]