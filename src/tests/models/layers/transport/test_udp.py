from pcap_visualizer.models.layers.transport.udp import (
	UDP,
)


def test_udp_creation():
	udp = UDP(
		source_port=12345,
		destination_port=80,
		length=1024,
	)

	assert udp.source_port == 12345
	assert udp.destination_port == 80
	assert udp.length == 1024