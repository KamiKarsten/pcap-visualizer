from pcap_visualizer.models.information.port_information import PortInfo


def test_port_info_creation():
	port_info = PortInfo(
		source_port=12345,
		destination_port=80
	)

	assert port_info.source_port == 12345
	assert port_info.destination_port == 80