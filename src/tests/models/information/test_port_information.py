from pcap_visualizer.models.information.port_information import PortInfo


def test_port_info_creation():
	port_info = PortInfo(
		source=12345,
		destination=80
	)

	assert port_info.source == 12345
	assert port_info.destination == 80