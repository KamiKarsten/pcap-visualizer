from pcap_visualizer.models.information.address_information import AddressInfo


def test_address_info_creation():
	address_info = AddressInfo(
		source_ip="192.168.1.10",
		destination_ip="192.168.1.20"
	)

	assert address_info.source_ip == "192.168.1.10"
	assert address_info.destination_ip == "192.168.1.20"