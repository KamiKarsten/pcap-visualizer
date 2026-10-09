from pcap_visualizer.models.information.address_information import AddressInfo


def test_address_info_creation():
	address_info = AddressInfo(
		source="192.168.1.10",
		destination="192.168.1.20"
	)

	assert address_info.source == "192.168.1.10"
	assert address_info.destination == "192.168.1.20"