from pcap_visualizer.models.information.mac_address_information import MacAddressInfo


def test_mac_address_info_creation():
	mac_address_info = MacAddressInfo(
		source_mac="00:11:22:33:44:55",
		destination_mac="AA:BB:CC:DD:EE:FF"
	)

	assert mac_address_info.source_mac == "00:11:22:33:44:55"
	assert mac_address_info.destination_mac == "AA:BB:CC:DD:EE:FF"