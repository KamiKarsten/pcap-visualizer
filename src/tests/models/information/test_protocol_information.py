from pcap_visualizer.models.information.protocol_information import ProtocolInfo


def test_protocol_info_creation():
	protocol_info = ProtocolInfo(
		protocol_type="TCP"
	)

	assert protocol_info.protocol_type == "TCP"  