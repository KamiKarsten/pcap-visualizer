from pcap_visualizer.models.layers.network.icmp import (
	ICMP,
	ICMPType,
)


def test_icmp_creation():
	icmp = ICMP(
		type=ICMPType.ECHO_REQUEST,
		code=0,
	)

	assert icmp.type == ICMPType.ECHO_REQUEST
	assert icmp.code == 0

def test_icmp_type_values():
	assert ICMPType.DESTINATION_UNREACHABLE == 3
	assert ICMPType.ECHO_REQUEST == 8
	assert ICMPType.ECHO_REPLY == 0