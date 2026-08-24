from pcap_visualizer.models.layers.network.icmpv6 import (
	ICMPv6,
	ICMPv6Type,
)


def test_icmpv6_creation():
	icmpv6 = ICMPv6(
		type=ICMPv6Type.ECHO_REQUEST,
		code=0,
	)

	assert icmpv6.type == ICMPv6Type.ECHO_REQUEST
	assert icmpv6.code == 0

def test_icmpv6_type_values():
	assert ICMPv6Type.DESTINATION_UNREACHABLE == 1
	assert ICMPv6Type.PACKET_TOO_BIG == 2
	assert ICMPv6Type.TIME_EXCEEDED == 3
	assert ICMPv6Type.ECHO_REQUEST == 128
	assert ICMPv6Type.ECHO_REPLY == 129
	assert ICMPv6Type.ROUTER_SOLICITATION == 133
	assert ICMPv6Type.ROUTER_ADVERTISEMENT == 134
	assert ICMPv6Type.NEIGHBOR_SOLICITATION == 135
	assert ICMPv6Type.NEIGHBOR_ADVERTISEMENT == 136