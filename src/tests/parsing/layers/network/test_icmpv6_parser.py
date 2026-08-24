import pytest
from scapy.layers.inet6 import (
	ICMPv6DestUnreach,
	ICMPv6EchoReply,
	ICMPv6EchoRequest,
	ICMPv6ND_NA,
	ICMPv6ND_NS,
	ICMPv6ND_RA,
	ICMPv6ND_RS,
	ICMPv6PacketTooBig,
	IPv6,
)

from pcap_visualizer.models import ICMPv6, ICMPv6Type
from pcap_visualizer.parsing import ICMPv6Parser


def test_parse_returns_none_when_packet_has_no_icmpv6_layer():
	packet = IPv6()

	result = ICMPv6Parser.parse(packet)

	assert result is None

@pytest.mark.parametrize(
    ("scapy_type", "expected_type"),
    [
        (ICMPv6EchoRequest, ICMPv6Type.ECHO_REQUEST),
        (ICMPv6EchoReply, ICMPv6Type.ECHO_REPLY),
        (ICMPv6DestUnreach, ICMPv6Type.DESTINATION_UNREACHABLE),
        (ICMPv6PacketTooBig, ICMPv6Type.PACKET_TOO_BIG),
        (ICMPv6ND_RS, ICMPv6Type.ROUTER_SOLICITATION),
        (ICMPv6ND_RA, ICMPv6Type.ROUTER_ADVERTISEMENT),
        (ICMPv6ND_NS, ICMPv6Type.NEIGHBOR_SOLICITATION),
        (ICMPv6ND_NA, ICMPv6Type.NEIGHBOR_ADVERTISEMENT),
    ],
)
def test_parse_maps_icmpv6_type(scapy_type, expected_type):
    packet = IPv6() / scapy_type(code=0)

    result = ICMPv6Parser.parse(packet)

    assert result is not None
    assert isinstance(result, ICMPv6)
    assert result.type == expected_type
    assert result.code == 0
