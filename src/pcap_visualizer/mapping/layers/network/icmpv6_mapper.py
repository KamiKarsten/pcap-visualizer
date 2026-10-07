from scapy.layers.inet6 import (
	ICMPv6DestUnreach,
	ICMPv6EchoReply,
	ICMPv6EchoRequest,
	ICMPv6ND_NA,
	ICMPv6ND_NS,
	ICMPv6ND_RA,
	ICMPv6ND_RS,
	ICMPv6PacketTooBig,
)

from pcap_visualizer.models import ICMPv6, ICMPv6Type

ICMPv6_TYPES = {
	ICMPv6EchoRequest: ICMPv6Type.ECHO_REQUEST,
	ICMPv6EchoReply: ICMPv6Type.ECHO_REPLY,
	ICMPv6DestUnreach: ICMPv6Type.DESTINATION_UNREACHABLE,
	ICMPv6PacketTooBig: ICMPv6Type.PACKET_TOO_BIG,
	ICMPv6ND_RS: ICMPv6Type.ROUTER_SOLICITATION,
	ICMPv6ND_RA: ICMPv6Type.ROUTER_ADVERTISEMENT,
	ICMPv6ND_NS: ICMPv6Type.NEIGHBOR_SOLICITATION,
	ICMPv6ND_NA: ICMPv6Type.NEIGHBOR_ADVERTISEMENT
}

class ICMPv6Mapper:

	@staticmethod
	def map(layer) -> ICMPv6 | None:

		icmpv6_type = ICMPv6_TYPES.get(type(layer))

		if icmpv6_type is None:
			return None

		return ICMPv6(
			type=icmpv6_type,
			code=layer.code
		)