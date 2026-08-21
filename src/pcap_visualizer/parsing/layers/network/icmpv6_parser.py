from scapy.layers.inet6 import (
	ICMPv6EchoRequest,
	ICMPv6EchoReply,
	ICMPv6DestUnreach,
	ICMPv6PacketTooBig,
	ICMPv6ND_RS,
	ICMPv6ND_RA,
	ICMPv6ND_NS,
	ICMPv6ND_NA,
			
)
from pcap_visualizer.models.layers.network.icmpv6 import (
	ICMPv6, 
	ICMPv6Type
)

ICMPv6_TYPES = {
	ICMPv6EchoRequest:  ICMPv6Type.ECHO_REQUEST,
	ICMPv6EchoReply: ICMPv6Type.ECHO_REPLY,
	ICMPv6DestUnreach: ICMPv6Type.DESTINATION_UNREACHABLE,
	ICMPv6PacketTooBig: ICMPv6Type.PACKET_TOO_BIG,
	ICMPv6ND_RS: ICMPv6Type.ROUTER_SOLICITATION,
	ICMPv6ND_RA: ICMPv6Type.ROUTER_ADVERTISEMENT,
	ICMPv6ND_NS: ICMPv6Type.NEIGHBOR_SOLICITATION,
	ICMPv6ND_NA: ICMPv6Type.NEIGHBOR_ADVERTISEMENT
}


class ICMPv6Parser:
	@staticmethod
	def parse(packet) -> ICMPv6 | None:
		for scapy_type, icmpv6_type in ICMPv6_TYPES.items():
			if packet.haslayer(scapy_type):
				icmpv6 = packet[scapy_type]

				return ICMPv6(
					type=icmpv6_type,
					code=icmpv6.code
				)

		return None