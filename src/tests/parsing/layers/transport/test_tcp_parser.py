import pytest
from scapy.layers.inet import IP
from scapy.layers.inet import TCP as ScapyTCP

from pcap_visualizer.models import TCP, TCPFlags
from pcap_visualizer.parsing import TCPParser


def test_parse_returns_none_when_packet_has_no_tcp_layer():
	packet = IP()

	result = TCPParser.parse(packet)

	assert result is None

def test_parse_returns_tcp_object_when_packet_has_tcp_layer():
	packet = ScapyTCP(
		sport = 1234,
		dport = 80,
		seq = 100,
		ack = 200,
		flags = "SA",
		window = 4096
	)

	result = TCPParser.parse(packet)

	assert result is not None
	assert isinstance(result, TCP)

	assert result.source_port == 1234
	assert result.destination_port == 80
	assert result.sequence_number == 100
	assert result.acknowledgment_number == 200
	assert result.flags == TCPFlags.SYN | TCPFlags.ACK
	assert result.window == 4096

@pytest.mark.parametrize(
	("scapy_flags", "expected_flags"),
	[
		("S", TCPFlags.SYN),
		("A", TCPFlags.ACK),
		("F", TCPFlags.FIN),
		("R", TCPFlags.RST),
		("P", TCPFlags.PSH),
		("U", TCPFlags.URG),
		("E", TCPFlags.ECE),
		("C", TCPFlags.CWR),
		("N", TCPFlags.NS),
		("SA", TCPFlags.SYN | TCPFlags.ACK),
		("FA", TCPFlags.FIN | TCPFlags.ACK),
		("SFA", TCPFlags.SYN | TCPFlags.FIN | TCPFlags.ACK),
		("", TCPFlags(0)),
	],
)
def test_match_flags(scapy_flags, expected_flags):
	packet = ScapyTCP(flags = scapy_flags)

	result = TCPParser.parse(packet)

	assert result is not None
	assert result.flags == expected_flags