import pytest

from pcap_visualizer.models.layers.transport.tcp import (
	TCP,
	TCPFlags,
)


def test_tcp_creation():
	tcp = TCP(
		source_port=12345,
		destination_port=80,
		sequence_number=1000,
		acknowledgment_number=2000,
		flags=TCPFlags.SYN | TCPFlags.ACK,
		window=65535,
	)

	assert tcp.source_port == 12345
	assert tcp.destination_port == 80
	assert tcp.sequence_number == 1000
	assert tcp.acknowledgment_number == 2000
	assert tcp.flags == TCPFlags.SYN | TCPFlags.ACK
	assert tcp.window == 65535

@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        (TCPFlags.FIN, 1 << 0),
        (TCPFlags.SYN, 1 << 1),
        (TCPFlags.RST, 1 << 2),
        (TCPFlags.PSH, 1 << 3),
        (TCPFlags.ACK, 1 << 4),
        (TCPFlags.URG, 1 << 5),
        (TCPFlags.ECE, 1 << 6),
        (TCPFlags.CWR, 1 << 7),
        (TCPFlags.NS, 1 << 8),
    ],
)
def test_tcp_flags_values(flag, expected):
	assert flag == expected

def test_tcp_flags_can_be_combined():
    flags = TCPFlags.SYN | TCPFlags.ACK

    assert TCPFlags.SYN in flags
    assert TCPFlags.ACK in flags
    assert TCPFlags.FIN not in flags