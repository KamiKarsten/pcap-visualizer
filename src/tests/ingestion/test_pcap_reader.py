from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from pcap_visualizer.ingestion.pcap_reader import read_pcap


def test_read_pcap_returns_packets(tmp_path):
	packet_1 = IP() / TCP()
	packet_2 = IP() / TCP()

	filename = tmp_path / "test.pcap"

	wrpcap(str(filename), [packet_1, packet_2])

	result = list(read_pcap(str(filename)))

	assert len(result) == 2
	assert result[0].haslayer(IP)
	assert result[0].haslayer(TCP)
	assert result[1].haslayer(IP)
	assert result[1].haslayer(TCP)