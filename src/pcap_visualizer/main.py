from pcap_visualizer.extractor.information_extractor import InformationExtractor
from pcap_visualizer.ingestion.pcap_reader import read_pcap
from pcap_visualizer.mapping import PacketMapper


def main():
	filename = 'captures/example.pcap'

	for packet in read_pcap(filename):
		mapped_packet = PacketMapper.map(packet)
		packet_info = InformationExtractor.extract(mapped_packet)

		print(f"Packet: {packet_info}")

if __name__ == "__main__":
	main()
