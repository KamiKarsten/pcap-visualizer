from .ingestion.pcap_reader import read_pcap
from .parsing import PacketParser


def main():
	filename = 'captures/example.pcap'
	
	for packet in read_pcap(filename):
		packet_info = PacketParser.parse(packet)
		print(packet_info)

if __name__ == "__main__":
	main()
