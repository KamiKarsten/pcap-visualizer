from .ingestion.pcap_reader import read_pcap
from .mapping import PacketMapper


def main():
	filename = 'captures/example.pcap'
	
	for packet in read_pcap(filename):
		packet_info = PacketMapper.map(packet)
		print(packet_info)

if __name__ == "__main__":
	main()
