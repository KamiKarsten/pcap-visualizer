from .ingestion.pcap_reader import read_pcap
from .parsing.packet_parser import parse_packet

def main():
	filename = 'captures/example.pcap'
	
	for packet in read_pcap(filename):
		package_info = parse_packet(packet)
		print(package_info)

if __name__ == "__main__":
	main()
