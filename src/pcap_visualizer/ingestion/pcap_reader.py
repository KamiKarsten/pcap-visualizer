from scapy.all import PcapReader


def read_pcap(filename):
	with PcapReader(filename) as packets:
		yield from packets