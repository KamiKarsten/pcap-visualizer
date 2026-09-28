from unittest.mock import MagicMock, patch

from pcap_visualizer.models import Packet
from pcap_visualizer.parsing import PacketParser


def test_parse_adds_layer_when_parser_returns_layer():
	packet = MagicMock()
	layer = MagicMock()

	parser = MagicMock()
	parser.parse.return_value = layer

	with patch.object(
		PacketParser,
		"parsers",
		[parser]
	):
		result = PacketParser.parse(packet)

	assert isinstance(result, Packet)
	assert result.layers == [layer]

def test_parse_does_not_add_layer_when_parser_returns_none():
	packet = MagicMock()

	parser = MagicMock()
	parser.parse.return_value = None

	with patch.object(
		PacketParser,
		"parsers",
		[parser]
	):
		result = PacketParser.parse(packet)

	assert isinstance(result, Packet)
	assert result.layers == []


def test_parse_adds_all_returned_layers():
	packet = MagicMock()

	layer_1 = MagicMock()
	layer_2 = MagicMock()

	parser_1 = MagicMock()
	parser_1.parse.return_value = layer_1

	parser_2 = MagicMock()
	parser_2.parse.return_value = layer_2

	with patch.object(
		PacketParser,
		"parsers",
		[parser_1, parser_2],
	):
		result = PacketParser.parse(packet)

	assert result.layers == [layer_1, layer_2]

def test_parse_sets_packet_size():
	packet = MagicMock()
	packet.__len__.return_value = 123

	with patch.object(PacketParser, "parsers", []):
		result = PacketParser.parse(packet)

	assert result.size == 123
	assert result.layers == []