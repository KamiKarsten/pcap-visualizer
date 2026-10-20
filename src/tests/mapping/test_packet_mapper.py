from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from pcap_visualizer.mapping import PacketMapper
from pcap_visualizer.models import Packet
from pcap_visualizer.models.layer.layer import Layer


def test_map_adds_layer_when_mapper_returns_layer():
	packet = Ether()
	
	layer = MagicMock()
	mapper = MagicMock()
	
	mapper.map.return_value = layer

	with patch.object(
		PacketMapper,
		"mappers",
		[mapper]
	):
		result = PacketMapper.map(packet)

	assert isinstance(result, Packet)
	assert result.layer == layer

def test_map_does_not_add_layer_when_mapper_returns_none():
	packet = Ether()

	mapper = MagicMock()
	mapper.map.return_value = None

	with patch.object(
		PacketMapper,
		"mappers",
		[mapper]
	):
		result = PacketMapper.map(packet)

	assert isinstance(result, Packet)
	assert result.layer is None

def test_map_adds_all_returned_layers():
	packet = Ether() / IP()

	layer_1 = Layer()
	layer_2 = Layer()

	mapper_1 = MagicMock()
	mapper_1.map.side_effect = lambda layer: (
		layer_1 if isinstance(layer, Ether) else None
	)

	mapper_2 = MagicMock()
	mapper_2.map.side_effect = lambda layer: (
		layer_2 if isinstance(layer, IP) else None
	)

	with patch.object(
		PacketMapper,
		"mappers",
		[mapper_1, mapper_2],
	):
		result = PacketMapper.map(packet)

	assert result.layer is layer_1
	assert layer_1.payload is layer_2

def test_map_sets_packet_size():
	packet = Ether()
	
	with patch.object(
		PacketMapper,
		"mappers",
		[]
	):
		result = PacketMapper.map(packet)

	assert result.size == len(packet)

def test_map_sets_packet_timestamp():
	timestamp = datetime(2026, 10, 10, 1, 13, 35, 456789, tzinfo=UTC)
	packet = Ether()
	packet.time = timestamp.timestamp()

	with patch.object(
		PacketMapper,
		"mappers",
		[]
	):
		result = PacketMapper.map(packet)

	assert result.timestamp == timestamp