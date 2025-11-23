import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from src.ports import parse_port_piece, parse_ports, parse_targets 
from src.config import MAX_PORT  


def test_parse_port_piece_single():
    assert list(parse_port_piece("80")) == [80]


def test_parse_port_piece_range():
    assert list(parse_port_piece("20-22")) == [20, 21, 22]


def test_parse_ports_empty_means_full_range():
    ports = parse_ports("")
    assert len(ports) == MAX_PORT
    assert 1 in ports and MAX_PORT in ports


def test_parse_ports_mixed_chunks():
    ports = parse_ports("20-22,80,90-91")
    assert ports == {20, 21, 22, 80, 90, 91}


def test_parse_targets_tcp_udp():
    tcp, udp = parse_targets(["tcp/22,80", "udp/53-54"])
    assert tcp == {22, 80}
    assert udp == {53, 54}


def test_invalid_port_raises():
    with pytest.raises(ValueError):
        parse_port_piece("0")
    with pytest.raises(ValueError):
        parse_port_piece("10-5")
    with pytest.raises(ValueError):
        parse_ports("1,,2")
    with pytest.raises(ValueError):
        parse_targets(["foo/1"])
