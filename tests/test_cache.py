"""TTL cache behavior tests."""

from netscan.cache import ScanCache
from netscan.models import Host, Port, Service


def test_cache_round_trip_and_ttl(tmp_path) -> None:
    cache = ScanCache(tmp_path)
    host = Host(address="127.0.0.1", status="up", ports=[Port(22, "tcp", "open", service=Service(name="ssh"))])
    cache.put("127.0.0.1", "quick", host)
    assert cache.get("127.0.0.1", "quick", 60).ports[0].service.name == "ssh"
    assert cache.get("127.0.0.1", "quick", 0) is None
    assert cache.get("127.0.0.2", "quick", 60) is None


def test_corrupt_cache_is_ignored(tmp_path) -> None:
    cache = ScanCache(tmp_path)
    path = cache._path("127.0.0.1", "quick")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json", encoding="utf-8")
    assert cache.get("127.0.0.1", "quick", 60) is None
