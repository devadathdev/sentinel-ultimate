from pathlib import Path

NFT = Path(__file__).parents[1] / "nftables" / "sentinel.nft.template"
text = NFT.read_text()

def test_default_drop():
    assert "chain forward" in text
    assert "policy drop" in text

def test_zone_isolation():
    assert "10.10.40.0/24" in text  # IoT
    assert "10.10.60.0/24" in text  # Data
    assert "forward_drops" in text

def test_no_broad_forward_accept():
    assert "ip saddr 10.10.10.0/24 ip daddr 10.10.20.0/24 tcp dport 443 accept" in text
    assert "ip saddr 10.10.10.0/24 ip daddr 10.10.20.0/24 accept" not in text
