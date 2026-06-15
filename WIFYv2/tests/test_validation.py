from core import validation


def test_valid_mac():
    assert validation.valid_mac("AA:BB:CC:11:22:33")
    assert validation.valid_mac("aa:bb:cc:11:22:33")
    assert not validation.valid_mac("AA:BB:CC:11:22")
    assert not validation.valid_mac("AA:BB:CC:11:22:ZZ")
    assert not validation.valid_mac("not-a-mac")


def test_valid_number():
    assert validation.valid_number("0")
    assert validation.valid_number("123")
    assert not validation.valid_number("")
    assert not validation.valid_number("-1")
    assert not validation.valid_number("12a")


def test_sanitize_name():
    assert validation.sanitize_name("My Project!") == "MyProject"
    assert validation.sanitize_name("test_123-abc") == "test_123-abc"
    assert validation.sanitize_name("../../etc/passwd") == "etcpasswd"


def test_check_deps_missing():
    missing = validation.check_deps("definitely-not-a-real-binary-xyz")
    assert missing == ["definitely-not-a-real-binary-xyz"]


def test_check_deps_present():
    missing = validation.check_deps("python3")
    assert missing == []
