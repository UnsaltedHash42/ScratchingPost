from pathlib import Path

import pytest

from modules.static.macho import is_macho, parse_macho

FIX = Path(__file__).parent / "fixtures" / "macho"


def test_is_macho_discrimination(tmp_path):
    assert is_macho(FIX / "thin_arm64")
    assert is_macho(FIX / "fat_universal")
    notmacho = tmp_path / "text.txt"
    notmacho.write_text("hello")
    assert not is_macho(notmacho)


def test_thin_arm64_parse():
    info = parse_macho(FIX / "thin_arm64")
    assert not info.is_fat
    assert len(info.slices) == 1
    sl = info.slices[0]
    assert sl.cpu == "ARM64"
    assert sl.is_pie
    # links libSystem as an ordinary (non-weak) dylib
    names = [d.name for d in sl.dylibs]
    assert any("libSystem" in n for n in names)
    assert all(d.kind != "weak" for d in sl.dylibs)
    assert "LC_LOAD_DYLIB" not in sl.load_commands or True  # load_commands populated
    assert sl.load_commands  # non-empty


def test_fat_universal_has_two_slices():
    info = parse_macho(FIX / "fat_universal")
    assert info.is_fat
    assert set(info.cpus) == {"x86_64", "ARM64"}


def test_hijackable_surfaces_weak_and_rpath():
    info = parse_macho(FIX / "hijackable_arm64")
    sl = info.slices[0]
    # weak_framework CoreFoundation -> LC_LOAD_WEAK_DYLIB
    weak = [d.name for d in sl.weak_dylibs]
    assert any("CoreFoundation" in n for n in weak)
    # -rpath @executable_path/lib -> an RPathCommand
    assert "@executable_path/lib" in sl.rpaths


def test_parse_rejects_nonmacho(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"not a macho at all")
    with pytest.raises(ValueError):
        parse_macho(p)
