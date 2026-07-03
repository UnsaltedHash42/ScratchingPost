"""Mach-O parser (ROADMAP.md Phase 1 static tier).

Extracts load commands, LC_LOAD_DYLIB imports (and their kind), rpaths, symbols,
and fat/universal slices via LIEF. Output feeds both the code-identity assessor
and the dylib-hijack surface (Callandor territory): weak dylibs and @rpath loads
are where planted libraries get picked up.

LIEF version note: developed against LIEF 0.12.x, whose MachO API differs from
current releases (FatBinary.at(i), Header.cpu_type, DylibCommand.command, and a
concrete RPathCommand with .path). If LIEF is upgraded, re-verify these accessors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import lief
from lief import MachO

# LIEF logs "Command 'X' not parsed!" to stderr for load commands it doesn't
# model (DYLD_CHAINED_FIXUPS etc.). Those aren't errors for our purposes.
lief.logging.disable()

# DylibCommand.command values that denote a hijack-relevant weak load. Compared
# by enum name to stay robust across LIEF builds.
_WEAK_DYLIB_CMDS = {"LOAD_WEAK_DYLIB"}


@dataclass
class DylibRef:
    name: str
    kind: str  # load|weak|reexport|upward|lazy|id|other
    rpath_relative: bool = False  # name starts with @rpath/


@dataclass
class MachOSlice:
    cpu: str
    file_type: str
    flags: list[str]
    is_pie: bool
    load_commands: list[str] = field(default_factory=list)
    dylibs: list[DylibRef] = field(default_factory=list)
    rpaths: list[str] = field(default_factory=list)
    imported_symbols: list[str] = field(default_factory=list)
    exported_symbols: list[str] = field(default_factory=list)

    @property
    def weak_dylibs(self) -> list[DylibRef]:
        return [d for d in self.dylibs if d.kind == "weak"]

    @property
    def rpath_dylibs(self) -> list[DylibRef]:
        return [d for d in self.dylibs if d.rpath_relative]


@dataclass
class MachOInfo:
    path: str
    is_fat: bool
    slices: list[MachOSlice] = field(default_factory=list)

    @property
    def cpus(self) -> list[str]:
        return [s.cpu for s in self.slices]


def _dylib_kind(cmd_name: str) -> str:
    n = cmd_name.upper()
    if n == "LOAD_WEAK_DYLIB":
        return "weak"
    if n == "REEXPORT_DYLIB":
        return "reexport"
    if n == "LOAD_UPWARD_DYLIB":
        return "upward"
    if n == "LAZY_LOAD_DYLIB":
        return "lazy"
    if n == "ID_DYLIB":
        return "id"
    if n in ("LOAD_DYLIB", "DYLIB"):
        return "load"
    return "other"


def _enum_name(v: object) -> str:
    # LIEF enums stringify as "CPU_TYPES.ARM64"; take the trailing token.
    return str(v).rsplit(".", 1)[-1]


def _parse_slice(binary: "MachO.Binary") -> MachOSlice:
    header = binary.header
    flags = [_enum_name(f) for f in header.flags_list]
    sl = MachOSlice(
        cpu=_enum_name(header.cpu_type),
        file_type=_enum_name(header.file_type),
        flags=flags,
        is_pie="PIE" in flags,
    )

    for cmd in binary.commands:
        cmd_name = _enum_name(cmd.command)
        sl.load_commands.append(cmd_name)
        if isinstance(cmd, MachO.RPathCommand):
            sl.rpaths.append(cmd.path)

    for lib in binary.libraries:
        name = lib.name
        sl.dylibs.append(
            DylibRef(
                name=name,
                kind=_dylib_kind(_enum_name(lib.command)),
                rpath_relative=name.startswith("@rpath/"),
            )
        )

    # imported_functions/symbols availability varies; guard defensively.
    try:
        sl.imported_symbols = [s.name for s in binary.imported_functions]
    except Exception:  # pragma: no cover - LIEF edge cases
        sl.imported_symbols = []
    try:
        sl.exported_symbols = [s.name for s in binary.exported_functions]
    except Exception:  # pragma: no cover
        sl.exported_symbols = []
    return sl


def parse_macho(path: str | Path) -> MachOInfo:
    """Parse a Mach-O (thin or fat) into a MachOInfo. Raises ValueError if the
    bytes are not a recognizable Mach-O."""
    fat = MachO.parse(str(path))
    if fat is None:
        raise ValueError(f"not a Mach-O: {path}")
    count = fat.size
    slices = [_parse_slice(fat.at(i)) for i in range(count)]
    return MachOInfo(path=str(path), is_fat=count > 1, slices=slices)


def is_macho(path: str | Path) -> bool:
    """Cheap magic-number check (thin + fat, both endiannesses) without a full
    parse. Used to classify a Sample before committing to LIEF."""
    magics = {
        b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64 (LE)
        b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 (BE)
        b"\xce\xfa\xed\xfe",  # MH_MAGIC (LE)
        b"\xfe\xed\xfa\xce",  # MH_MAGIC (BE)
        b"\xca\xfe\xba\xbe",  # FAT_MAGIC
        b"\xbe\xba\xfe\xca",  # FAT_CIGAM
    }
    try:
        with open(path, "rb") as f:
            return f.read(4) in magics
    except OSError:
        return False
