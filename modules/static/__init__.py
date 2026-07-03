"""Static tier: Mach-O parsing + code-identity assessment."""

from .code_identity import CodeIdentity, assess_code_identity
from .macho import DylibRef, MachOInfo, MachOSlice, is_macho, parse_macho
from .module import StaticMachOModule

__all__ = [
    "CodeIdentity",
    "assess_code_identity",
    "DylibRef",
    "MachOInfo",
    "MachOSlice",
    "is_macho",
    "parse_macho",
    "StaticMachOModule",
]
