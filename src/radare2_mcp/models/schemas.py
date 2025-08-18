"""Pydantic models for Radare2 MCP server."""

from enum import Enum
from typing import Any, List, Optional, Union

from pydantic import BaseModel, validator


class OutputFormat(str, Enum):
    """Output format options."""

    JSON = "json"
    TEXT = "text"
    HEX = "hex"
    DISASM = "disasm"
    PYTHON = "python"
    C = "c"


class Architecture(str, Enum):
    """Supported architectures."""

    X86 = "x86"
    X86_64 = "x86.64"
    ARM = "arm"
    ARM64 = "arm.64"
    MIPS = "mips"
    PPC = "ppc"
    SPARC = "sparc"
    WASM = "wasm"


class R2Session(BaseModel):
    """Radare2 session information."""

    session_id: str
    file_path: Optional[str] = None
    pid: Optional[int] = None
    architecture: Optional[Architecture] = None
    bits: Optional[int] = None
    endian: Optional[str] = None
    is_debugger: bool = False
    write_mode: bool = False


class Address(BaseModel):
    """Address representation."""

    value: Union[int, str]

    @validator("value")
    def validate_address(cls, v):
        if isinstance(v, str):
            # Handle various address formats
            if v.startswith("0x"):
                return int(v, 16)
            elif v.startswith("sym.") or v.startswith("fcn."):
                return v  # Keep as symbol
            else:
                try:
                    return int(v)
                except ValueError:
                    return v  # Might be a flag or symbol
        return v


class AnalysisResult(BaseModel):
    """Analysis operation result."""

    success: bool
    functions_found: Optional[int] = None
    basic_blocks: Optional[int] = None
    cross_references: Optional[int] = None
    message: Optional[str] = None


class FunctionInfo(BaseModel):
    """Function information."""

    name: str
    offset: int
    size: int
    nargs: Optional[int] = None
    nlocals: Optional[int] = None
    nbbs: Optional[int] = None  # Number of basic blocks
    edges: Optional[int] = None
    cc: Optional[str] = None  # Calling convention
    type: Optional[str] = None
    xrefs_to: Optional[List[int]] = None
    xrefs_from: Optional[List[int]] = None


class SectionInfo(BaseModel):
    """Binary section information."""

    name: str
    size: int
    vsize: int
    offset: int
    vaddr: int
    permissions: str
    type: Optional[str] = None


class SymbolInfo(BaseModel):
    """Symbol information."""

    name: str
    offset: int
    size: int
    type: str
    bind: Optional[str] = None
    is_imported: bool = False


class StringInfo(BaseModel):
    """String information."""

    offset: int
    length: int
    type: str
    string: str
    section: Optional[str] = None


class RegisterState(BaseModel):
    """CPU register state."""

    name: str
    value: int
    size: int

    @property
    def hex_value(self) -> str:
        return f"0x{self.value:x}"


class Breakpoint(BaseModel):
    """Breakpoint information."""

    address: int
    size: int = 1
    enabled: bool = True
    condition: Optional[str] = None
    commands: Optional[List[str]] = None
    hits: int = 0


class MemoryMap(BaseModel):
    """Memory mapping information."""

    start: int
    end: int
    size: int
    permissions: str
    name: Optional[str] = None
    file: Optional[str] = None


class DisassemblyLine(BaseModel):
    """Single disassembly line."""

    offset: int
    size: int
    opcode: str
    bytes: str
    instruction: str
    comment: Optional[str] = None
    xrefs: Optional[List[int]] = None
    flags: Optional[List[str]] = None


class SearchResult(BaseModel):
    """Search result."""

    offset: int
    size: int
    data: bytes
    string: Optional[str] = None

    @property
    def hex_data(self) -> str:
        return self.data.hex()


class ROPGadget(BaseModel):
    """ROP gadget information."""

    offset: int
    instructions: List[str]
    size: int
    ending: str  # e.g., "ret", "jmp eax"

    @property
    def assembly(self) -> str:
        return "; ".join(self.instructions)


class WriteOperation(BaseModel):
    """Write operation details."""

    offset: int
    data: Union[bytes, str]
    size: Optional[int] = None
    operation: Optional[str] = None  # e.g., "xor", "add"

    @validator("data")
    def validate_data(cls, v):
        if isinstance(v, str):
            # Handle hex string
            if v.startswith("0x"):
                v = v[2:]
            return bytes.fromhex(v)
        return v


class Flag(BaseModel):
    """Flag (label) information."""

    name: str
    offset: int
    size: int = 1
    space: Optional[str] = None


class ConfigProperty(BaseModel):
    """Configuration property."""

    key: str
    value: Any
    type: str
    description: Optional[str] = None
    options: Optional[List[Any]] = None
