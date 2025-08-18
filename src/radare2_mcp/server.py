"""Main MCP server for Radare2."""

import logging
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

from radare2_mcp.models.schemas import (
    Address,
    R2Session,
)
from radare2_mcp.tools.analysis import AnalysisTools
from radare2_mcp.tools.binary_info import BinaryInfoTools
from radare2_mcp.tools.config import ConfigTools
from radare2_mcp.tools.debugger import DebuggerTools
from radare2_mcp.tools.disassembly import DisassemblyTools
from radare2_mcp.tools.flags import FlagTools
from radare2_mcp.tools.navigation import NavigationTools
from radare2_mcp.tools.search import SearchTools
from radare2_mcp.tools.write import WriteTools
from radare2_mcp.utils.r2_manager import r2_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("radare2-mcp", dependencies=["r2pipe"])

# Session Management Tools


@mcp.tool()
async def create_session(
    file_path: Optional[str] = None,
    pid: Optional[int] = None,
    write_mode: bool = False,
    debug_mode: bool = False,
    session_name: Optional[str] = None,
) -> R2Session:
    """
    Create a new Radare2 session.

    Args:
        file_path: Path to binary file to analyze
        pid: Process ID to attach to
        write_mode: Enable write mode
        debug_mode: Enable debugger mode
        session_name: Optional session name (auto-generated if not provided)

    Returns:
        Session information
    """
    import uuid

    session_id = session_name or str(uuid.uuid4())[:8]

    session = r2_manager.create_session(
        session_id=session_id,
        file_path=file_path,
        pid=pid,
        write_mode=write_mode,
        debug_mode=debug_mode,
    )

    return session


@mcp.tool()
async def list_sessions() -> List[R2Session]:
    """List all active Radare2 sessions."""
    return r2_manager.list_sessions()


@mcp.tool()
async def close_session(session_id: str) -> bool:
    """Close a Radare2 session."""
    return r2_manager.close_session(session_id)


@mcp.tool()
async def switch_session(session_id: str) -> bool:
    """Switch to a different session."""
    return r2_manager.switch_session(session_id)


# Analysis Tools


@mcp.tool()
async def analyze_all(session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform complete analysis of the binary (aa).
    Analyzes functions, basic blocks, and cross-references.
    """
    result = await AnalysisTools.analyze_all(session_id)
    return result.dict()


@mcp.tool()
async def analyze_function(
    address: Optional[str] = None, session_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyze function at current or specified address (af).

    Args:
        address: Address or symbol (e.g., "0x401000", "sym.main")
        session_id: Session to use
    """
    addr = Address(value=address) if address else None
    result = await AnalysisTools.analyze_function(addr, session_id)
    return result.dict()


@mcp.tool()
async def list_functions(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all analyzed functions (afl)."""
    functions = await AnalysisTools.list_functions(session_id)
    return [f.dict() for f in functions]


@mcp.tool()
async def get_function_info(
    address: Optional[str] = None, session_id: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Get detailed information about a function (afi)."""
    addr = Address(value=address) if address else None
    info = await AnalysisTools.get_function_info(addr, session_id)
    return info.dict() if info else None


@mcp.tool()
async def get_xrefs_to(address: str, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get cross references to an address (axt)."""
    addr = Address(value=address)
    return await AnalysisTools.get_xrefs_to(addr, session_id)


@mcp.tool()
async def get_xrefs_from(address: str, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get cross references from an address (axf)."""
    addr = Address(value=address)
    return await AnalysisTools.get_xrefs_from(addr, session_id)


# Binary Information Tools


@mcp.tool()
async def get_binary_info(session_id: Optional[str] = None) -> Dict[str, Any]:
    """Get comprehensive binary information (iI)."""
    return await BinaryInfoTools.get_binary_info(session_id)


@mcp.tool()
async def get_sections(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get binary sections (iS)."""
    sections = await BinaryInfoTools.get_sections(session_id)
    return [s.dict() for s in sections]


@mcp.tool()
async def get_symbols(
    imports_only: bool = False, exports_only: bool = False, session_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Get binary symbols (is)."""
    symbols = await BinaryInfoTools.get_symbols(imports_only, exports_only, session_id)
    return [s.dict() for s in symbols]


@mcp.tool()
async def get_strings(
    data_section_only: bool = True, session_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Get strings from binary (iz/izz)."""
    strings = await BinaryInfoTools.get_strings(data_section_only, session_id)
    return [s.dict() for s in strings]


@mcp.tool()
async def get_imports(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get imported functions (ii)."""
    return await BinaryInfoTools.get_imports(session_id)


@mcp.tool()
async def get_entrypoint(session_id: Optional[str] = None) -> Optional[int]:
    """Get binary entrypoint (ie)."""
    return await BinaryInfoTools.get_entrypoint(session_id)


@mcp.tool()
async def check_security(session_id: Optional[str] = None) -> Dict[str, bool]:
    """Check binary security features (NX, PIE, Canary, etc.)."""
    return await BinaryInfoTools.check_security(session_id)


# Disassembly Tools


@mcp.tool()
async def disassemble(
    count: int = 10, address: Optional[str] = None, session_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Disassemble N instructions (pd).

    Args:
        count: Number of instructions to disassemble
        address: Starting address or symbol
        session_id: Session to use
    """
    addr = Address(value=address) if address else None
    lines = await DisassemblyTools.disassemble(count, addr, session_id)
    return [line.dict() for line in lines]


@mcp.tool()
async def disassemble_function(
    address: Optional[str] = None, session_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Disassemble entire function (pdf)."""
    addr = Address(value=address) if address else None
    lines = await DisassemblyTools.disassemble_function(addr, session_id)
    return [line.dict() for line in lines]


@mcp.tool()
async def print_hex(
    size: int = 64, address: Optional[str] = None, session_id: Optional[str] = None
) -> str:
    """Print hexdump (px)."""
    addr = Address(value=address) if address else None
    return await DisassemblyTools.print_hex(size, addr, session_id)


@mcp.tool()
async def print_string(
    address: str, length: Optional[int] = None, session_id: Optional[str] = None
) -> str:
    """Print string at address (psz)."""
    addr = Address(value=address)
    return await DisassemblyTools.print_string(addr, length, session_id)


# Navigation Tools


@mcp.tool()
async def seek(address: str, session_id: Optional[str] = None) -> int:
    """
    Seek to address or symbol (s).
    Returns new position.
    """
    addr = Address(value=address)
    return await NavigationTools.seek(addr, session_id)


@mcp.tool()
async def seek_relative(offset: int, session_id: Optional[str] = None) -> int:
    """Seek relative to current position."""
    return await NavigationTools.seek_relative(offset, session_id)


@mcp.tool()
async def get_current_address(session_id: Optional[str] = None) -> int:
    """Get current address."""
    return await NavigationTools.get_current_address(session_id)


@mcp.tool()
async def set_block_size(size: int, session_id: Optional[str] = None) -> bool:
    """Set block size (b)."""
    return await NavigationTools.set_block_size(size, session_id)


# Search Tools


@mcp.tool()
async def search_bytes(
    pattern: str,
    from_addr: Optional[int] = None,
    to_addr: Optional[int] = None,
    session_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Search for byte pattern (/x).
    Pattern should be hex string like "909090" or "\\x90\\x90"
    """
    results = await SearchTools.search_bytes(pattern, from_addr, to_addr, session_id)
    return [r.dict() for r in results]


@mcp.tool()
async def search_string(
    text: str,
    case_sensitive: bool = True,
    from_addr: Optional[int] = None,
    to_addr: Optional[int] = None,
    session_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search for string (/)."""
    results = await SearchTools.search_string(text, case_sensitive, from_addr, to_addr, session_id)
    return [r.dict() for r in results]


@mcp.tool()
async def search_rop_gadgets(
    instructions: List[str], max_length: int = 5, session_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Search for ROP gadgets (/R).
    Example: ["pop eax", "ret"]
    """
    gadgets = await SearchTools.search_rop_gadgets(instructions, max_length, session_id)
    return [g.dict() for g in gadgets]


# Write Tools


@mcp.tool()
async def write_hex(
    data: str, address: Optional[str] = None, session_id: Optional[str] = None
) -> bool:
    """
    Write hex values (wx).
    Data should be hex string like "909090"
    """
    addr = Address(value=address) if address else None
    return await WriteTools.write_hex(data, addr, session_id)


@mcp.tool()
async def write_assembly(
    assembly: str, address: Optional[str] = None, session_id: Optional[str] = None
) -> bool:
    """
    Write assembly instruction (wa).
    Example: "jmp 0x401000"
    """
    addr = Address(value=address) if address else None
    return await WriteTools.write_assembly(assembly, addr, session_id)


@mcp.tool()
async def write_nop(
    count: int = 1, address: Optional[str] = None, session_id: Optional[str] = None
) -> bool:
    """Write NOP instructions."""
    addr = Address(value=address) if address else None
    return await WriteTools.write_nop(count, addr, session_id)


# Debugger Tools


@mcp.tool()
async def continue_execution(session_id: Optional[str] = None) -> bool:
    """Continue program execution (dc)."""
    return await DebuggerTools.continue_execution(session_id)


@mcp.tool()
async def step_into(session_id: Optional[str] = None) -> bool:
    """Step into (single step) (ds)."""
    return await DebuggerTools.step_into(session_id)


@mcp.tool()
async def step_over(session_id: Optional[str] = None) -> bool:
    """Step over (dso)."""
    return await DebuggerTools.step_over(session_id)


@mcp.tool()
async def set_breakpoint(address: str, session_id: Optional[str] = None) -> bool:
    """Set breakpoint (db)."""
    addr = Address(value=address)
    return await DebuggerTools.set_breakpoint(addr, session_id=session_id)


@mcp.tool()
async def list_breakpoints(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all breakpoints."""
    bps = await DebuggerTools.list_breakpoints(session_id)
    return [bp.dict() for bp in bps]


@mcp.tool()
async def get_registers(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get register values (dr)."""
    regs = await DebuggerTools.get_registers(session_id)
    return [r.dict() for r in regs]


@mcp.tool()
async def set_register(register: str, value: int, session_id: Optional[str] = None) -> bool:
    """Set register value (dr reg=value)."""
    return await DebuggerTools.set_register(register, value, session_id)


# Flag Tools


@mcp.tool()
async def list_flags(
    space: Optional[str] = None, session_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """List flags/labels (f)."""
    flags = await FlagTools.list_flags(space, session_id)
    return [f.dict() for f in flags]


@mcp.tool()
async def create_flag(
    name: str, address: str, size: int = 1, session_id: Optional[str] = None
) -> bool:
    """Create a flag/label at address (f name @ addr)."""
    addr = Address(value=address)
    return await FlagTools.create_flag(name, addr, size, session_id)


# Configuration Tools


@mcp.tool()
async def get_config(key: Optional[str] = None, session_id: Optional[str] = None) -> Any:
    """Get configuration value(s) (e)."""
    return await ConfigTools.get_config(key, session_id)


@mcp.tool()
async def set_config(key: str, value: Any, session_id: Optional[str] = None) -> bool:
    """Set configuration value (e key=value)."""
    return await ConfigTools.set_config(key, value, session_id)


@mcp.tool()
async def execute_command(
    command: str, session_id: Optional[str] = None, json_output: bool = False
) -> Any:
    """
    Execute raw Radare2 command.
    Use this for commands not yet wrapped by specific tools.
    """
    return r2_manager.execute_command(command, session_id, json_output)


# Main entry point
def main():
    """Run the MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
