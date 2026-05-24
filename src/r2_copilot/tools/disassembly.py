"""Disassembly and print tools for Radare2 MCP server."""

import json
import logging
from typing import Any, Dict, List, Optional, Union

from r2_copilot.models.schemas import (
    Address,
    DisassemblyLine,
    OutputFormat,
)
from r2_copilot.server.instance import mcp
from r2_copilot.utils.r2_manager import r2_manager

logger = logging.getLogger(__name__)


class DisassemblyTools:
    """Radare2 disassembly and print commands."""

    @staticmethod
    async def disassemble(
        count: int = 10,
        address: Optional[Address] = None,
        session_id: Optional[str] = None,
    ) -> List[DisassemblyLine]:
        """
        Disassemble N instructions.
        Equivalent to 'pd' command.
        """
        try:
            cmd = f"pdj {count}"
            if address:
                if isinstance(address.value, str):
                    cmd = f"pdj {count} @ {address.value}"
                else:
                    cmd = f"pdj {count} @ {address.value:#x}"

            disasm = r2_manager.execute_command(cmd, session_id)
            if isinstance(disasm, str):
                disasm = json.loads(disasm)

            lines = []
            for line in disasm:
                lines.append(
                    DisassemblyLine(
                        offset=line.get("offset", 0),
                        size=line.get("size", 0),
                        opcode=line.get("opcode", ""),
                        bytes=line.get("bytes", ""),
                        instruction=line.get("disasm", ""),
                        comment=line.get("comment"),
                        xrefs=line.get("xrefs"),
                        flags=line.get("flags"),
                    )
                )
            return lines
        except Exception as e:
            logger.error(f"Failed to disassemble: {e}")
            return []

    @staticmethod
    async def disassemble_function(
        address: Optional[Address] = None, session_id: Optional[str] = None
    ) -> List[DisassemblyLine]:
        """
        Disassemble function.
        Equivalent to 'pdf' command.
        """
        try:
            cmd = "pdfj"
            if address:
                if isinstance(address.value, str):
                    cmd = f"pdfj @ {address.value}"
                else:
                    cmd = f"pdfj @ {address.value:#x}"

            disasm = r2_manager.execute_command(cmd, session_id)
            if isinstance(disasm, str):
                disasm = json.loads(disasm)

            # pdf returns ops array
            ops = disasm.get("ops", []) if isinstance(disasm, dict) else disasm

            lines = []
            for op in ops:
                lines.append(
                    DisassemblyLine(
                        offset=op.get("offset", 0),
                        size=op.get("size", 0),
                        opcode=op.get("opcode", ""),
                        bytes=op.get("bytes", ""),
                        instruction=op.get("disasm", ""),
                        comment=op.get("comment"),
                        xrefs=op.get("xrefs"),
                        flags=op.get("flags"),
                    )
                )
            return lines
        except Exception as e:
            logger.error(f"Failed to disassemble function: {e}")
            return []

    @staticmethod
    async def print_hex(
        size: int = 64,
        address: Optional[Address] = None,
        session_id: Optional[str] = None,
    ) -> str:
        """
        Print hexdump.
        Equivalent to 'px' command.
        """
        try:
            cmd = f"px {size}"
            if address:
                if isinstance(address.value, str):
                    cmd = f"px {size} @ {address.value}"
                else:
                    cmd = f"px {size} @ {address.value:#x}"

            return r2_manager.execute_command(cmd, session_id)
        except Exception as e:
            logger.error(f"Failed to print hex: {e}")
            return ""

    @staticmethod
    async def print_string(
        address: Address, length: Optional[int] = None, session_id: Optional[str] = None
    ) -> str:
        """
        Print zero-terminated string.
        Equivalent to 'psz' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"psz @ {address.value}"
            else:
                cmd = f"psz @ {address.value:#x}"

            if length:
                cmd = f"ps {length} @ {address.value}"

            return r2_manager.execute_command(cmd, session_id)
        except Exception as e:
            logger.error(f"Failed to print string: {e}")
            return ""

    @staticmethod
    async def print_instructions(
        count: int = 10,
        address: Optional[Address] = None,
        session_id: Optional[str] = None,
    ) -> List[str]:
        """
        Print instructions only (no addresses, xrefs).
        Equivalent to 'pi' command.
        """
        try:
            cmd = f"pi {count}"
            if address:
                if isinstance(address.value, str):
                    cmd = f"pi {count} @ {address.value}"
                else:
                    cmd = f"pi {count} @ {address.value:#x}"

            result = r2_manager.execute_command(cmd, session_id)
            return result.strip().split("\n") if result else []
        except Exception as e:
            logger.error(f"Failed to print instructions: {e}")
            return []

    @staticmethod
    async def print_bytes(
        count: int = 16,
        address: Optional[Address] = None,
        format: OutputFormat = OutputFormat.HEX,
        session_id: Optional[str] = None,
    ) -> Union[str, bytes]:
        """
        Print N bytes in various formats.
        Equivalent to 'p8', 'pcp', etc.
        """
        try:
            if format == OutputFormat.HEX:
                cmd = f"p8 {count}"
            elif format == OutputFormat.PYTHON:
                cmd = f"pcp {count}"
            elif format == OutputFormat.C:
                cmd = f"pc {count}"
            else:
                cmd = f"p8 {count}"

            if address:
                if isinstance(address.value, str):
                    cmd = f"{cmd} @ {address.value}"
                else:
                    cmd = f"{cmd} @ {address.value:#x}"

            result = r2_manager.execute_command(cmd, session_id)

            if format == OutputFormat.HEX and result:
                return bytes.fromhex(result.strip())
            return result
        except Exception as e:
            logger.error(f"Failed to print bytes: {e}")
            return b"" if format == OutputFormat.HEX else ""

    @staticmethod
    async def print_words(
        count: int = 8,
        address: Optional[Address] = None,
        session_id: Optional[str] = None,
    ) -> str:
        """
        Print hexdump of N words.
        Equivalent to 'pxw' command.
        """
        try:
            cmd = f"pxw {count * 4}"  # words are 4 bytes
            if address:
                if isinstance(address.value, str):
                    cmd = f"pxw {count * 4} @ {address.value}"
                else:
                    cmd = f"pxw {count * 4} @ {address.value:#x}"

            return r2_manager.execute_command(cmd, session_id)
        except Exception as e:
            logger.error(f"Failed to print words: {e}")
            return ""

    @staticmethod
    async def print_disassembled_bytes(
        size: int = 32,
        address: Optional[Address] = None,
        session_id: Optional[str] = None,
    ) -> str:
        """
        Print N bytes disassembled.
        Equivalent to 'pD' command.
        """
        try:
            cmd = f"pD {size}"
            if address:
                if isinstance(address.value, str):
                    cmd = f"pD {size} @ {address.value}"
                else:
                    cmd = f"pD {size} @ {address.value:#x}"

            return r2_manager.execute_command(cmd, session_id)
        except Exception as e:
            logger.error(f"Failed to print disassembled bytes: {e}")
            return ""

    @staticmethod
    async def print_entropy(
        address: Optional[Address] = None, session_id: Optional[str] = None
    ) -> str:
        """
        Print entropy graph.
        Equivalent to 'p=' command.
        """
        try:
            cmd = "p="
            if address:
                if isinstance(address.value, str):
                    cmd = f"p= @ {address.value}"
                else:
                    cmd = f"p= @ {address.value:#x}"

            return r2_manager.execute_command(cmd, session_id)
        except Exception as e:
            logger.error(f"Failed to print entropy: {e}")
            return ""


# MCP Tool Wrappers


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
