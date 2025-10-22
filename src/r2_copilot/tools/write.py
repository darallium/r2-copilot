"""Write/patch tools for Radare2 MCP server."""

import logging
from pathlib import Path
from typing import Optional, Union

from r2_copilot.models.schemas import Address
from r2_copilot.server.instance import mcp
from r2_copilot.utils.r2_manager import r2_manager

logger = logging.getLogger(__name__)


class WriteTools:
    """Radare2 write/patch commands."""

    @staticmethod
    async def write_hex(
        data: Union[str, bytes], address: Optional[Address] = None, session_id: Optional[str] = None
    ) -> bool:
        """
        Write hex values at current or specified offset.
        Equivalent to 'wx' command.
        """
        try:
            if isinstance(data, bytes):
                hex_data = data.hex()
            else:
                hex_data = data.replace("0x", "").replace(" ", "")

            cmd = f"wx {hex_data}"
            if address:
                if isinstance(address.value, str):
                    cmd = f"wx {hex_data} @ {address.value}"
                else:
                    cmd = f"wx {hex_data} @ {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to write hex: {e}")
            return False

    @staticmethod
    async def write_assembly(
        assembly: str, address: Optional[Address] = None, session_id: Optional[str] = None
    ) -> bool:
        """
        Write assembly instruction.
        Equivalent to 'wa' command.
        Example: "jnz 0x400d24"
        """
        try:
            cmd = f"wa {assembly}"
            if address:
                if isinstance(address.value, str):
                    cmd = f"wa {assembly} @ {address.value}"
                else:
                    cmd = f"wa {assembly} @ {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to write assembly: {e}")
            return False

    @staticmethod
    async def write_string(
        text: str,
        address: Optional[Address] = None,
        null_terminated: bool = True,
        session_id: Optional[str] = None,
    ) -> bool:
        """
        Write string at current or specified offset.
        Equivalent to 'w' command.
        """
        try:
            if null_terminated:
                text += "\x00"

            hex_data = text.encode().hex()
            return await WriteTools.write_hex(hex_data, address, session_id)
        except Exception as e:
            logger.error(f"Failed to write string: {e}")
            return False

    @staticmethod
    async def write_value(
        value: int,
        size: int = 4,
        address: Optional[Address] = None,
        endian: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> bool:
        """
        Write value with endian conversion.
        Equivalent to 'wv' command.
        Size in bytes (1, 2, 4, 8)
        """
        try:
            cmd = f"wv{size} {value:#x}"
            if address:
                if isinstance(address.value, str):
                    cmd = f"wv{size} {value:#x} @ {address.value}"
                else:
                    cmd = f"wv{size} {value:#x} @ {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to write value: {e}")
            return False

    @staticmethod
    async def write_operation(
        operation: str,
        value: Union[int, str],
        address: Optional[Address] = None,
        size: Optional[int] = None,
        session_id: Optional[str] = None,
    ) -> bool:
        """
        Write result of operation.
        Equivalent to 'wo' commands.
        Operations: xor, add, sub, mul, div, and, or
        """
        try:
            op_map = {
                "xor": "wox",
                "add": "woa",
                "sub": "wos",
                "mul": "wom",
                "div": "wod",
                "and": "woA",
                "or": "woo",
            }

            if operation not in op_map:
                raise ValueError(f"Unknown operation: {operation}")

            cmd = f"{op_map[operation]} {value}"

            if address:
                if isinstance(address.value, str):
                    cmd = f"{cmd} @ {address.value}"
                else:
                    cmd = f"{cmd} @ {address.value:#x}"

            if size:
                cmd = f"{cmd}!{size}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to write operation: {e}")
            return False

    @staticmethod
    async def write_file(
        file_path: str,
        address: Optional[Address] = None,
        ascii_only: bool = False,
        session_id: Optional[str] = None,
    ) -> bool:
        """
        Write file contents at current or specified offset.
        Equivalent to 'wf' or 'wF' command.
        """
        try:
            if not Path(file_path).exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            cmd = "wf" if ascii_only else "wF"
            cmd = f"{cmd} {file_path}"

            if address:
                if isinstance(address.value, str):
                    cmd = f"{cmd} @ {address.value}"
                else:
                    cmd = f"{cmd} @ {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to write file: {e}")
            return False

    @staticmethod
    async def write_to_file(
        file_path: str,
        size: Optional[int] = None,
        address: Optional[Address] = None,
        session_id: Optional[str] = None,
    ) -> bool:
        """
        Write from memory to file.
        Equivalent to 'wt' command.
        """
        try:
            cmd = f"wt {file_path}"
            if size:
                cmd = f"{cmd} {size}"

            if address:
                if isinstance(address.value, str):
                    cmd = f"{cmd} @ {address.value}"
                else:
                    cmd = f"{cmd} @ {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to write to file: {e}")
            return False

    @staticmethod
    async def write_cache_commit(session_id: Optional[str] = None) -> bool:
        """
        Commit write cache.
        Equivalent to 'wc' command.
        """
        try:
            r2_manager.execute_command("wc", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to commit write cache: {e}")
            return False

    @staticmethod
    async def get_debruijn_offset(pattern: str, session_id: Optional[str] = None) -> Optional[int]:
        """
        Get offset in De Bruijn pattern.
        Equivalent to 'wopO' command.
        """
        try:
            result = r2_manager.execute_command(f"wopO {pattern}", session_id)
            if result and result.strip().isdigit():
                return int(result.strip())
            return None
        except Exception as e:
            logger.error(f"Failed to get De Bruijn offset: {e}")
            return None

    @staticmethod
    async def write_nop(
        count: int = 1, address: Optional[Address] = None, session_id: Optional[str] = None
    ) -> bool:
        """
        Write NOP instructions.
        """
        try:
            # Get architecture to determine NOP opcode
            info = r2_manager.execute_command("ij", session_id)
            import json

            if isinstance(info, str):
                info = json.loads(info)

            arch = info.get("bin", {}).get("arch", "x86")

            # Determine NOP opcode based on architecture
            nop_opcodes = {"x86": "90", "arm": "00f020e3", "mips": "00000000", "ppc": "60000000"}

            nop = nop_opcodes.get(arch, "90")
            hex_data = nop * count

            return await WriteTools.write_hex(hex_data, address, session_id)
        except Exception as e:
            logger.error(f"Failed to write NOP: {e}")
            return False


# MCP Tool Wrappers


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
