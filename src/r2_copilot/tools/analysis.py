"""Analysis tools for Radare2 MCP server."""

import json
import logging
from typing import Any, Dict, List, Optional

from r2_copilot.models.schemas import (
    Address,
    AnalysisResult,
    FunctionInfo,
)
from r2_copilot.server.instance import mcp
from r2_copilot.utils.r2_manager import r2_manager

logger = logging.getLogger(__name__)


class AnalysisTools:
    """Radare2 analysis commands."""

    @staticmethod
    async def analyze_all(session_id: Optional[str] = None) -> AnalysisResult:
        """
        Analyze all (functions + basic blocks).
        Equivalent to 'aa' command.
        """
        try:
            r2_manager.execute_command("aa", session_id)

            # Get analysis statistics
            funcs = r2_manager.execute_command("afl~?", session_id).strip()

            return AnalysisResult(
                success=True,
                functions_found=int(funcs) if funcs.isdigit() else 0,
                message="Analysis completed successfully",
            )
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return AnalysisResult(success=False, message=str(e))

    @staticmethod
    async def analyze_function(
        address: Optional[Address] = None, session_id: Optional[str] = None
    ) -> AnalysisResult:
        """
        Analyze function at current address or specified address.
        Equivalent to 'af' command.
        """
        try:
            cmd = "af"
            if address:
                if isinstance(address.value, str):
                    cmd = f"af @ {address.value}"
                else:
                    cmd = f"af @ {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)

            return AnalysisResult(
                success=True,
                message=f"Function analyzed at {address.value if address else 'current position'}",
            )
        except Exception as e:
            logger.error(f"Function analysis failed: {e}")
            return AnalysisResult(success=False, message=str(e))

    @staticmethod
    async def list_functions(
        session_id: Optional[str] = None, json_output: bool = True
    ) -> List[FunctionInfo]:
        """
        List all functions.
        Equivalent to 'afl' command.
        """
        try:
            if json_output:
                funcs_data = r2_manager.execute_command("aflj", session_id)
                if isinstance(funcs_data, str):
                    funcs_data = json.loads(funcs_data)

                functions = []
                for func in funcs_data:
                    functions.append(
                        FunctionInfo(
                            name=func.get("name", ""),
                            offset=func.get("offset", 0),
                            size=func.get("size", 0),
                            nargs=func.get("nargs"),
                            nlocals=func.get("nlocals"),
                            nbbs=func.get("nbbs"),
                            edges=func.get("edges"),
                            cc=func.get("cc"),
                            type=func.get("type"),
                        )
                    )
                return functions
            else:
                # Return raw text output
                result = r2_manager.execute_command("afl", session_id)
                # Parse text output if needed
                return result

        except Exception as e:
            logger.error(f"Failed to list functions: {e}")
            return []

    @staticmethod
    async def get_function_info(
        address: Optional[Address] = None, session_id: Optional[str] = None
    ) -> Optional[FunctionInfo]:
        """
        Get information about current function.
        Equivalent to 'afi' command.
        """
        try:
            cmd = "afij"
            if address:
                if isinstance(address.value, str):
                    cmd = f"afij @ {address.value}"
                else:
                    cmd = f"afij @ {address.value:#x}"

            info = r2_manager.execute_command(cmd, session_id)
            if isinstance(info, str):
                info = json.loads(info)

            if not info:
                return None

            # Handle both single function and list response
            if isinstance(info, list):
                info = info[0] if info else {}

            return FunctionInfo(
                name=info.get("name", ""),
                offset=info.get("offset", 0),
                size=info.get("size", 0),
                nargs=info.get("nargs"),
                nlocals=info.get("nlocals"),
                nbbs=info.get("nbbs"),
                edges=info.get("edges"),
                cc=info.get("cc"),
                type=info.get("type"),
            )

        except Exception as e:
            logger.error(f"Failed to get function info: {e}")
            return None

    @staticmethod
    async def rename_function(
        old_name: str, new_name: str, session_id: Optional[str] = None
    ) -> bool:
        """
        Rename a function.
        Equivalent to 'afn' command.
        """
        try:
            r2_manager.execute_command(f"afn {new_name} {old_name}", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to rename function: {e}")
            return False

    @staticmethod
    async def analyze_data(
        address: Optional[Address] = None, session_id: Optional[str] = None
    ) -> AnalysisResult:
        """
        Analyze data at address.
        Equivalent to 'ad' command.
        """
        try:
            cmd = "ad"
            if address:
                if isinstance(address.value, str):
                    cmd = f"ad @ {address.value}"
                else:
                    cmd = f"ad @ {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)

            return AnalysisResult(
                success=True,
                message=f"Data analyzed at {address.value if address else 'current position'}",
            )
        except Exception as e:
            logger.error(f"Data analysis failed: {e}")
            return AnalysisResult(success=False, message=str(e))

    @staticmethod
    async def get_xrefs_to(
        address: Address, session_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get cross references to an address.
        Equivalent to 'axt' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"axtj {address.value}"
            else:
                cmd = f"axtj {address.value:#x}"

            xrefs = r2_manager.execute_command(cmd, session_id)
            if isinstance(xrefs, str):
                xrefs = json.loads(xrefs)

            return xrefs if xrefs else []

        except Exception as e:
            logger.error(f"Failed to get xrefs: {e}")
            return []

    @staticmethod
    async def get_xrefs_from(
        address: Address, session_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get cross references from an address.
        Equivalent to 'axf' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"axfj {address.value}"
            else:
                cmd = f"axfj {address.value:#x}"

            xrefs = r2_manager.execute_command(cmd, session_id)
            if isinstance(xrefs, str):
                xrefs = json.loads(xrefs)

            return xrefs if xrefs else []

        except Exception as e:
            logger.error(f"Failed to get xrefs: {e}")
            return []

    @staticmethod
    async def analyze_opcodes(
        count: int = 1, address: Optional[Address] = None, session_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze N opcodes from current or specified offset.
        Equivalent to 'ao' command.
        """
        try:
            cmd = f"aoj {count}"
            if address:
                if isinstance(address.value, str):
                    cmd = f"aoj {count} @ {address.value}"
                else:
                    cmd = f"aoj {count} @ {address.value:#x}"

            opcodes = r2_manager.execute_command(cmd, session_id)
            if isinstance(opcodes, str):
                opcodes = json.loads(opcodes)

            return opcodes if opcodes else []

        except Exception as e:
            logger.error(f"Failed to analyze opcodes: {e}")
            return []

    @staticmethod
    async def define_function(
        address: Address, size: int, name: Optional[str] = None, session_id: Optional[str] = None
    ) -> bool:
        """
        Define a function manually.
        Equivalent to 'af+' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"af+ {address.value} {size}"
            else:
                cmd = f"af+ {address.value:#x} {size}"

            if name:
                cmd += f" {name}"

            r2_manager.execute_command(cmd, session_id)
            return True

        except Exception as e:
            logger.error(f"Failed to define function: {e}")
            return False

    @staticmethod
    async def undefine_function(address: Address, session_id: Optional[str] = None) -> bool:
        """
        Remove function metadata.
        Equivalent to 'af-' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"af- {address.value}"
            else:
                cmd = f"af- {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)
            return True

        except Exception as e:
            logger.error(f"Failed to undefine function: {e}")
            return False


# MCP Tool Wrappers


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
