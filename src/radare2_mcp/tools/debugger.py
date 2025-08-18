"""Debugger tools for Radare2 MCP server."""

import json
import logging
from typing import Any, Dict, List, Optional

from radare2_mcp.models.schemas import (
    Address,
    Breakpoint,
    MemoryMap,
    RegisterState,
)
from radare2_mcp.utils.r2_manager import r2_manager

logger = logging.getLogger(__name__)


class DebuggerTools:
    """Radare2 debugger commands."""

    @staticmethod
    async def continue_execution(session_id: Optional[str] = None) -> bool:
        """
        Continue program execution.
        Equivalent to 'dc' command.
        """
        try:
            r2_manager.execute_command("dc", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to continue execution: {e}")
            return False

    @staticmethod
    async def continue_until(address: Address, session_id: Optional[str] = None) -> bool:
        """
        Continue until address.
        Equivalent to 'dcu' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"dcu {address.value}"
            else:
                cmd = f"dcu {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to continue until: {e}")
            return False

    @staticmethod
    async def step_into(session_id: Optional[str] = None) -> bool:
        """
        Step into (single step).
        Equivalent to 'ds' command.
        """
        try:
            r2_manager.execute_command("ds", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to step: {e}")
            return False

    @staticmethod
    async def step_over(session_id: Optional[str] = None) -> bool:
        """
        Step over.
        Equivalent to 'dso' command.
        """
        try:
            r2_manager.execute_command("dso", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to step over: {e}")
            return False

    @staticmethod
    async def step_out(session_id: Optional[str] = None) -> bool:
        """
        Step out of current function.
        Equivalent to 'dsu' command.
        """
        try:
            r2_manager.execute_command("dsu", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to step out: {e}")
            return False

    @staticmethod
    async def skip_instruction(session_id: Optional[str] = None) -> bool:
        """
        Skip current instruction.
        Equivalent to 'dss' command.
        """
        try:
            r2_manager.execute_command("dss", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to skip instruction: {e}")
            return False

    @staticmethod
    async def set_breakpoint(
        address: Address, size: int = 1, session_id: Optional[str] = None
    ) -> bool:
        """
        Set breakpoint at address.
        Equivalent to 'db' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"db {address.value}"
            else:
                cmd = f"db {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to set breakpoint: {e}")
            return False

    @staticmethod
    async def remove_breakpoint(address: Address, session_id: Optional[str] = None) -> bool:
        """
        Remove breakpoint at address.
        Equivalent to 'db-' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"db- {address.value}"
            else:
                cmd = f"db- {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to remove breakpoint: {e}")
            return False

    @staticmethod
    async def list_breakpoints(session_id: Optional[str] = None) -> List[Breakpoint]:
        """
        List all breakpoints.
        Equivalent to 'db' command.
        """
        try:
            bps = r2_manager.execute_command("dbj", session_id)
            if isinstance(bps, str):
                bps = json.loads(bps)

            breakpoints = []
            for bp in bps or []:
                breakpoints.append(
                    Breakpoint(
                        address=bp.get("addr", 0),
                        size=bp.get("size", 1),
                        enabled=bp.get("enabled", True),
                        condition=bp.get("cond"),
                        commands=bp.get("cmds"),
                        hits=bp.get("hits", 0),
                    )
                )
            return breakpoints
        except Exception as e:
            logger.error(f"Failed to list breakpoints: {e}")
            return []

    @staticmethod
    async def get_registers(session_id: Optional[str] = None) -> List[RegisterState]:
        """
        Get register values.
        Equivalent to 'dr' command.
        """
        try:
            regs = r2_manager.execute_command("drj", session_id)
            if isinstance(regs, str):
                regs = json.loads(regs)

            registers = []
            for name, value in (regs or {}).items():
                # Determine register size based on name
                size = 8  # default
                if name.startswith("e"):  # eax, ebx, etc.
                    size = 4
                elif name.startswith("r"):  # rax, rbx, etc.
                    size = 8
                elif name in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"]:
                    size = 1
                elif name in ["ax", "bx", "cx", "dx", "sp", "bp", "si", "di"]:
                    size = 2

                registers.append(RegisterState(name=name, value=value, size=size))
            return registers
        except Exception as e:
            logger.error(f"Failed to get registers: {e}")
            return []

    @staticmethod
    async def set_register(register: str, value: int, session_id: Optional[str] = None) -> bool:
        """
        Set register value.
        Equivalent to 'dr register=value' command.
        """
        try:
            cmd = f"dr {register}={value:#x}"
            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to set register: {e}")
            return False

    @staticmethod
    async def get_memory_maps(session_id: Optional[str] = None) -> List[MemoryMap]:
        """
        Get memory maps.
        Equivalent to 'dm' command.
        """
        try:
            maps = r2_manager.execute_command("dmj", session_id)
            if isinstance(maps, str):
                maps = json.loads(maps)

            memory_maps = []
            for m in maps or []:
                memory_maps.append(
                    MemoryMap(
                        start=m.get("addr", 0),
                        end=m.get("addr_end", 0),
                        size=m.get("size", 0),
                        permissions=m.get("perm", ""),
                        name=m.get("name"),
                        file=m.get("file"),
                    )
                )
            return memory_maps
        except Exception as e:
            logger.error(f"Failed to get memory maps: {e}")
            return []

    @staticmethod
    async def get_backtrace(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get backtrace.
        Equivalent to 'dbt' command.
        """
        try:
            bt = r2_manager.execute_command("dbtj", session_id)
            if isinstance(bt, str):
                bt = json.loads(bt)
            return bt if bt else []
        except Exception as e:
            logger.error(f"Failed to get backtrace: {e}")
            return []

    @staticmethod
    async def conditional_step(condition: str, session_id: Optional[str] = None) -> bool:
        """
        Conditional step.
        Equivalent to 'dsi' command.
        Example: "eax==3,ecx>0"
        """
        try:
            cmd = f"dsi {condition}"
            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed conditional step: {e}")
            return False

    @staticmethod
    async def continue_until_syscall(
        syscall: Optional[str] = None, session_id: Optional[str] = None
    ) -> bool:
        """
        Continue until syscall.
        Equivalent to 'dcs' command.
        """
        try:
            cmd = "dcs"
            if syscall:
                cmd = f"dcs {syscall}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to continue until syscall: {e}")
            return False

    @staticmethod
    async def continue_until_call(session_id: Optional[str] = None) -> bool:
        """
        Continue until next call.
        Equivalent to 'dcc' command.
        """
        try:
            r2_manager.execute_command("dcc", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to continue until call: {e}")
            return False

    @staticmethod
    async def restart_debug(session_id: Optional[str] = None) -> bool:
        """
        Restart debugging session.
        Equivalent to 'do' command.
        """
        try:
            r2_manager.execute_command("do", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to restart debug: {e}")
            return False
