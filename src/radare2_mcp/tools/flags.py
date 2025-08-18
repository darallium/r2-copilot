"""Flag management tools for Radare2 MCP server."""

import json
import logging
from typing import List, Optional

from radare2_mcp.models.schemas import Address, Flag
from radare2_mcp.utils.r2_manager import r2_manager

logger = logging.getLogger(__name__)


class FlagTools:
    """Radare2 flag (label) commands."""

    @staticmethod
    async def list_flags(
        space: Optional[str] = None, session_id: Optional[str] = None
    ) -> List[Flag]:
        """
        List all flags or flags in specific space.
        Equivalent to 'f' command.
        """
        try:
            if space:
                r2_manager.execute_command(f"fs {space}", session_id)

            flags_data = r2_manager.execute_command("fj", session_id)
            if isinstance(flags_data, str):
                flags_data = json.loads(flags_data)

            flags = []
            for f in flags_data or []:
                flags.append(
                    Flag(
                        name=f.get("name", ""),
                        offset=f.get("offset", 0),
                        size=f.get("size", 1),
                        space=f.get("space"),
                    )
                )
            return flags
        except Exception as e:
            logger.error(f"Failed to list flags: {e}")
            return []

    @staticmethod
    async def create_flag(
        name: str, address: Address, size: int = 1, session_id: Optional[str] = None
    ) -> bool:
        """
        Create a flag at address.
        Equivalent to 'f name @ offset' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"f {name} {size} @ {address.value}"
            else:
                cmd = f"f {name} {size} @ {address.value:#x}"

            r2_manager.execute_command(cmd, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to create flag: {e}")
            return False

    @staticmethod
    async def remove_flag(name: str, session_id: Optional[str] = None) -> bool:
        """
        Remove a flag.
        Equivalent to 'f-name' command.
        """
        try:
            r2_manager.execute_command(f"f-{name}", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to remove flag: {e}")
            return False

    @staticmethod
    async def rename_flag(old_name: str, new_name: str, session_id: Optional[str] = None) -> bool:
        """
        Rename a flag.
        Equivalent to 'fr' command.
        """
        try:
            r2_manager.execute_command(f"fr {old_name} {new_name}", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to rename flag: {e}")
            return False

    @staticmethod
    async def get_flag_at(address: Address, session_id: Optional[str] = None) -> Optional[Flag]:
        """
        Get flag at specific address.
        Equivalent to 'fd' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"fdj @ {address.value}"
            else:
                cmd = f"fdj @ {address.value:#x}"

            result = r2_manager.execute_command(cmd, session_id)
            if isinstance(result, str):
                result = json.loads(result)

            if result:
                return Flag(
                    name=result.get("name", ""),
                    offset=result.get("offset", 0),
                    size=result.get("size", 1),
                    space=result.get("space"),
                )
            return None
        except Exception as e:
            logger.error(f"Failed to get flag at address: {e}")
            return None

    @staticmethod
    async def list_flag_spaces(session_id: Optional[str] = None) -> List[str]:
        """
        List all flag spaces.
        Equivalent to 'fs' command.
        """
        try:
            result = r2_manager.execute_command("fsj", session_id)
            if isinstance(result, str):
                result = json.loads(result)

            return [s.get("name", "") for s in (result or [])]
        except Exception as e:
            logger.error(f"Failed to list flag spaces: {e}")
            return []

    @staticmethod
    async def change_flag_space(space: str, session_id: Optional[str] = None) -> bool:
        """
        Change to specific flag space.
        Equivalent to 'fs space' command.
        """
        try:
            r2_manager.execute_command(f"fs {space}", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to change flag space: {e}")
            return False
