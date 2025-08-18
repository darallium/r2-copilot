"""Navigation tools for Radare2 MCP server."""

from typing import Optional, List
from radare2_mcp.utils.r2_manager import r2_manager
from radare2_mcp.models.schemas import Address
import logging

logger = logging.getLogger(__name__)


class NavigationTools:
    """Radare2 navigation commands."""
    
    @staticmethod
    async def seek(
        address: Address,
        session_id: Optional[str] = None
    ) -> int:
        """
        Seek to address or symbol.
        Equivalent to 's' command.
        Returns new position.
        """
        try:
            return r2_manager.seek(address.value, session_id)
        except Exception as e:
            logger.error(f"Failed to seek: {e}")
            return 0
    
    @staticmethod
    async def seek_relative(
        offset: int,
        session_id: Optional[str] = None
    ) -> int:
        """
        Seek relative to current position.
        Positive for forward, negative for backward.
        """
        try:
            if offset >= 0:
                cmd = f"s+{offset}"
            else:
                cmd = f"s{offset}"
            
            r2_manager.execute_command(cmd, session_id)
            return r2_manager.get_current_address(session_id)
        except Exception as e:
            logger.error(f"Failed to seek relative: {e}")
            return 0
    
    @staticmethod
    async def seek_undo(
        session_id: Optional[str] = None
    ) -> int:
        """
        Undo seek.
        Equivalent to 's-' command.
        """
        try:
            r2_manager.execute_command("s-", session_id)
            return r2_manager.get_current_address(session_id)
        except Exception as e:
            logger.error(f"Failed to undo seek: {e}")
            return 0
    
    @staticmethod
    async def seek_redo(
        session_id: Optional[str] = None
    ) -> int:
        """
        Redo seek.
        Equivalent to 's+' command.
        """
        try:
            r2_manager.execute_command("s+", session_id)
            return r2_manager.get_current_address(session_id)
        except Exception as e:
            logger.error(f"Failed to redo seek: {e}")
            return 0
    
    @staticmethod
    async def get_current_address(
        session_id: Optional[str] = None
    ) -> int:
        """
        Get current address.
        Equivalent to 's' command without arguments.
        """
        try:
            return r2_manager.get_current_address(session_id)
        except Exception as e:
            logger.error(f"Failed to get current address: {e}")
            return 0
    
    @staticmethod
    async def set_block_size(
        size: int,
        session_id: Optional[str] = None
    ) -> bool:
        """
        Set block size.
        Equivalent to 'b' command.
        """
        try:
            r2_manager.execute_command(f"b {size}", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to set block size: {e}")
            return False
    
    @staticmethod
    async def get_block_size(
        session_id: Optional[str] = None
    ) -> int:
        """
        Get current block size.
        Equivalent to 'b' command without arguments.
        """
        try:
            result = r2_manager.execute_command("b", session_id)
            if result and result.strip().startswith("0x"):
                return int(result.strip(), 16)
            elif result and result.strip().isdigit():
                return int(result.strip())
            return 0
        except Exception as e:
            logger.error(f"Failed to get block size: {e}")
            return 0
    
    @staticmethod
    async def seek_to_function(
        function_name: str,
        session_id: Optional[str] = None
    ) -> int:
        """
        Seek to function by name.
        """
        try:
            # Functions usually have sym. or fcn. prefix
            if not function_name.startswith(("sym.", "fcn.", "sub.")):
                # Try different prefixes
                for prefix in ["sym.", "fcn.", "sub."]:
                    try:
                        addr = r2_manager.seek(f"{prefix}{function_name}", session_id)
                        if addr:
                            return addr
                    except:
                        continue
            
            return r2_manager.seek(function_name, session_id)
        except Exception as e:
            logger.error(f"Failed to seek to function: {e}")
            return 0
    
    @staticmethod
    async def seek_to_string(
        string_ref: str,
        session_id: Optional[str] = None
    ) -> int:
        """
        Seek to string reference.
        """
        try:
            # Strings usually have str. prefix
            if not string_ref.startswith("str."):
                string_ref = f"str.{string_ref}"
            
            return r2_manager.seek(string_ref, session_id)
        except Exception as e:
            logger.error(f"Failed to seek to string: {e}")
            return 0
    
    @staticmethod
    async def seek_history(
        session_id: Optional[str] = None
    ) -> List[int]:
        """
        Get seek history.
        Equivalent to 's*' command.
        """
        try:
            result = r2_manager.execute_command("s*", session_id)
            history = []
            
            for line in result.strip().split('\n'):
                if line.startswith("f undo_"):
                    parts = line.split()
                    if len(parts) >= 4:
                        addr = parts[3]
                        if addr.startswith("0x"):
                            history.append(int(addr, 16))
            
            return history
        except Exception as e:
            logger.error(f"Failed to get seek history: {e}")
            return []
    
    @staticmethod
    async def seek_to_register(
        register: str,
        session_id: Optional[str] = None
    ) -> int:
        """
        Seek to address in register.
        Example: "eax", "rsp"
        """
        try:
            cmd = f"s ${register}"
            r2_manager.execute_command(cmd, session_id)
            return r2_manager.get_current_address(session_id)
        except Exception as e:
            logger.error(f"Failed to seek to register: {e}")
            return 0
