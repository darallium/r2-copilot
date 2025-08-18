"""Configuration tools for Radare2 MCP server."""

from typing import Any, Dict, List, Optional
from radare2_mcp.utils.r2_manager import r2_manager
from radare2_mcp.models.schemas import ConfigProperty
import logging

logger = logging.getLogger(__name__)


class ConfigTools:
    """Radare2 configuration commands."""
    
    @staticmethod
    async def get_config(
        key: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> Any:
        """
        Get configuration value(s).
        Equivalent to 'e' command.
        """
        try:
            if key:
                result = r2_manager.execute_command(f"e {key}", session_id)
                return result.strip() if result else None
            else:
                # Get all config
                result = r2_manager.execute_command("e", session_id)
                config = {}
                for line in result.strip().split('\n'):
                    if '=' in line:
                        k, v = line.split('=', 1)
                        config[k.strip()] = v.strip()
                return config
        except Exception as e:
            logger.error(f"Failed to get config: {e}")
            return None
    
    @staticmethod
    async def set_config(
        key: str,
        value: Any,
        session_id: Optional[str] = None
    ) -> bool:
        """
        Set configuration value.
        Equivalent to 'e key=value' command.
        """
        try:
            r2_manager.execute_command(f"e {key}={value}", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to set config: {e}")
            return False
    
    @staticmethod
    async def get_config_description(
        key: str,
        session_id: Optional[str] = None
    ) -> str:
        """
        Get configuration property description.
        Equivalent to 'e? key' command.
        """
        try:
            result = r2_manager.execute_command(f"e? {key}", session_id)
            return result.strip() if result else ""
        except Exception as e:
            logger.error(f"Failed to get config description: {e}")
            return ""
    
    @staticmethod
    async def set_common_configs(
        asm_pseudo: Optional[bool] = None,
        asm_describe: Optional[bool] = None,
        asm_tabs: Optional[bool] = None,
        asm_emu: Optional[bool] = None,
        scr_utf8: Optional[bool] = None,
        scr_color: Optional[int] = None,
        dbg_follow_child: Optional[bool] = None,
        write_mode: Optional[bool] = None,
        session_id: Optional[str] = None
    ) -> bool:
        """
        Set commonly used configuration options.
        """
        try:
            configs = {
                "asm.pseudo": asm_pseudo,
                "asm.describe": asm_describe,
                "asm.tabs": asm_tabs,
                "asm.emu": asm_emu,
                "scr.utf8": scr_utf8,
                "scr.color": scr_color,
                "dbg.follow.child": dbg_follow_child,
                "io.cache": write_mode,  # Enable cache for write mode
            }
            
            for key, value in configs.items():
                if value is not None:
                    if isinstance(value, bool):
                        value = "true" if value else "false"
                    await ConfigTools.set_config(key, value, session_id)
            
            return True
        except Exception as e:
            logger.error(f"Failed to set common configs: {e}")
            return False
    
    @staticmethod
    async def set_architecture(
        arch: str,
        bits: Optional[int] = None,
        session_id: Optional[str] = None
    ) -> bool:
        """
        Set architecture and bits.
        """
        try:
            await ConfigTools.set_config("asm.arch", arch, session_id)
            if bits:
                await ConfigTools.set_config("asm.bits", bits, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to set architecture: {e}")
            return False
    
    @staticmethod
    async def set_endianness(
        big_endian: bool,
        session_id: Optional[str] = None
    ) -> bool:
        """
        Set endianness.
        """
        try:
            value = "big" if big_endian else "little"
            await ConfigTools.set_config("cfg.bigendian", value, session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to set endianness: {e}")
            return False
    
    @staticmethod
    async def set_theme(
        theme: str,
        session_id: Optional[str] = None
    ) -> bool:
        """
        Set color theme.
        Equivalent to 'eco' command.
        Available themes: solarized, dark, white, etc.
        """
        try:
            r2_manager.execute_command(f"eco {theme}", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to set theme: {e}")
            return False
    
    @staticmethod
    async def list_themes(
        session_id: Optional[str] = None
    ) -> List[str]:
        """
        List available color themes.
        Equivalent to 'eco' command.
        """
        try:
            result = r2_manager.execute_command("eco", session_id)
            themes = []
            for line in result.strip().split('\n'):
                if line and not line.startswith(' '):
                    themes.append(line.strip())
            return themes
        except Exception as e:
            logger.error(f"Failed to list themes: {e}")
            return []
    
    @staticmethod
    async def reset_config(
        session_id: Optional[str] = None
    ) -> bool:
        """
        Reset configuration to defaults.
        """
        try:
            r2_manager.execute_command("e-", session_id)
            return True
        except Exception as e:
            logger.error(f"Failed to reset config: {e}")
            return False
