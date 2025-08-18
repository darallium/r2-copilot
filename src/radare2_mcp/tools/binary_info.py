"""Binary information tools for Radare2 MCP server."""

import json
import logging
from typing import Any, Dict, List, Optional

from radare2_mcp.models.schemas import (
    SectionInfo,
    StringInfo,
    SymbolInfo,
)
from radare2_mcp.utils.r2_manager import r2_manager

logger = logging.getLogger(__name__)


class BinaryInfoTools:
    """Radare2 binary information commands."""

    @staticmethod
    async def get_info(session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get file information.
        Equivalent to 'i' and 'ij' commands.
        """
        try:
            info = r2_manager.execute_command("ij", session_id)
            if isinstance(info, str):
                info = json.loads(info)
            return info
        except Exception as e:
            logger.error(f"Failed to get file info: {e}")
            return {}

    @staticmethod
    async def get_sections(session_id: Optional[str] = None) -> List[SectionInfo]:
        """
        Get binary sections.
        Equivalent to 'iS' command.
        """
        try:
            sections_data = r2_manager.execute_command("iSj", session_id)
            if isinstance(sections_data, str):
                sections_data = json.loads(sections_data)

            sections = []
            for sect in sections_data:
                sections.append(
                    SectionInfo(
                        name=sect.get("name", ""),
                        size=sect.get("size", 0),
                        vsize=sect.get("vsize", 0),
                        offset=sect.get("paddr", 0),
                        vaddr=sect.get("vaddr", 0),
                        permissions=sect.get("perm", ""),
                        type=sect.get("type"),
                    )
                )
            return sections
        except Exception as e:
            logger.error(f"Failed to get sections: {e}")
            return []

    @staticmethod
    async def get_symbols(
        imports_only: bool = False, exports_only: bool = False, session_id: Optional[str] = None
    ) -> List[SymbolInfo]:
        """
        Get binary symbols.
        Equivalent to 'is' command.
        """
        try:
            cmd = "isj"
            if imports_only:
                cmd = "iij"  # imports
            elif exports_only:
                cmd = "iej"  # exports/entrypoints

            symbols_data = r2_manager.execute_command(cmd, session_id)
            if isinstance(symbols_data, str):
                symbols_data = json.loads(symbols_data)

            symbols = []
            for sym in symbols_data:
                symbols.append(
                    SymbolInfo(
                        name=sym.get("name", ""),
                        offset=sym.get("vaddr", 0),
                        size=sym.get("size", 0),
                        type=sym.get("type", ""),
                        bind=sym.get("bind"),
                        is_imported=sym.get("is_imported", False),
                    )
                )
            return symbols
        except Exception as e:
            logger.error(f"Failed to get symbols: {e}")
            return []

    @staticmethod
    async def get_strings(
        data_section_only: bool = True, session_id: Optional[str] = None
    ) -> List[StringInfo]:
        """
        Get strings from binary.
        Equivalent to 'iz' (data section) or 'izz' (whole binary) commands.
        """
        try:
            cmd = "izj" if data_section_only else "izzj"
            strings_data = r2_manager.execute_command(cmd, session_id)
            if isinstance(strings_data, str):
                strings_data = json.loads(strings_data)

            strings = []
            for s in strings_data:
                strings.append(
                    StringInfo(
                        offset=s.get("vaddr", 0),
                        length=s.get("length", 0),
                        type=s.get("type", ""),
                        string=s.get("string", ""),
                        section=s.get("section"),
                    )
                )
            return strings
        except Exception as e:
            logger.error(f"Failed to get strings: {e}")
            return []

    @staticmethod
    async def get_imports(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get imported functions.
        Equivalent to 'ii' command.
        """
        try:
            imports = r2_manager.execute_command("iij", session_id)
            if isinstance(imports, str):
                imports = json.loads(imports)
            return imports if imports else []
        except Exception as e:
            logger.error(f"Failed to get imports: {e}")
            return []

    @staticmethod
    async def get_exports(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get exported functions.
        Equivalent to 'iE' command.
        """
        try:
            exports = r2_manager.execute_command("iEj", session_id)
            if isinstance(exports, str):
                exports = json.loads(exports)
            return exports if exports else []
        except Exception as e:
            logger.error(f"Failed to get exports: {e}")
            return []

    @staticmethod
    async def get_entrypoint(session_id: Optional[str] = None) -> Optional[int]:
        """
        Get binary entrypoint.
        Equivalent to 'ie' command.
        """
        try:
            entry = r2_manager.execute_command("iej", session_id)
            if isinstance(entry, str):
                entry = json.loads(entry)

            if entry and len(entry) > 0:
                return entry[0].get("vaddr", 0)
            return None
        except Exception as e:
            logger.error(f"Failed to get entrypoint: {e}")
            return None

    @staticmethod
    async def get_libraries(session_id: Optional[str] = None) -> List[str]:
        """
        Get linked libraries.
        Equivalent to 'il' command.
        """
        try:
            libs = r2_manager.execute_command("ilj", session_id)
            if isinstance(libs, str):
                libs = json.loads(libs)
            return libs if libs else []
        except Exception as e:
            logger.error(f"Failed to get libraries: {e}")
            return []

    @staticmethod
    async def get_relocations(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get relocations.
        Equivalent to 'ir' command.
        """
        try:
            relocs = r2_manager.execute_command("irj", session_id)
            if isinstance(relocs, str):
                relocs = json.loads(relocs)
            return relocs if relocs else []
        except Exception as e:
            logger.error(f"Failed to get relocations: {e}")
            return []

    @staticmethod
    async def get_headers(session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get file headers information.
        Equivalent to 'ih' command.
        """
        try:
            headers = r2_manager.execute_command("ihj", session_id)
            if isinstance(headers, str):
                headers = json.loads(headers)
            return headers if headers else {}
        except Exception as e:
            logger.error(f"Failed to get headers: {e}")
            return {}

    @staticmethod
    async def get_binary_info(session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive binary information.
        Equivalent to 'iI' command.
        """
        try:
            info = r2_manager.execute_command("iIj", session_id)
            if isinstance(info, str):
                info = json.loads(info)
            return info if info else {}
        except Exception as e:
            logger.error(f"Failed to get binary info: {e}")
            return {}

    @staticmethod
    async def check_security(session_id: Optional[str] = None) -> Dict[str, bool]:
        """
        Check binary security features (NX, PIE, Canary, etc.).
        """
        try:
            info = await BinaryInfoTools.get_binary_info(session_id)

            return {
                "nx": info.get("nx", False),
                "pic": info.get("pic", False),  # Position Independent Code (PIE)
                "canary": info.get("canary", False),
                "crypto": info.get("crypto", False),
                "stripped": info.get("stripped", False),
                "static": info.get("static", False),
                "relocs": info.get("relocs", False),
            }
        except Exception as e:
            logger.error(f"Failed to check security: {e}")
            return {}
