"""Search tools for Radare2 MCP server."""

from typing import List, Optional, Dict, Any
from radare2_mcp.utils.r2_manager import r2_manager
from radare2_mcp.models.schemas import (
    SearchResult,
    ROPGadget,
    Address,
)
import json
import logging

logger = logging.getLogger(__name__)


class SearchTools:
    """Radare2 search commands."""
    
    @staticmethod
    async def search_bytes(
        pattern: str,
        from_addr: Optional[int] = None,
        to_addr: Optional[int] = None,
        session_id: Optional[str] = None
    ) -> List[SearchResult]:
        """
        Search for byte pattern.
        Equivalent to '/x' command.
        Pattern should be hex string like "90909090" or "\\x90\\x90"
        """
        try:
            # Clean pattern
            pattern = pattern.replace("\\x", "").replace(" ", "")
            
            # Set search boundaries if provided
            if from_addr:
                r2_manager.execute_command(f"e search.from={from_addr:#x}", session_id)
            if to_addr:
                r2_manager.execute_command(f"e search.to={to_addr:#x}", session_id)
            
            # Search
            cmd = f"/xj {pattern}"
            results = r2_manager.execute_command(cmd, session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            search_results = []
            for r in (results or []):
                search_results.append(SearchResult(
                    offset=r.get("offset", 0),
                    size=r.get("len", 0),
                    data=bytes.fromhex(r.get("data", ""))
                ))
            
            return search_results
        except Exception as e:
            logger.error(f"Failed to search bytes: {e}")
            return []
    
    @staticmethod
    async def search_string(
        text: str,
        case_sensitive: bool = True,
        from_addr: Optional[int] = None,
        to_addr: Optional[int] = None,
        session_id: Optional[str] = None
    ) -> List[SearchResult]:
        """
        Search for string.
        Equivalent to '/' command.
        """
        try:
            # Set search boundaries if provided
            if from_addr:
                r2_manager.execute_command(f"e search.from={from_addr:#x}", session_id)
            if to_addr:
                r2_manager.execute_command(f"e search.to={to_addr:#x}", session_id)
            
            # Search
            cmd = f"/j {text}" if case_sensitive else f"/ij {text}"
            results = r2_manager.execute_command(cmd, session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            search_results = []
            for r in (results or []):
                search_results.append(SearchResult(
                    offset=r.get("offset", 0),
                    size=r.get("len", len(text)),
                    data=text.encode(),
                    string=text
                ))
            
            return search_results
        except Exception as e:
            logger.error(f"Failed to search string: {e}")
            return []
    
    @staticmethod
    async def search_rop_gadgets(
        instructions: List[str],
        max_length: int = 5,
        session_id: Optional[str] = None
    ) -> List[ROPGadget]:
        """
        Search for ROP gadgets.
        Equivalent to '/R' command.
        Example: ["pop eax", "ret"]
        """
        try:
            # Set ROP search depth
            r2_manager.execute_command(f"e rop.len={max_length}", session_id)
            
            # Build search pattern
            pattern = ";".join(instructions)
            cmd = f"/Rj {pattern}"
            
            results = r2_manager.execute_command(cmd, session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            gadgets = []
            for r in (results or []):
                gadgets.append(ROPGadget(
                    offset=r.get("offset", 0),
                    instructions=r.get("opcodes", []),
                    size=r.get("size", 0),
                    ending=instructions[-1] if instructions else "ret"
                ))
            
            return gadgets
        except Exception as e:
            logger.error(f"Failed to search ROP gadgets: {e}")
            return []
    
    @staticmethod
    async def search_assembly(
        assembly: str,
        session_id: Optional[str] = None
    ) -> List[SearchResult]:
        """
        Search for assembly instruction.
        Equivalent to '/a' command.
        Example: "jmp eax"
        """
        try:
            cmd = f"/aj {assembly}"
            results = r2_manager.execute_command(cmd, session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            search_results = []
            for r in (results or []):
                search_results.append(SearchResult(
                    offset=r.get("offset", 0),
                    size=r.get("len", 0),
                    data=bytes.fromhex(r.get("data", ""))
                ))
            
            return search_results
        except Exception as e:
            logger.error(f"Failed to search assembly: {e}")
            return []
    
    @staticmethod
    async def search_magic(
        magic_db: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for magic bytes/signatures.
        Equivalent to '/m' command.
        """
        try:
            cmd = "/mj"
            if magic_db:
                cmd = f"/mj {magic_db}"
            
            results = r2_manager.execute_command(cmd, session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            return results if results else []
        except Exception as e:
            logger.error(f"Failed to search magic: {e}")
            return []
    
    @staticmethod
    async def search_references(
        address: Address,
        session_id: Optional[str] = None
    ) -> List[SearchResult]:
        """
        Search for references to address.
        Equivalent to '/r' command.
        """
        try:
            if isinstance(address.value, str):
                cmd = f"/rj {address.value}"
            else:
                cmd = f"/rj {address.value:#x}"
            
            results = r2_manager.execute_command(cmd, session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            search_results = []
            for r in (results or []):
                search_results.append(SearchResult(
                    offset=r.get("offset", 0),
                    size=r.get("len", 0),
                    data=bytes.fromhex(r.get("data", ""))
                ))
            
            return search_results
        except Exception as e:
            logger.error(f"Failed to search references: {e}")
            return []
    
    @staticmethod
    async def get_all_strings(
        min_length: int = 4,
        session_id: Optional[str] = None
    ) -> List[SearchResult]:
        """
        Search for all strings in current section.
        Equivalent to '/z' command.
        """
        try:
            r2_manager.execute_command(f"e str.minlen={min_length}", session_id)
            
            results = r2_manager.execute_command("/zj", session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            search_results = []
            for r in (results or []):
                string_val = r.get("string", "")
                search_results.append(SearchResult(
                    offset=r.get("offset", 0),
                    size=len(string_val),
                    data=string_val.encode(),
                    string=string_val
                ))
            
            return search_results
        except Exception as e:
            logger.error(f"Failed to search strings: {e}")
            return []
    
    @staticmethod
    async def search_pattern(
        pattern: str,
        mask: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> List[SearchResult]:
        """
        Search with pattern and mask.
        Pattern can include wildcards.
        Example: pattern="909090??90", mask="fffff00ff"
        """
        try:
            if mask:
                cmd = f"/xj {pattern}:{mask}"
            else:
                cmd = f"/xj {pattern}"
            
            results = r2_manager.execute_command(cmd, session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            search_results = []
            for r in (results or []):
                search_results.append(SearchResult(
                    offset=r.get("offset", 0),
                    size=r.get("len", 0),
                    data=bytes.fromhex(r.get("data", ""))
                ))
            
            return search_results
        except Exception as e:
            logger.error(f"Failed to search pattern: {e}")
            return []
    
    @staticmethod
    async def configure_search(
        align: Optional[int] = None,
        from_addr: Optional[int] = None,
        to_addr: Optional[int] = None,
        in_section: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> bool:
        """
        Configure search parameters.
        """
        try:
            if align:
                r2_manager.execute_command(f"e search.align={align}", session_id)
            if from_addr:
                r2_manager.execute_command(f"e search.from={from_addr:#x}", session_id)
            if to_addr:
                r2_manager.execute_command(f"e search.to={to_addr:#x}", session_id)
            if in_section:
                r2_manager.execute_command(f"e search.in={in_section}", session_id)
            
            return True
        except Exception as e:
            logger.error(f"Failed to configure search: {e}")
            return False
