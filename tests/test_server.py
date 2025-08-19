"""Tests for the main MCP server."""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from radare2_mcp import server


@pytest.mark.asyncio
class TestMCPServer:
    """Test MCP server functionality."""
    
    async def test_create_session(self, sample_binary):
        """Test creating a session through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="test_mcp"
        )
        
        assert session.session_id == "test_mcp"
        assert session.file_path == sample_binary
        
        # Cleanup
        await server.close_session("test_mcp")
    
    async def test_list_sessions(self, sample_binary):
        """Test listing sessions."""
        # Create multiple sessions
        session1 = await server.create_session(
            file_path=sample_binary,
            session_name="mcp1"
        )
        session2 = await server.create_session(
            file_path=sample_binary,
            session_name="mcp2"
        )
        
        sessions = await server.list_sessions()
        
        assert len(sessions) >= 2
        session_ids = [s.session_id for s in sessions]
        assert "mcp1" in session_ids
        assert "mcp2" in session_ids
        
        # Cleanup
        await server.close_session("mcp1")
        await server.close_session("mcp2")
    
    async def test_analyze_all(self, sample_binary):
        """Test analysis through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="analyze_test"
        )
        
        result = await server.analyze_all("analyze_test")
        
        assert result["success"] is True
        assert "message" in result
        
        # Cleanup
        await server.close_session("analyze_test")
    
    async def test_list_functions(self, sample_binary):
        """Test listing functions through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="func_test"
        )
        
        await server.analyze_all("func_test")
        functions = await server.list_functions("func_test")
        
        assert isinstance(functions, list)
        
        # Cleanup
        await server.close_session("func_test")
    
    async def test_get_binary_info(self, sample_binary):
        """Test getting binary info through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="info_test"
        )
        
        info = await server.get_binary_info("info_test")
        
        assert isinstance(info, dict)
        
        # Cleanup
        await server.close_session("info_test")
    
    async def test_disassemble(self, sample_binary):
        """Test disassembly through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="disasm_test"
        )
        
        lines = await server.disassemble(
            count=5,
            address="0x400078",
            session_id="disasm_test"
        )
        
        assert isinstance(lines, list)
        assert len(lines) <= 5
        
        # Cleanup
        await server.close_session("disasm_test")
    
    async def test_search_bytes(self, sample_binary):
        """Test byte search through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="search_test"
        )
        
        results = await server.search_bytes(
            pattern="7f454c46",  # ELF magic
            session_id="search_test"
        )
        
        assert isinstance(results, list)
        assert len(results) > 0  # Should find ELF header
        
        # Cleanup
        await server.close_session("search_test")
    
    async def test_navigation(self, sample_binary):
        """Test navigation through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="nav_test"
        )
        
        # Seek to address
        new_pos = await server.seek("0x400100", "nav_test")
        assert new_pos == 0x400100
        
        # Get current address
        current = await server.get_current_address("nav_test")
        assert current == 0x400100
        
        # Seek relative
        new_pos = await server.seek_relative(0x100, "nav_test")
        assert new_pos == 0x400200
        
        # Cleanup
        await server.close_session("nav_test")
    
    async def test_flags(self, sample_binary):
        """Test flag operations through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="flag_test"
        )
        
        # Create flag
        result = await server.create_flag(
            name="test_flag",
            address="0x400300",
            session_id="flag_test"
        )
        assert result is True
        
        # List flags
        flags = await server.list_flags(session_id="flag_test")
        assert isinstance(flags, list)
        
        # Cleanup
        await server.close_session("flag_test")
    
    async def test_config(self, sample_binary):
        """Test configuration through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="config_test"
        )
        
        # Get config
        value = await server.get_config("asm.arch", "config_test")
        assert value is not None
        
        # Set config
        result = await server.set_config(
            "asm.comments", "true", "config_test"
        )
        assert result is True
        
        # Cleanup
        await server.close_session("config_test")
    
    async def test_execute_command(self, sample_binary):
        """Test raw command execution through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="cmd_test"
        )
        
        # Execute a simple command
        result = await server.execute_command(
            "?v 2+2",
            session_id="cmd_test"
        )
        
        assert "0x4" in result or "4" in result
        
        # Cleanup
        await server.close_session("cmd_test")
    
    async def test_check_security(self, sample_binary):
        """Test security check through server."""
        session = await server.create_session(
            file_path=sample_binary,
            session_name="sec_test"
        )
        
        security = await server.check_security("sec_test")
        
        assert isinstance(security, dict)
        assert "nx" in security
        assert "pic" in security
        assert "canary" in security
        
        # Cleanup
        await server.close_session("sec_test")
