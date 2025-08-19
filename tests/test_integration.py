"""Integration tests for Radare2 MCP server."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from radare2_mcp import server
from radare2_mcp.utils.r2_manager import r2_manager


@pytest.mark.asyncio
class TestIntegration:
    """Integration tests combining multiple tools."""

    async def test_full_analysis_workflow(self, sample_binary):
        """Test complete analysis workflow."""
        # Create session
        session = await server.create_session(file_path=sample_binary, session_name="workflow_test")

        # Analyze
        analysis = await server.analyze_all("workflow_test")
        assert analysis["success"] is True

        # Get binary info
        info = await server.get_binary_info("workflow_test")
        assert info is not None

        # List functions
        functions = await server.list_functions("workflow_test")

        # Disassemble first function if exists
        if functions:
            first_func = functions[0]
            await server.seek(f"0x{first_func['offset']:x}", "workflow_test")
            disasm = await server.disassemble_function(session_id="workflow_test")
            assert len(disasm) > 0

        # Search for strings
        strings = await server.get_strings(session_id="workflow_test")

        # Search for patterns
        results = await server.search_bytes("90", session_id="workflow_test")

        # Check security
        security = await server.check_security("workflow_test")
        assert isinstance(security, dict)

        # Cleanup
        await server.close_session("workflow_test")

    async def test_search_and_flag_workflow(self, sample_binary):
        """Test searching and flagging workflow."""
        session = await server.create_session(
            file_path=sample_binary, session_name="search_flag_test"
        )

        # Search for ELF header
        results = await server.search_bytes("7f454c46", session_id="search_flag_test")
        assert len(results) > 0

        # Flag the first result
        first_result = results[0]
        await server.create_flag(
            name="elf_header",
            address=f"0x{first_result['offset']:x}",
            session_id="search_flag_test",
        )

        # Verify flag was created
        flags = await server.list_flags(session_id="search_flag_test")
        flag_names = [f["name"] for f in flags]
        assert "elf_header" in flag_names

        # Seek to flag
        await server.seek("elf_header", "search_flag_test")
        current = await server.get_current_address("search_flag_test")
        assert current == first_result["offset"]

        # Cleanup
        await server.close_session("search_flag_test")

    async def test_rop_gadget_search(self, compiled_test_binary):
        """Test ROP gadget search workflow."""
        if compiled_test_binary is None:
            pytest.skip("No compiled binary available")

        session = await server.create_session(
            file_path=compiled_test_binary, session_name="rop_test"
        )

        # Analyze first
        await server.analyze_all("rop_test")

        # Search for ROP gadgets
        gadgets = await server.search_rop_gadgets(
            instructions=["ret"], max_length=3, session_id="rop_test"
        )

        assert isinstance(gadgets, list)

        # Flag interesting gadgets
        for i, gadget in enumerate(gadgets[:5]):  # First 5 gadgets
            await server.create_flag(
                name=f"gadget_{i}", address=f"0x{gadget['offset']:x}", session_id="rop_test"
            )

        # Cleanup
        await server.close_session("rop_test")

    async def test_patch_workflow(self):
        """Test binary patching workflow."""
        # Create a test file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            # Write some test data
            f.write(b"\x75\x10")  # JNE instruction
            f.write(b"\x90" * 20)  # NOPs
            temp_file = f.name

        try:
            session = await server.create_session(
                file_path=temp_file, write_mode=True, session_name="patch_test"
            )

            # Search for JNE
            results = await server.search_bytes("75", session_id="patch_test")
            assert len(results) > 0

            # Patch JNE to JMP
            await server.write_hex(data="EB", address="0x0", session_id="patch_test")  # JMP

            # Write some NOPs
            await server.write_nop(count=5, address="0x10", session_id="patch_test")

            # Execute raw command to save
            await server.execute_command("wc", session_id="patch_test")

            # Cleanup
            await server.close_session("patch_test")

        finally:
            os.unlink(temp_file)

    async def test_multi_session(self, sample_binary):
        """Test working with multiple sessions."""
        # Create multiple sessions
        session1 = await server.create_session(file_path=sample_binary, session_name="multi1")
        session2 = await server.create_session(file_path=sample_binary, session_name="multi2")

        # Work with first session
        await server.analyze_all("multi1")
        funcs1 = await server.list_functions("multi1")

        # Work with second session
        await server.seek("0x400100", "multi2")
        await server.create_flag("test_flag", "0x400200", session_id="multi2")

        # Switch between sessions
        await server.switch_session("multi1")
        await server.switch_session("multi2")

        # Verify both sessions are independent
        flags2 = await server.list_flags(session_id="multi2")
        flag_names = [f["name"] for f in flags2]
        assert "test_flag" in flag_names

        # Cleanup
        await server.close_session("multi1")
        await server.close_session("multi2")

    async def test_error_handling(self):
        """Test error handling."""
        # Try to work with non-existent session
        result = await server.close_session("nonexistent")
        assert result is False

        # Try to create session with non-existent file
        with pytest.raises(Exception):
            await server.create_session(
                file_path="/nonexistent/file.bin", session_name="error_test"
            )

        # Try invalid operations
        session = await server.create_session(session_name="error_handling")

        # Invalid address format should be handled
        result = await server.seek("invalid_address", "error_handling")
        assert result == 0  # Should return 0 or handle gracefully

        # Cleanup
        await server.close_session("error_handling")
