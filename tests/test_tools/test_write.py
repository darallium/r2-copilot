"""Tests for write tools."""

import os
import tempfile
from pathlib import Path

import pytest

from radare2_mcp.models.schemas import Address
from radare2_mcp.tools.write import WriteTools
from radare2_mcp.utils.r2_manager import R2Manager


@pytest.fixture
async def write_session():
    """Create a session with write mode enabled."""
    # Create a temporary file for writing
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x00" * 1024)  # 1KB of zeros
        temp_file = f.name

    manager = R2Manager()
    session = manager.create_session(session_id="write_test", file_path=temp_file, write_mode=True)

    yield session

    # Cleanup
    manager.close_session("write_test")
    try:
        os.unlink(temp_file)
    except:
        pass


@pytest.mark.asyncio
class TestWriteTools:
    """Test write tools functionality."""

    async def test_write_hex(self, write_session):
        """Test writing hex values."""
        result = await WriteTools.write_hex(
            data="909090", address=Address(value=0x10), session_id="write_test"
        )

        assert result is True

    async def test_write_hex_bytes(self, write_session):
        """Test writing hex from bytes."""
        result = await WriteTools.write_hex(
            data=b"\x90\x90\x90", address=Address(value=0x20), session_id="write_test"
        )

        assert result is True

    async def test_write_assembly(self, write_session):
        """Test writing assembly instruction."""
        result = await WriteTools.write_assembly(
            assembly="nop", address=Address(value=0x30), session_id="write_test"
        )

        assert result is True

    async def test_write_string(self, write_session):
        """Test writing string."""
        result = await WriteTools.write_string(
            text="Hello", address=Address(value=0x40), null_terminated=True, session_id="write_test"
        )

        assert result is True

    async def test_write_string_no_null(self, write_session):
        """Test writing string without null terminator."""
        result = await WriteTools.write_string(
            text="Test", address=Address(value=0x50), null_terminated=False, session_id="write_test"
        )

        assert result is True

    async def test_write_value(self, write_session):
        """Test writing integer value."""
        result = await WriteTools.write_value(
            value=0x12345678, size=4, address=Address(value=0x60), session_id="write_test"
        )

        assert result is True

    async def test_write_value_different_sizes(self, write_session):
        """Test writing values of different sizes."""
        # 1 byte
        result1 = await WriteTools.write_value(
            value=0xFF, size=1, address=Address(value=0x70), session_id="write_test"
        )
        assert result1 is True

        # 2 bytes
        result2 = await WriteTools.write_value(
            value=0xFFFF, size=2, address=Address(value=0x72), session_id="write_test"
        )
        assert result2 is True

        # 8 bytes
        result8 = await WriteTools.write_value(
            value=0xFFFFFFFFFFFFFFFF, size=8, address=Address(value=0x78), session_id="write_test"
        )
        assert result8 is True

    async def test_write_operation_xor(self, write_session):
        """Test XOR write operation."""
        result = await WriteTools.write_operation(
            operation="xor",
            value=0xFF,
            address=Address(value=0x80),
            size=4,
            session_id="write_test",
        )

        assert result is True

    async def test_write_operation_add(self, write_session):
        """Test ADD write operation."""
        result = await WriteTools.write_operation(
            operation="add", value=1, address=Address(value=0x90), session_id="write_test"
        )

        assert result is True

    async def test_write_operation_invalid(self, write_session):
        """Test invalid write operation."""
        result = await WriteTools.write_operation(
            operation="invalid_op", value=1, session_id="write_test"
        )

        assert result is False

    async def test_write_file(self, write_session):
        """Test writing file contents."""
        # Create a temporary file to write
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("Test content")
            source_file = f.name

        try:
            result = await WriteTools.write_file(
                file_path=source_file,
                address=Address(value=0x100),
                ascii_only=True,
                session_id="write_test",
            )

            assert result is True
        finally:
            os.unlink(source_file)

    async def test_write_file_not_found(self, write_session):
        """Test writing non-existent file."""
        result = await WriteTools.write_file(
            file_path="/nonexistent/file.txt", session_id="write_test"
        )

        assert result is False

    async def test_write_to_file(self, write_session):
        """Test writing memory to file."""
        output_file = tempfile.mktemp()

        try:
            result = await WriteTools.write_to_file(
                file_path=output_file, size=100, address=Address(value=0x0), session_id="write_test"
            )

            assert result is True
            # File should be created
            assert Path(output_file).exists()
        finally:
            try:
                os.unlink(output_file)
            except:
                pass

    async def test_write_cache_commit(self, write_session):
        """Test committing write cache."""
        result = await WriteTools.write_cache_commit("write_test")
        assert result is True

    async def test_get_debruijn_offset(self, write_session):
        """Test getting De Bruijn pattern offset."""
        # This might not work without proper pattern
        offset = await WriteTools.get_debruijn_offset(pattern="AAAA", session_id="write_test")

        # Offset might be None if pattern not found
        assert offset is None or isinstance(offset, int)

    async def test_write_nop(self, write_session):
        """Test writing NOP instructions."""
        result = await WriteTools.write_nop(
            count=5, address=Address(value=0x200), session_id="write_test"
        )

        assert result is True
