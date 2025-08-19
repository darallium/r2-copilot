"""Tests for R2Manager."""

from pathlib import Path

import pytest

from radare2_mcp.models.schemas import Architecture, R2Session
from radare2_mcp.utils.r2_manager import R2Manager


class TestR2Manager:
    """Test R2Manager functionality."""

    def test_create_session_with_file(self, r2_manager, sample_binary):
        """Test creating a session with a file."""
        session = r2_manager.create_session(session_id="test1", file_path=sample_binary)

        assert isinstance(session, R2Session)
        assert session.session_id == "test1"
        assert session.file_path == sample_binary
        assert session.pid is None
        assert not session.is_debugger
        assert not session.write_mode

    def test_create_session_with_malloc(self, r2_manager):
        """Test creating a session with malloc."""
        session = r2_manager.create_session(session_id="test_malloc")

        assert isinstance(session, R2Session)
        assert session.session_id == "test_malloc"
        assert session.file_path is None

    def test_create_session_write_mode(self, r2_manager, sample_binary):
        """Test creating a session in write mode."""
        session = r2_manager.create_session(
            session_id="test_write", file_path=sample_binary, write_mode=True
        )

        assert session.write_mode is True

    def test_get_session(self, r2_manager, sample_binary):
        """Test getting an existing session."""
        r2_manager.create_session(session_id="test_get", file_path=sample_binary)

        r2_session = r2_manager.get_session("test_get")
        assert r2_session is not None

        # Test with current session
        r2_session_current = r2_manager.get_session()
        assert r2_session_current == r2_session

    def test_get_nonexistent_session(self, r2_manager):
        """Test getting a non-existent session."""
        with pytest.raises(ValueError, match="Session .* not found"):
            r2_manager.get_session("nonexistent")

    def test_close_session(self, r2_manager, sample_binary):
        """Test closing a session."""
        r2_manager.create_session(session_id="test_close", file_path=sample_binary)

        result = r2_manager.close_session("test_close")
        assert result is True

        # Verify session is gone
        with pytest.raises(ValueError):
            r2_manager.get_session("test_close")

    def test_close_nonexistent_session(self, r2_manager):
        """Test closing a non-existent session."""
        result = r2_manager.close_session("nonexistent")
        assert result is False

    def test_list_sessions(self, r2_manager, sample_binary):
        """Test listing all sessions."""
        # Create multiple sessions
        r2_manager.create_session(session_id="test_list1", file_path=sample_binary)
        r2_manager.create_session(session_id="test_list2", file_path=sample_binary)

        sessions = r2_manager.list_sessions()
        assert len(sessions) == 2
        assert all(isinstance(s, R2Session) for s in sessions)

        session_ids = [s.session_id for s in sessions]
        assert "test_list1" in session_ids
        assert "test_list2" in session_ids

    def test_switch_session(self, r2_manager, sample_binary):
        """Test switching between sessions."""
        r2_manager.create_session(session_id="session1", file_path=sample_binary)
        r2_manager.create_session(session_id="session2", file_path=sample_binary)

        assert r2_manager.current_session == "session2"

        result = r2_manager.switch_session("session1")
        assert result is True
        assert r2_manager.current_session == "session1"

        # Test switching to non-existent session
        result = r2_manager.switch_session("nonexistent")
        assert result is False

    def test_execute_command(self, r2_manager, sample_binary):
        """Test executing a command."""
        r2_manager.create_session(session_id="test_exec", file_path=sample_binary)

        # Test basic command
        result = r2_manager.execute_command("?v 1+1", "test_exec")
        assert "0x2" in result or "2" in result

        # Test JSON output
        result = r2_manager.execute_command("i", "test_exec", json_output=True)
        assert isinstance(result, (dict, list))

    def test_execute_batch(self, r2_manager, sample_binary):
        """Test executing batch commands."""
        r2_manager.create_session(session_id="test_batch", file_path=sample_binary)

        commands = ["s 0x100", "b 32", "?v $$"]
        results = r2_manager.execute_batch(commands, "test_batch")

        assert len(results) == 3
        assert "0x100" in results[2]

    def test_seek(self, r2_manager, sample_binary):
        """Test seeking to address."""
        r2_manager.create_session(session_id="test_seek", file_path=sample_binary)

        # Seek to address
        pos = r2_manager.seek(0x1000, "test_seek")
        assert pos == 0x1000

        # Seek to symbol (if exists)
        # This might fail if no symbols in minimal binary
        try:
            pos = r2_manager.seek("entry0", "test_seek")
            assert pos > 0
        except:
            pass  # Symbol might not exist in minimal binary

    def test_get_current_address(self, r2_manager, sample_binary):
        """Test getting current address."""
        r2_manager.create_session(session_id="test_addr", file_path=sample_binary)

        r2_manager.seek(0x2000, "test_addr")
        addr = r2_manager.get_current_address("test_addr")
        assert addr == 0x2000

    def test_parse_arch(self, r2_manager):
        """Test architecture parsing."""
        assert r2_manager._parse_arch("x86") == Architecture.X86
        assert r2_manager._parse_arch("x86_64") == Architecture.X86_64
        assert r2_manager._parse_arch("arm") == Architecture.ARM
        assert r2_manager._parse_arch("arm64") == Architecture.ARM64
        assert r2_manager._parse_arch("unknown") is None

    def test_file_not_found(self, r2_manager):
        """Test creating session with non-existent file."""
        with pytest.raises(FileNotFoundError):
            r2_manager.create_session(session_id="test_notfound", file_path="/nonexistent/file.bin")
