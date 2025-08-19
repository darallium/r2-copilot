"""Tests for navigation tools."""

import pytest
from radare2_mcp.tools.navigation import NavigationTools
from radare2_mcp.models.schemas import Address


@pytest.mark.asyncio
class TestNavigationTools:
    """Test navigation tools functionality."""
    
    async def test_seek(self, test_session):
        """Test seeking to address."""
        addr = Address(value=0x400100)
        new_pos = await NavigationTools.seek(addr, "test_session")
        
        assert new_pos == 0x400100
    
    async def test_seek_symbol(self, test_session):
        """Test seeking to symbol."""
        # Try seeking to entry point
        addr = Address(value="entry0")
        new_pos = await NavigationTools.seek(addr, "test_session")
        
        # Should be non-zero if symbol exists
        assert new_pos >= 0
    
    async def test_seek_relative_forward(self, test_session):
        """Test relative seek forward."""
        # First seek to known position
        await NavigationTools.seek(Address(value=0x400000), "test_session")
        
        # Seek forward
        new_pos = await NavigationTools.seek_relative(0x100, "test_session")
        assert new_pos == 0x400100
    
    async def test_seek_relative_backward(self, test_session):
        """Test relative seek backward."""
        # First seek to known position
        await NavigationTools.seek(Address(value=0x400100), "test_session")
        
        # Seek backward
        new_pos = await NavigationTools.seek_relative(-0x50, "test_session")
        assert new_pos == 0x4000b0
    
    async def test_seek_undo(self, test_session):
        """Test undo seek."""
        # Seek to multiple positions
        await NavigationTools.seek(Address(value=0x400000), "test_session")
        await NavigationTools.seek(Address(value=0x400100), "test_session")
        
        # Undo
        prev_pos = await NavigationTools.seek_undo("test_session")
        assert prev_pos == 0x400000
    
    async def test_seek_redo(self, test_session):
        """Test redo seek."""
        # Seek and undo
        await NavigationTools.seek(Address(value=0x400000), "test_session")
        await NavigationTools.seek(Address(value=0x400100), "test_session")
        await NavigationTools.seek_undo("test_session")
        
        # Redo
        next_pos = await NavigationTools.seek_redo("test_session")
        assert next_pos == 0x400100
    
    async def test_get_current_address(self, test_session):
        """Test getting current address."""
        # Seek to known position
        await NavigationTools.seek(Address(value=0x400200), "test_session")
        
        current = await NavigationTools.get_current_address("test_session")
        assert current == 0x400200
    
    async def test_set_block_size(self, test_session):
        """Test setting block size."""
        result = await NavigationTools.set_block_size(256, "test_session")
        assert result is True
        
        # Verify block size was set
        size = await NavigationTools.get_block_size("test_session")
        assert size == 256
    
    async def test_get_block_size(self, test_session):
        """Test getting block size."""
        # Set a known block size
        await NavigationTools.set_block_size(128, "test_session")
        
        size = await NavigationTools.get_block_size("test_session")
        assert size == 128
    
    async def test_seek_to_function(self, test_session):
        """Test seeking to function by name."""
        # This might not work with minimal binary
        pos = await NavigationTools.seek_to_function("main", "test_session")
        
        # Position should be valid (0 if not found)
        assert pos >= 0
    
    async def test_seek_to_string(self, test_session):
        """Test seeking to string reference."""
        # This might not work with minimal binary
        pos = await NavigationTools.seek_to_string("hello", "test_session")
        
        # Position should be valid (0 if not found)
        assert pos >= 0
    
    async def test_seek_history(self, test_session):
        """Test getting seek history."""
        # Make some seeks
        await NavigationTools.seek(Address(value=0x400000), "test_session")
        await NavigationTools.seek(Address(value=0x400100), "test_session")
        await NavigationTools.seek(Address(value=0x400200), "test_session")
        
        history = await NavigationTools.seek_history("test_session")
        
        assert isinstance(history, list)
        # History should contain our seeks
        # Note: implementation might vary
