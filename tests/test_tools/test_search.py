"""Tests for search tools."""

import pytest

from radare2_mcp.models.schemas import Address, ROPGadget, SearchResult
from radare2_mcp.tools.search import SearchTools


@pytest.mark.asyncio
class TestSearchTools:
    """Test search tools functionality."""

    async def test_search_bytes(self, test_session):
        """Test searching for byte pattern."""
        # Search for ELF magic
        results = await SearchTools.search_bytes(pattern="7f454c46", session_id="test_session")

        assert isinstance(results, list)
        if results:  # Should find ELF header
            assert len(results) > 0
            for result in results:
                assert isinstance(result, SearchResult)
                assert result.offset >= 0
                assert result.size > 0
                assert isinstance(result.data, bytes)

    async def test_search_bytes_with_escape(self, test_session):
        """Test searching with escaped hex notation."""
        results = await SearchTools.search_bytes(
            pattern="\\x7f\\x45\\x4c\\x46", session_id="test_session"
        )

        assert isinstance(results, list)

    async def test_search_bytes_with_range(self, test_session):
        """Test searching within address range."""
        results = await SearchTools.search_bytes(
            pattern="90",
            from_addr=0x400000,
            to_addr=0x401000,
            session_id="test_session",  # NOP
        )

        assert isinstance(results, list)

    async def test_search_string(self, test_session):
        """Test searching for string."""
        results = await SearchTools.search_string(
            text="ELF", case_sensitive=True, session_id="test_session"
        )

        assert isinstance(results, list)
        for result in results:
            assert isinstance(result, SearchResult)
            assert result.string == "ELF"

    async def test_search_string_case_insensitive(self, test_session):
        """Test case-insensitive string search."""
        results = await SearchTools.search_string(
            text="elf", case_sensitive=False, session_id="test_session"
        )

        assert isinstance(results, list)

    async def test_search_rop_gadgets(self, test_session):
        """Test searching for ROP gadgets."""
        gadgets = await SearchTools.search_rop_gadgets(
            instructions=["ret"], max_length=3, session_id="test_session"
        )

        assert isinstance(gadgets, list)
        for gadget in gadgets:
            assert isinstance(gadget, ROPGadget)
            assert gadget.offset >= 0
            assert len(gadget.instructions) > 0
            assert gadget.size > 0
            assert gadget.ending == "ret"

    async def test_search_rop_gadgets_complex(self, test_session):
        """Test searching for complex ROP gadgets."""
        gadgets = await SearchTools.search_rop_gadgets(
            instructions=["pop rax", "ret"], max_length=5, session_id="test_session"
        )

        assert isinstance(gadgets, list)
        # Might not find these specific gadgets in minimal binary

    async def test_search_assembly(self, test_session):
        """Test searching for assembly instruction."""
        results = await SearchTools.search_assembly(assembly="mov eax", session_id="test_session")

        assert isinstance(results, list)
        for result in results:
            assert isinstance(result, SearchResult)

    async def test_search_magic(self, test_session):
        """Test searching for magic bytes."""
        results = await SearchTools.search_magic(session_id="test_session")

        assert isinstance(results, list)
        # Should find at least ELF magic

    async def test_search_references(self, test_session):
        """Test searching for references to address."""
        addr = Address(value=0x400078)
        results = await SearchTools.search_references(address=addr, session_id="test_session")

        assert isinstance(results, list)

    async def test_get_all_strings(self, test_session):
        """Test getting all strings."""
        results = await SearchTools.get_all_strings(min_length=4, session_id="test_session")

        assert isinstance(results, list)
        for result in results:
            assert isinstance(result, SearchResult)
            assert result.string
            assert len(result.string) >= 4

    async def test_search_pattern_with_wildcards(self, test_session):
        """Test searching with pattern containing wildcards."""
        results = await SearchTools.search_pattern(
            pattern="7f45??46",
            session_id="test_session",  # ELF with wildcard
        )

        assert isinstance(results, list)

    async def test_search_pattern_with_mask(self, test_session):
        """Test searching with pattern and mask."""
        results = await SearchTools.search_pattern(
            pattern="7f454c46", mask="ffff00ff", session_id="test_session"
        )

        assert isinstance(results, list)

    async def test_configure_search(self, test_session):
        """Test configuring search parameters."""
        result = await SearchTools.configure_search(
            align=4, from_addr=0x400000, to_addr=0x500000, session_id="test_session"
        )

        assert result is True
