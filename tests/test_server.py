import asyncio

from osint_mcp.server import mcp

TOOLS = asyncio.run(mcp.list_tools())


def test_all_tools_registered():
    assert len(TOOLS) == 15


def test_every_parameter_has_a_description():
    # clients only see the schema, an undocumented parameter is a guess for the model
    for tool in TOOLS:
        for name, prop in tool.input_schema["properties"].items():
            assert prop.get("description"), f"{tool.name}.{name} has no description"


def test_tools_are_marked_read_only():
    for tool in TOOLS:
        assert tool.title, tool.name
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.destructive_hint is False, tool.name
