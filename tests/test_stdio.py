import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_stdio_lists_tools_and_rejects_private_urls_without_network():
    async def scenario():
        parameters = StdioServerParameters(command=sys.executable, args=["-m", "osint_mcp"])
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                tools = await client.list_tools()
                assert len(tools.tools) == 15
                assert {
                    "investigate_site",
                    "compare_domains",
                    "recon_batch",
                    "certificate_history",
                } <= {tool.name for tool in tools.tools}
                blocked = await client.call_tool("http_headers", {"url": "http://127.0.0.1/admin"})
                assert blocked.is_error
                invalid = await client.call_tool(
                    "certificate_history", {"domain": "example.com", "limit": 0}
                )
                assert invalid.is_error

    asyncio.run(asyncio.wait_for(scenario(), timeout=30))
