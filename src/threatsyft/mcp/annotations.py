"""Tool annotations, chosen per tool by what the tool actually reaches.

Hosts use these hints to decide what to auto-approve, so they have to describe
behaviour rather than which server a tool happens to live on. The split is not
enrichment-versus-knowledge: `enrichment_status` reads local configuration and
never leaves the process, while `lookup` on a CVE calls the NVD API. Annotating
either by its server would tell a host the opposite of the truth.

Nothing here is destructive or writes anything, so every tool is read-only.
"""

from __future__ import annotations

from mcp.types import ToolAnnotations

# Local files and process configuration only. The same question gives the same
# answer, and the set of things reachable is closed.
LOCAL_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

# Calls a third-party API. Reading changes nothing, but the answers move between
# calls and the reachable set is open, so this is neither idempotent nor
# closed-world.
LIVE_NETWORK = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)
