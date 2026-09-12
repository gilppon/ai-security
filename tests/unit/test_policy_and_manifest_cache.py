from agent_security.mcp.manifest import MCPManifest, MCPManifestRegistry, MCPToolManifest
from policy.lifecycle import parse_policy_bundle
from policy.signing import PolicySignatureVerifier, sign_policy_bundle


SOURCE = """
id: ASEC-POLICY-SIGNED
title: Signed health policy
category: core
severity: info
when:
  event_type: system.health.check
match:
  source: internal
risk:
  score: 0
actions: [allow, audit]
"""


def test_policy_signature_verifier_cache():
    key = b"k" * 32
    bundle = parse_policy_bundle("signed-policy", 1, SOURCE)
    signed = sign_policy_bundle(bundle, signer_id="signer-01", key=key)

    verifier = PolicySignatureVerifier({"signer-01": key})

    # Initial verification (Cache miss)
    assert verifier.verify(signed) is True
    assert len(verifier._cache) == 1

    # Second verification (Cache hit)
    assert verifier.verify(signed) is True
    assert len(verifier._cache) == 1

    # Clear cache
    verifier.clear_cache()
    assert len(verifier._cache) == 0


def test_mcp_manifest_registry_tool_lookup_cache():
    tool1 = MCPToolManifest(name="tool_a", local_tool_name="tool_a", description="Test tool A")
    tool2 = MCPToolManifest(name="tool_b", local_tool_name="tool_b", description="Test tool B")
    manifest = MCPManifest(server_id="server_1", version="1.0.0", tools=(tool1, tool2))

    registry = MCPManifestRegistry([manifest])

    # Cache hit check
    assert registry.get_tool("server_1", "tool_a") == tool1
    assert registry.get_tool("server_1", "tool_b") == tool2
    assert registry.get_tool("server_1", "nonexistent") is None
    assert registry.get_tool("unknown_server", "tool_a") is None
