"""Host-neutral parsing does not mistake declared controls for host support."""

import pytest

from langgraph.prebuilt.security.enforcement import AuthorityDomain
from langgraph.prebuilt.security.host_controls import host_control_rule
from langgraph.prebuilt.security.object_policy import parse_security_manifest


@pytest.mark.parametrize("host", ["linux", "macos", "inprocess"])
@pytest.mark.parametrize(
    "statement,domain,selector",
    [
        ("cpu per_process 1000 need", AuthorityDomain.RESOURCE_LIMIT, "cpu_ms"),
        ("cpu aggregate 1000 need", AuthorityDomain.RESOURCE_LIMIT, "aggregate_cpu_ms"),
        ("syscalls @minimal need", AuthorityDomain.PROCESS, "minimal"),
    ],
)
def test_control_vocabulary_is_platform_neutral(host, statement, domain, selector):
    manifest = parse_security_manifest(f"tool probe {{\nruns {host}\n{statement}\n}}")
    (line,) = manifest.expand("probe", {})
    rule = host_control_rule(line)
    assert rule is not None and rule.domain is domain and rule.selector == selector
    assert rule.provenance == line.provenance
    assert rule.requirement.value == "need"
