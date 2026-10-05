# Prior-work notes

Read in full before feature implementation on October 5, 2026:

- Wright et al., [Linux Security Modules: General Security Support for the Linux Kernel](https://www.usenix.org/conference/11th-usenix-security-symposium/linux-security-modules-general-security-support-linux-kernel)
  (USENIX Security 2002).
- Linux kernel documentation,
  [`Documentation/security/lsm.rst`](https://docs.kernel.org/security/lsm.html).
- Wang et al., [Progent: Programmable Privilege Control for LLM Agents](https://arxiv.org/abs/2504.11703),
  arXiv:2504.11703v3.
- Chen et al., [SEAgent: A Systematic Framework for Governing
  LLM-based Agents with Mandatory Access Control](https://arxiv.org/abs/2601.11893),
  arXiv:2601.11893v1.

## Design consequences

The LSM work treats the framework as mediation infrastructure, not as a policy.
It places hooks at access points reached through the kernel's internal objects,
keeps the existing discretionary decision in place, and gives security modules
opaque per-object state. For slangGraph this means that DAC remains
framework-owned, modules receive private slots, and the decisive tool hook must
sit immediately before the actual `BaseTool` invocation rather than outside a
middleware wrapper.

The kernel documentation makes ordering an operator choice while retaining
framework-defined infrastructure and blob ownership. slangGraph follows that
split: `cap` is fixed first, configured MAC modules run in declared order, and
the restrictive verdict algebra prevents ordering from becoming a grant path.

Progent's strongest relevant idea is that a policy-mediated rewrite must be
provably non-expansive rather than merely trusted because it came from policy
code. slangGraph realizes the same safety direction operationally: prepare hooks
may transform arguments, but the framework normalizes and reruns DAC on the
final arguments before permission checks.

SEAgent demonstrates why isolated call-by-call checks are insufficient for
agent systems: decisions need provenance and prior-flow context. slangGraph's
`ToolCall.history` should therefore be immutable, scoped to the bound principal
and thread, and derived from framework audit records. A module can use that
history to reject a read-then-send chain without owning shared mutable state.

Neither prior agent framework removes the need for an innermost hook. In this
fork a wrapper can call its execution callback repeatedly with changed
arguments, subgraphs contain independent `ToolNode` instances, and tools may
enter child graphs. Complete mediation must therefore be a property of all
execution routes, not a convention imposed on one outer wrapper.
