permit(principal == slangGraph::User::"alice",
action in [slangGraph::Action::"record::read", slangGraph::Action::"record::write"], resource)
when { resource.selector == "notes/alice" };
permit(principal == slangGraph::User::"alice",
action in [slangGraph::Action::"pump::inspect", slangGraph::Action::"pump::set_flow"], resource)
when { resource.selector == "pump-1" };
permit(principal == slangGraph::User::"alice",
action == slangGraph::Action::"trace::append", resource)
when { resource.selector == "entry" };
permit(principal == slangGraph::User::"alice",
action == slangGraph::Action::"session::execute", resource)
when { resource.selector == "session-b" };
permit(principal == slangGraph::User::"alice",
action in [slangGraph::Action::"host_cpu::require",
slangGraph::Action::"host_syscalls::require"], resource);
