"""
behavior_analyzer/refgraph.py

Manages call-graph construction and reachability analysis using NetworkX.
"""
from __future__ import annotations

import networkx as nx
import structlog

log = structlog.get_logger(__name__)

class RefGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        # Maps node to call site details of outgoing calls
        # Key: (file, func), Value: list of dicts with keys (callee_file, callee_func, call_file, call_line)
        self.call_sites = {}

    def add_call(
        self,
        caller_file: str,
        caller_func: str,
        callee_file: str,
        callee_func: str,
        call_file: str,
        call_line: int
    ):
        """
        Adds a call edge from caller to callee, along with its source location.
        """
        caller_node = (caller_file, caller_func)
        callee_node = (callee_file, callee_func)

        self.graph.add_edge(caller_node, callee_node)

        if caller_node not in self.call_sites:
            self.call_sites[caller_node] = []
        
        self.call_sites[caller_node].append({
            "callee_file": callee_file,
            "callee_func": callee_func,
            "call_file": call_file,
            "call_line": call_line
        })

    def get_reachable_nodes(self, entry_file: str, entry_func: str) -> set[tuple[str, str]]:
        """
        Finds all functions reachable from the entry point.
        """
        entry_node = (entry_file, entry_func)
        if entry_node not in self.graph:
            log.warning("entry_point_not_in_graph", file=entry_file, func=entry_func)
            # Try finding nodes matching entry_func if file path mismatch
            alternate_nodes = [node for node in self.graph.nodes if node[1] == entry_func]
            if alternate_nodes:
                log.info("using_alternate_entry_nodes", nodes=alternate_nodes)
                reachable = set()
                for node in alternate_nodes:
                    reachable.update(nx.descendants(self.graph, node))
                    reachable.add(node)
                return reachable
            return {entry_node}

        reachable = nx.descendants(self.graph, entry_node)
        reachable.add(entry_node)
        return reachable

    def get_call_path(self, source: tuple[str, str], target: tuple[str, str]) -> list[tuple[str, str]] | None:
        """
        Computes a shortest path of calls from source to target.
        """
        try:
            return nx.shortest_path(self.graph, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None
