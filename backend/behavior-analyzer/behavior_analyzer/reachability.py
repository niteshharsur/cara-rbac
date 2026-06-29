"""
behavior_analyzer/reachability.py

Performs graph reachability starting from an entry point file/function
to find reachable Kubernetes API calls.
"""
from __future__ import annotations

import structlog
from behavior_analyzer.refgraph import RefGraph
from behavior_analyzer.resource_mapper import ResourceMapper

log = structlog.get_logger(__name__)

class ReachabilityAnalyzer:
    def __init__(self):
        self.ref_graph = RefGraph()
        # Maps (caller_file, caller_func) -> list of raw api call dicts
        self.api_calls_by_caller = {}

    def load_go_calls(self, rows: list[dict]):
        """
        Loads Go call tuples into the call graph and identifies K8s API calls.
        """
        for row in rows:
            caller_file = row.get("callerFile", "")
            caller_line = row.get("callerLine", 0)
            caller_name = row.get("callerName", "")
            callee_pkg = row.get("calleePkg", "")
            callee_recv = row.get("calleeRecv", "")
            callee_name = row.get("calleeName", "")
            call_file = row.get("callFile", "")
            call_line = row.get("callLine", 0)

            if not caller_file or not caller_name:
                continue

            # Check if callee is a K8s API call
            k8s_tuple = ResourceMapper.map_go_call(callee_pkg, callee_recv, callee_name)
            if k8s_tuple:
                caller_node = (caller_file, caller_name)
                if caller_node not in self.api_calls_by_caller:
                    self.api_calls_by_caller[caller_node] = []
                
                self.api_calls_by_caller[caller_node].append({
                    "mapped": k8s_tuple,
                    "call_site_file": call_file,
                    "call_site_line": call_line,
                    "callee": f"{callee_pkg}.{callee_recv}.{callee_name}"
                })
            else:
                # Add to call-graph for traversal
                # Go CodeQL might not give a callee file if it is an external pkg, but package path is unique enough
                callee_file_dummy = callee_pkg or "unknown_file"
                self.ref_graph.add_call(
                    caller_file=caller_file,
                    caller_func=caller_name,
                    callee_file=callee_file_dummy,
                    callee_func=callee_name,
                    call_file=call_file,
                    call_line=call_line
                )

    def load_python_calls(self, rows: list[dict]):
        """
        Loads Python call tuples into the call graph and identifies K8s API calls.
        """
        for row in rows:
            caller_file = row.get("callerFile", "")
            caller_name = row.get("callerName", "")
            callee_name = row.get("calleeName", "")
            call_file = row.get("callFile", "")
            call_line = row.get("callLine", 0)

            if not caller_file or not caller_name:
                continue

            # In Python, the callee name might be like:
            # - create_namespaced_pod
            # - self.api.create_namespaced_pod
            # Let's clean the callee name by extracting the last part of a dot-separated string
            method_name = callee_name.split(".")[-1] if callee_name else ""

            k8s_tuple = ResourceMapper.map_python_call(method_name)
            if k8s_tuple:
                caller_node = (caller_file, caller_name)
                if caller_node not in self.api_calls_by_caller:
                    self.api_calls_by_caller[caller_node] = []
                
                self.api_calls_by_caller[caller_node].append({
                    "mapped": k8s_tuple,
                    "call_site_file": call_file,
                    "call_site_line": call_line,
                    "callee": callee_name
                })
            else:
                # Add to call-graph
                # For python, target file might be dynamic; we'll treat target name as unique within scope
                # or match to files. For dynamic languages, callgraph uses best-effort.
                self.ref_graph.add_call(
                    caller_file=caller_file,
                    caller_func=caller_name,
                    callee_file="dynamic_py_target",
                    callee_func=callee_name,
                    call_file=call_file,
                    call_line=call_line
                )

    def analyze_reachability(self, entry_file: str, entry_func: str) -> list[dict]:
        """
        Finds all reachable Kubernetes API call sites starting from the entry point.
        """
        log.info("starting_reachability_analysis", entry_file=entry_file, entry_func=entry_func)
        
        reachable_funcs = self.ref_graph.get_reachable_nodes(entry_file, entry_func)
        log.info("reachable_functions_found", count=len(reachable_funcs))

        reachable_api_calls = []
        for node in reachable_funcs:
            if node in self.api_calls_by_caller:
                for api_call in self.api_calls_by_caller[node]:
                    reachable_api_calls.append(api_call)

        log.info("reachable_k8s_api_calls", count=len(reachable_api_calls))
        return reachable_api_calls
