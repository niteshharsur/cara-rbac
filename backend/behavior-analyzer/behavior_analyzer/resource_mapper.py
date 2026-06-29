"""
behavior_analyzer/resource_mapper.py

Maps CodeQL-extracted Kubernetes client calls to standard Kubernetes RBAC tuples.
"""
from __future__ import annotations

import re
import structlog

log = structlog.get_logger(__name__)

# List of known cluster-scoped resources in Kubernetes
CLUSTER_SCOPED_RESOURCES = {
    "nodes",
    "namespaces",
    "persistentvolumes",
    "clusterroles",
    "clusterrolebindings",
    "certificatesigningrequests",
    "apiservices",
    "tokenreviews",
    "subjectaccessreviews",
    "selfsubjectaccessreviews",
    "selfsubjectrulesreviews",
    "storageclasses",
    "volumeattachments",
    "mutatingwebhookconfigurations",
    "validatingwebhookconfigurations",
    "customresourcedefinitions",
}

# Mapping of singular names/variants to standard plural K8s resource names
SINGULAR_TO_PLURAL = {
    "pod": "pods",
    "service": "services",
    "configmap": "configmaps",
    "secret": "secrets",
    "deployment": "deployments",
    "statefulset": "statefulsets",
    "daemonset": "daemonsets",
    "replica_set": "replicasets",
    "replicaset": "replicasets",
    "job": "jobs",
    "cronjob": "cronjobs",
    "ingress": "ingresses",
    "persistentvolumeclaim": "persistentvolumeclaims",
    "pvc": "persistentvolumeclaim",
    "persistentvolume": "persistentvolumes",
    "pv": "persistentvolumes",
    "namespace": "namespaces",
    "node": "nodes",
    "role": "roles",
    "rolebinding": "rolebindings",
    "clusterrole": "clusterroles",
    "clusterrolebinding": "clusterrolebindings",
    "serviceaccount": "serviceaccounts",
    "endpoints": "endpoints",
    "event": "events",
    "limitrange": "limitranges",
    "resourcequota": "resourcequotas",
    "horizontalpodautoscaler": "horizontalpodautoscalers",
    "hpa": "horizontalpodautoscalers",
    "poddisruptionbudget": "poddisruptionbudgets",
    "pdb": "poddisruptionbudgets",
    "customresourcedefinition": "customresourcedefinitions",
    "crd": "customresourcedefinitions",
}

# Go method names to K8s RBAC verbs
GO_VERB_MAP = {
    "Create": "create",
    "Get": "get",
    "List": "list",
    "Watch": "watch",
    "Update": "update",
    "Patch": "patch",
    "Delete": "delete",
    "DeleteCollection": "deletecollection",
    "UpdateStatus": "update", # UpdateStatus is usually mapped to update on resource/status
}

# API groups mapping from path package names
PACKAGE_TO_API_GROUP = {
    "core": "",
    "apps": "apps",
    "batch": "batch",
    "rbac": "rbac.authorization.k8s.io",
    "networking": "networking.k8s.io",
    "autoscaling": "autoscaling",
    "policy": "policy",
    "storage": "storage.k8s.io",
    "admissionregistration": "admissionregistration.k8s.io",
    "apiextensions": "apiextensions.k8s.io",
}

class ResourceMapper:
    @staticmethod
    def clean_go_resource(recv_type: str) -> str:
        """
        Cleans Go receiver type to get resource name.
        Example: "*podInterface" -> "pods"
        """
        if not recv_type:
            return ""
        # Remove pointer asterisks
        name = recv_type.replace("*", "")
        # Get package suffix if any (e.g., v1.PodInterface -> PodInterface)
        if "." in name:
            name = name.split(".")[-1]
        # Remove "Interface" suffix
        if name.endswith("Interface"):
            name = name[:-9]
        
        # Convert camelCase to snake_case
        name = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
        
        # Map or pluralize
        return SINGULAR_TO_PLURAL.get(name, name + "s")

    @classmethod
    def map_go_call(cls, pkg: str, recv: str, method: str) -> dict | None:
        """
        Maps a Go client-go call to a K8s RBAC tuple.
        Returns dict with keys (api_group, resource, verb, scope) or None if not a K8s call.
        """
        if not pkg or "k8s.io/client-go" not in pkg:
            return None

        verb = GO_VERB_MAP.get(method)
        if not verb:
            return None

        # Resolve resource from receiver type
        resource = cls.clean_go_resource(recv)
        if not resource:
            return None

        # Resolve API group from package path
        # Typically of form k8s.io/client-go/kubernetes/typed/apps/v1
        api_group = ""
        parts = pkg.split("/")
        if "typed" in parts:
            idx = parts.index("typed")
            if idx + 1 < len(parts):
                group_key = parts[idx + 1]
                api_group = PACKAGE_TO_API_GROUP.get(group_key, group_key + ".k8s.io")

        scope = "cluster" if resource in CLUSTER_SCOPED_RESOURCES else "namespace"

        return {
            "api_group": api_group,
            "resource": resource,
            "verb": verb,
            "scope": scope
        }

    @classmethod
    def map_python_call(cls, func_name: str) -> dict | None:
        """
        Maps a Python kubernetes client method name to a K8s RBAC tuple.
        Examples:
          - create_namespaced_pod -> (api_group='', resource='pods', verb='create', scope='namespace')
          - read_node -> (api_group='', resource='nodes', verb='get', scope='cluster')
        """
        if not func_name:
            return None

        # Pattern for namespaced resources: e.g. create_namespaced_pod, list_namespaced_deployment
        namespaced_match = re.match(r"^([a-z]+)_namespaced_(.+)$", func_name)
        # Pattern for cluster/non-namespaced resources: e.g. create_node, list_namespace
        cluster_match = re.match(r"^([a-z]+)_(.+)$", func_name)

        verb_prefix = ""
        resource_raw = ""
        scope = "namespace"

        if namespaced_match:
            verb_prefix = namespaced_match.group(1)
            resource_raw = namespaced_match.group(2)
            scope = "namespace"
        elif cluster_match:
            verb_prefix = cluster_match.group(1)
            resource_raw = cluster_match.group(2)
            # Check if this verb prefix is a valid K8s client action
            if verb_prefix not in {"create", "read", "list", "patch", "replace", "delete", "watch"}:
                return None
            scope = "cluster"
        else:
            return None

        # Map verb prefix
        verb_map = {
            "create": "create",
            "read": "get",
            "list": "list",
            "watch": "watch",
            "patch": "patch",
            "replace": "update",
            "delete": "delete",
        }
        verb = verb_map.get(verb_prefix)
        if not verb:
            return None

        # Clean resource name
        resource = resource_raw.replace("_", "")
        resource = SINGULAR_TO_PLURAL.get(resource, resource + "s")

        # Determine API Group
        # Python client doesn't encode API group directly in method name, but we can infer it
        api_group = ""
        if resource in {"deployments", "statefulsets", "daemonsets", "replicasets"}:
            api_group = "apps"
        elif resource in {"jobs", "cronjobs"}:
            api_group = "batch"
        elif resource in {"roles", "rolebindings", "clusterroles", "clusterrolebindings"}:
            api_group = "rbac.authorization.k8s.io"
        elif resource in {"ingresses"}:
            api_group = "networking.k8s.io"
        elif resource in {"horizontalpodautoscalers"}:
            api_group = "autoscaling"
        elif resource in {"poddisruptionbudgets"}:
            api_group = "policy"
        elif resource in {"customresourcedefinitions"}:
            api_group = "apiextensions.k8s.io"

        # Correct scope check based on resource type
        if resource in CLUSTER_SCOPED_RESOURCES:
            scope = "cluster"

        return {
            "api_group": api_group,
            "resource": resource,
            "verb": verb,
            "scope": scope
        }
