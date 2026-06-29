import unittest
from behavior_analyzer.resource_mapper import ResourceMapper

class TestResourceMapper(unittest.TestCase):
    def test_clean_go_resource(self):
        tests = [
            ("*podInterface", "pods"),
            ("v1.PodInterface", "pods"),
            ("*deploymentInterface", "deployments"),
            ("*persistentVolumeClaimInterface", "persistent_volume_claims"),
            ("*customResourceDefinitionInterface", "custom_resource_definitions"),
            ("", ""),
        ]
        for inp, expected in tests:
            self.assertEqual(ResourceMapper.clean_go_resource(inp), expected)

    def test_map_go_call(self):
        # 1. Non-k8s package call -> None
        self.assertIsNone(
            ResourceMapper.map_go_call("github.com/gin-gonic/gin", "*Context", "JSON")
        )

        # 2. Unknown verb -> None
        self.assertIsNone(
            ResourceMapper.map_go_call("k8s.io/client-go/kubernetes/typed/core/v1", "*podInterface", "Print")
        )

        # 3. Core namespace-scoped call
        res = ResourceMapper.map_go_call(
            "k8s.io/client-go/kubernetes/typed/core/v1", "*podInterface", "Create"
        )
        self.assertEqual(res, {
            "api_group": "",
            "resource": "pods",
            "verb": "create",
            "scope": "namespace"
        })

        # 4. Apps cluster-scoped / namespace-scoped call
        res = ResourceMapper.map_go_call(
            "k8s.io/client-go/kubernetes/typed/apps/v1", "*deploymentInterface", "List"
        )
        self.assertEqual(res, {
            "api_group": "apps",
            "resource": "deployments",
            "verb": "list",
            "scope": "namespace"
        })

        # 5. Core cluster-scoped call
        res = ResourceMapper.map_go_call(
            "k8s.io/client-go/kubernetes/typed/core/v1", "*nodeInterface", "Get"
        )
        self.assertEqual(res, {
            "api_group": "",
            "resource": "nodes",
            "verb": "get",
            "scope": "cluster"
        })

    def test_map_python_call(self):
        # 1. Invalid names -> None
        self.assertIsNone(ResourceMapper.map_python_call("foo_bar"))
        self.assertIsNone(ResourceMapper.map_python_call(""))

        # 2. Namespace-scoped core API
        res = ResourceMapper.map_python_call("create_namespaced_pod")
        self.assertEqual(res, {
            "api_group": "",
            "resource": "pods",
            "verb": "create",
            "scope": "namespace"
        })

        # 3. Namespace-scoped extension API
        res = ResourceMapper.map_python_call("list_namespaced_deployment")
        self.assertEqual(res, {
            "api_group": "apps",
            "resource": "deployments",
            "verb": "list",
            "scope": "namespace"
        })

        # 4. Cluster-scoped core API
        res = ResourceMapper.map_python_call("read_node")
        self.assertEqual(res, {
            "api_group": "",
            "resource": "nodes",
            "verb": "get",
            "scope": "cluster"
        })

        # 5. Cluster-scoped API namespace
        res = ResourceMapper.map_python_call("create_namespace")
        self.assertEqual(res, {
            "api_group": "",
            "resource": "namespaces",
            "verb": "create",
            "scope": "cluster"
        })

if __name__ == "__main__":
    unittest.main()
