import sys
from unittest.mock import MagicMock

# Mock out external dependencies not installed in the testing environment
mock_tenacity = MagicMock()
mock_tenacity.retry = lambda *args, **kwargs: lambda func: func
mock_tenacity.stop_after_attempt = lambda *args, **kwargs: None
mock_tenacity.wait_exponential = lambda *args, **kwargs: None
sys.modules["tenacity"] = mock_tenacity
sys.modules["openai"] = MagicMock()

import unittest
import tempfile
import shutil
from pathlib import Path
from pod_matcher.__main__ import collect_source_files

class TestPodMatcher(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory structure for testing source collection
        self.test_dir = tempfile.mkdtemp()
        self.test_path = Path(self.test_dir)

    def tearDown(self):
        # Clean up temporary directory
        shutil.rmtree(self.test_dir)

    def test_collect_source_files(self):
        # 1. Create matching source files
        (self.test_path / "main.go").touch()
        (self.test_path / "utils").mkdir(parents=True, exist_ok=True)
        (self.test_path / "utils" / "helper.py").touch()
        (self.test_path / "ui").mkdir(parents=True, exist_ok=True)
        (self.test_path / "ui" / "index.ts").touch()

        # 2. Create ignored extension files
        (self.test_path / "readme.md").touch()
        (self.test_path / "image.png").touch()

        # 3. Create files inside excluded directories
        (self.test_path / "vendor").mkdir(parents=True, exist_ok=True)
        (self.test_path / "vendor" / "dep.go").touch()
        (self.test_path / "node_modules" / "pkg").mkdir(parents=True, exist_ok=True)
        (self.test_path / "node_modules" / "pkg" / "index.js").touch()
        (self.test_path / ".git").mkdir(parents=True, exist_ok=True)
        (self.test_path / ".git" / "config").touch()

        # Call the target function
        files = collect_source_files(self.test_dir)

        # Expected output should only contain source files in normalized relative format, sorted alphabetically
        expected = [
            str(Path("main.go")),
            str(Path("ui") / "index.ts"),
            str(Path("utils") / "helper.py"),
        ]
        
        # Standardize path separators for OS independence
        standardized_files = [str(Path(f)) for f in files]
        standardized_expected = [str(Path(f)) for f in expected]

        self.assertEqual(standardized_files, standardized_expected)

if __name__ == "__main__":
    unittest.main()
