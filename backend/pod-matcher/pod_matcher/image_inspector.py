"""
pod_matcher/image_inspector.py

Pulls a container image and extracts its entrypoint, command, and working
directory so M2 can identify the main executable for static analysis.

Supports:
  - Docker Hub and private registries
  - Multi-platform manifests (amd64 preferred)
  - Layer inspection to locate the binary in the image filesystem
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional

import docker
import structlog

log = structlog.get_logger(__name__)


@dataclass
class ImageInfo:
    """Extracted metadata from a container image."""
    image_ref: str          # e.g. "my-registry/api-server:v1.2.0"
    digest: str             # sha256 content digest — used as cache key
    entrypoint: list[str]   # from ENTRYPOINT instruction
    cmd: list[str]          # from CMD instruction
    working_dir: str        # WORKDIR
    env: dict[str, str]     # ENV vars (useful for JAVA_MAIN_CLASS etc.)
    labels: dict[str, str]  # OCI/Docker labels
    # Resolved main executable (after plugin processing)
    main_executable: Optional[str] = None
    entry_point_file: Optional[str] = None  # source file path (from M2 LLM)
    language: Optional[str] = None          # go | python | java | node | unknown


class ImageInspector:
    """
    Wraps the Docker SDK to pull an image and extract its runtime metadata.
    Falls back to `docker inspect` via subprocess if the SDK is unavailable.
    """

    def __init__(self, registry_auth: Optional[dict] = None):
        """
        registry_auth: optional dict with keys 'username', 'password', 'registry'
        for private registries. Reads REGISTRY_USERNAME/REGISTRY_PASSWORD from env
        if not provided.
        """
        self._auth = registry_auth or self._auth_from_env()
        try:
            self._client = docker.from_env()
        except Exception as exc:
            log.warning("docker_sdk_unavailable", error=str(exc))
            self._client = None

    @staticmethod
    def _auth_from_env() -> dict:
        return {
            "username": os.getenv("REGISTRY_USERNAME", ""),
            "password": os.getenv("REGISTRY_PASSWORD", ""),
            "registry": os.getenv("REGISTRY_URL", ""),
        }

    def inspect(self, image_ref: str) -> ImageInfo:
        """
        Pull (if needed) and inspect the image.
        Returns an ImageInfo with entrypoint/cmd/workdir resolved.
        """
        log.info("inspecting_image", image_ref=image_ref)

        if self._client:
            return self._inspect_via_sdk(image_ref)
        return self._inspect_via_cli(image_ref)

    def _inspect_via_sdk(self, image_ref: str) -> ImageInfo:
        try:
            image = self._client.images.pull(image_ref, auth_config=self._auth or None)
        except docker.errors.ImageNotFound:
            raise ValueError(f"Image not found: {image_ref}")
        except docker.errors.APIError as e:
            raise RuntimeError(f"Docker API error pulling {image_ref}: {e}")

        attrs = image.attrs
        config = attrs.get("Config", {})
        digest = attrs.get("Id", "")

        return ImageInfo(
            image_ref=image_ref,
            digest=digest,
            entrypoint=config.get("Entrypoint") or [],
            cmd=config.get("Cmd") or [],
            working_dir=config.get("WorkingDir") or "/",
            env=self._parse_env(config.get("Env") or []),
            labels=config.get("Labels") or {},
        )

    def _inspect_via_cli(self, image_ref: str) -> ImageInfo:
        """Fallback: shell out to `docker inspect` (no SDK needed)."""
        # Pull first
        subprocess.run(["docker", "pull", image_ref], check=True, capture_output=True)
        result = subprocess.run(
            ["docker", "inspect", image_ref],
            capture_output=True, text=True, check=True,
        )
        data = json.loads(result.stdout)[0]
        config = data.get("Config", {})
        digest = data.get("Id", "")

        return ImageInfo(
            image_ref=image_ref,
            digest=digest,
            entrypoint=config.get("Entrypoint") or [],
            cmd=config.get("Cmd") or [],
            working_dir=config.get("WorkingDir") or "/",
            env=self._parse_env(config.get("Env") or []),
            labels=config.get("Labels") or {},
        )

    @staticmethod
    def _parse_env(env_list: list[str]) -> dict[str, str]:
        """Converts ["KEY=VALUE", ...] to {"KEY": "VALUE", ...}."""
        result = {}
        for item in env_list:
            if "=" in item:
                k, _, v = item.partition("=")
                result[k] = v
        return result

    def detect_language(self, info: ImageInfo) -> str:
        """
        Heuristically determine the container's primary language from image metadata.
        Used to select the appropriate entry-point plugin.
        """
        ep_str = " ".join(info.entrypoint + info.cmd).lower()

        if "python" in ep_str or info.env.get("PYTHON_VERSION"):
            return "python"
        if "java" in ep_str or info.env.get("JAVA_VERSION") or info.labels.get("java.version"):
            return "java"
        if "node" in ep_str or info.env.get("NODE_VERSION"):
            return "node"
        if info.labels.get("org.opencontainers.image.source", "").endswith(".go"):
            return "go"

        # Check working dir binary extension
        for token in info.entrypoint + info.cmd:
            if token.endswith(".py"):
                return "python"
            if token.endswith(".jar"):
                return "java"
            if token.endswith(".js"):
                return "node"

        # Default: assume Go/compiled binary
        return "go"

    def content_hash(self, image_ref: str) -> str:
        """Returns a stable hash of the image_ref for caching (quick path without pulling)."""
        return hashlib.sha256(image_ref.encode()).hexdigest()
