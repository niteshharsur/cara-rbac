"""
pod_matcher/llm_client.py

Wraps the OpenAI API to perform few-shot pod-to-program matching (M2).

Given:
  - Pod name, image reference, entrypoint/cmd
  - A list of source files in the repository

The LLM identifies which source file is the main program for this pod,
which the behavior analyzer (M3) will use as the call-graph entry point.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import structlog
from openai import OpenAI
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential

log = structlog.get_logger(__name__)

# Path to few-shot examples JSON
_EXAMPLES_PATH = Path(__file__).parent.parent / "prompts" / "few_shot_examples.json"


class PodMatchResult(BaseModel):
    """Structured output from the LLM pod-program matcher."""
    pod_name: str
    image_ref: str
    main_executable: str = Field(description="Binary or script name from the entrypoint")
    entry_point_file: str = Field(description="Relative source file path, e.g. cmd/server/main.go")
    language: str = Field(description="go | python | java | node | unknown")
    confidence: float = Field(ge=0.0, le=1.0, description="LLM confidence score")
    reasoning: str = Field(description="Brief explanation of the match decision")


class LLMClient:
    """
    Few-shot LLM client for pod-to-program matching.

    The prompt is built from:
    1. A system prompt explaining the task
    2. N few-shot examples (from prompts/few_shot_examples.json)
    3. The live pod context
    """

    SYSTEM_PROMPT = """You are a Kubernetes security analyst.
Your task is to identify which source file in a repository is the main entry point
for a given container image. You will be given:
- The pod name and namespace
- The container image reference
- The image ENTRYPOINT and CMD
- A list of candidate source files in the repository

Respond with a JSON object matching the PodMatchResult schema exactly.
Be conservative: if uncertain, set confidence below 0.6 and explain why."""

    def __init__(self, model: str = "gpt-4o", api_key: Optional[str] = None):
        self._model = model
        self._client = OpenAI(api_key=api_key or os.environ["OPENAI_API_KEY"])
        self._examples = self._load_examples()

    @staticmethod
    def _load_examples() -> list[dict]:
        if not _EXAMPLES_PATH.exists():
            return []
        with open(_EXAMPLES_PATH) as f:
            return json.load(f)

    def _build_prompt(
        self,
        pod_name: str,
        namespace: str,
        image_ref: str,
        entrypoint: list[str],
        cmd: list[str],
        source_files: list[str],
    ) -> list[dict]:
        messages = [{"role": "system", "content": self.SYSTEM_PROMPT}]

        # Add few-shot examples
        for ex in self._examples[:4]:  # max 4 examples to keep context short
            messages.append({"role": "user", "content": ex["user"]})
            messages.append({"role": "assistant", "content": json.dumps(ex["assistant"])})

        # Build live context
        source_list = "\n".join(f"  - {f}" for f in source_files[:200])  # cap at 200 files
        user_content = f"""
Pod name: {pod_name}
Namespace: {namespace}
Image: {image_ref}
ENTRYPOINT: {json.dumps(entrypoint)}
CMD: {json.dumps(cmd)}

Repository source files:
{source_list}

Identify the main entry point source file for this pod.
Respond with a JSON object matching the PodMatchResult schema.
""".strip()

        messages.append({"role": "user", "content": user_content})
        return messages

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def match(
        self,
        pod_name: str,
        namespace: str,
        image_ref: str,
        entrypoint: list[str],
        cmd: list[str],
        source_files: list[str],
    ) -> PodMatchResult:
        """
        Call the LLM to match a pod to its source entry point.
        Retries up to 3 times with exponential backoff on transient errors.
        """
        log.info("llm_match_start", pod=pod_name, image=image_ref, model=self._model)

        messages = self._build_prompt(pod_name, namespace, image_ref, entrypoint, cmd, source_files)

        response = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            response_format={"type": "json_object"},
            temperature=0.0,   # deterministic
            max_tokens=512,
        )

        raw = response.choices[0].message.content
        data = json.loads(raw)

        # Inject pod metadata that the model might not repeat
        data.setdefault("pod_name", pod_name)
        data.setdefault("image_ref", image_ref)

        result = PodMatchResult(**data)
        log.info(
            "llm_match_done",
            pod=pod_name,
            entry_point=result.entry_point_file,
            confidence=result.confidence,
        )
        return result
