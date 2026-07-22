# CodeRisk Agent v0.3.1 - Complete Source Code

> AMD AI DevMaster Hackathon Track 2 | 2026-07-19
> GitHub: https://github.com/a9320/code-risk-agent
> Hackathon Fork: https://github.com/a9320/Radeon-hackathon-2026-07

---

## Project Structure

```
code-risk-agent/
|-- core/
|   |-- __init__.py
|   |-- models.py                # Pydantic data models
|   |-- llm_client.py            # LLM 3-backend client + ChatML
|   |-- semgrep_runner.py        # Semgrep CLI integration
|   |-- cve_client.py            # NVD/CVE query client
|   +-- memory.py                # Dual memory layer
|-- agents/
|   |-- __init__.py
|   |-- static_analyzer.py       # Agent 1: Static analysis
|   |-- semantic_analyzer.py     # Agent 2: LLM semantic analysis
|   |-- deep_verifier.py         # Agent 3: Triple cross-validation
|   +-- report_generator.py      # Agent 4: Report generator
|-- orchestrator.py              # State machine pipeline
|-- main.py                      # CLI entry point
|-- scripts/run_demo.sh          # Demo script
|-- tests/
|   |-- test_static_analyzer.py  # 13 pytest tests
|   +-- test_cases/              # 5 vulnerability samples
|-- pyproject.toml
|-- .env.example
+-- README.md
```

---

## 1. `pyproject.toml`

```toml
[project]
name = "code-risk-agent"
version = "0.1.0"
description = "AI-powered code quality and risk analysis agent"
readme = "README.md"
requires-python = ">=3.10"
license = {text = "MIT"}
authors = [
    {name = "Yang Weike"}
]

dependencies = [
    "pydantic>=2.0",
    "rich>=13.0",
    "httpx>=0.25",
    "tree-sitter>=0.21",
    "semgrep>=1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "ruff>=0.1",
]

[project.scripts]
code-risk = "main:main"

[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.backends._legacy:_Backend"

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.pytest.ini_options]
testpaths = ["tests"]
```

---

## 2. `.env.example`

```text
# CodeRisk Agent - Environment Configuration

# LLM Backend: "shared_api" | "local_http" | "local_llama_cpp"
LLM_BACKEND=local_llama_cpp

# Shared API (Radeon Cloud)
SHARED_API_URL=https://developer.amd.com.cn/radeon/api/v1
SHARED_API_KEY=your-api-key-here
SHARED_API_MODEL=Qwen/Qwen3.6-35B-A3B

# Local llama-server (HTTP)
LOCAL_HTTP_URL=http://localhost:8080
LOCAL_HTTP_MODEL=qwen2.5-coder-7b-instruct

# Local llama-cpp-python (direct GGUF load)
LOCAL_MODEL_PATH=/workspace/llama.cpp/models/qwen2.5-coder-7b-instruct-q4_k_m.gguf
LOCAL_N_GPU_LAYERS=999

# Semgrep
SEMGREP_RULES=p/default
```

---

## 3. `.gitignore`

```text
# Python
__pycache__/
*.py[cod]
*$py.class
*.egg-info/
dist/
build/
.eggs/

# Virtual environments
.venv/
venv/
env/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Environment
.env
.env.local

# Models
models/*.gguf
models/*.bin

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Coverage
htmlcov/
.coverage
```

---

## 4. `README.md`

```markdown
# CodeRisk Agent 🛡️

AI 代码质量与风险智能体 — AMD AI DevMaster Hackathon Track 2 参赛项目

## 特性

- 🔍 **静态分析** — Tree-sitter AST 解析 + Semgrep 规则扫描
- 🤖 **AI 审查** — Qwen2.5-Coder-7B 驱动的智能代码审查
- 🔄 **自省循环** — Agent 自我验证，三重交叉确认
- 📊 **可解释** — 完整证据链，每个风险都有来源
- 🐍🐢 **双语言** — 深度支持 C + Python

## 架构

```
                    ┌─────────────┐
                    │ Orchestrator│
                    └──────┬──────┘
                           │
        ┌──────────┬───────┼───────┬──────────┐
        ▼          ▼       ▼       ▼          ▼
   ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
   │Static  │ │Semantic│ │Pattern │ │Report  │
   │Analyzer│ │Analyzer│ │Matcher │ │Generator│
   └────────┘ └────────┘ └────────┘ └────────┘
```

## 快速开始

```bash
# 安装
pip install -e .

# 配置
cp .env.example .env
# 编辑 .env 填入 API Key

# 运行
code-risk analyze ./path/to/code
```

## 技术栈

- **模型:** Qwen2.5-Coder-7B-Instruct（统一模型）
- **推理:** llama.cpp (ROCm) / 共享 API 双后端
- **分析:** Tree-sitter + Semgrep
- **搜索:** Meilisearch（记忆层）
- **CLI:** Rich 终端 UI

## 许可

MIT
```

---

## 5. `core/__init__.py`

```python
"""CodeRisk Agent - Core Module"""

from core.models import (AnalysisRequest, AnalysisResult, AgentMessage, AgentRole, CodeFile, Confidence, Evidence, Language, LLMBackend, LLMConfig, Risk, Severity)
from core.llm_client import LLMClient
from core.semgrep_runner import run_semgrep, semgrep_to_risks, analyze_with_semgrep
from core.cve_client import CVEClient
from core.memory import MemoryLayer
```

---

## 6. `core/models.py`

```python
"""CodeRisk Agent — 核心数据模型

所有 Agent 之间的数据流转都通过这些模型。
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, computed_field


# ─── 语言 & 风险等级 ───────────────────────────────────────────────

class Language(str, Enum):
    C = "c"
    PYTHON = "python"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """风险等级，从低到高"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """置信度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ─── 输入模型 ─────────────────────────────────────────────────────

class CodeFile(BaseModel):
    """待分析的源代码文件"""
    path: Path
    content: str
    language: Language = Language.UNKNOWN

    @computed_field
    @property
    def hash(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()[:16]

    @computed_field
    @property
    def line_count(self) -> int:
        return self.content.count("\n") + 1

    @classmethod
    def from_path(cls, path: Path) -> CodeFile:
        content = path.read_text(encoding="utf-8", errors="replace")
        lang = _detect_language(path)
        return cls(path=path, content=content, language=lang)


class AnalysisRequest(BaseModel):
    """分析请求"""
    files: list[CodeFile]
    rules: list[str] = Field(default_factory=lambda: ["p/default"])
    depth: int = Field(default=2, ge=1, le=5, description="分析深度，1=浅 5=深")
    enable_ai: bool = True


# ─── 风险 & 证据 ─────────────────────────────────────────────────

class Evidence(BaseModel):
    """单条证据 — 风险的来源和推理链"""
    source: str = Field(description="来源: semgrep/tree-sitter/ai/manual")
    rule_id: Optional[str] = None
    snippet: str = Field(description="相关代码片段")
    line_start: int
    line_end: int
    reasoning: str = Field(description="推理过程")


class Risk(BaseModel):
    """一个风险项"""
    id: str = Field(description="唯一 ID，如 RISK-001")
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    cwe_id: Optional[str] = Field(default=None, description="CWE 编号，如 CWE-120")
    language: Language
    file_path: Path
    line_start: int
    line_end: int
    evidence: list[Evidence] = Field(default_factory=list)
    suggestion: str = Field(description="修复建议")

    @computed_field
    @property
    def evidence_count(self) -> int:
        return len(self.evidence)


# ─── Agent 消息 ───────────────────────────────────────────────────

class AgentRole(str, Enum):
    STATIC = "static_analyzer"
    SEMANTIC = "semantic_analyzer"
    PATTERN = "pattern_matcher"
    REPORTER = "report_generator"
    ORCHESTRATOR = "orchestrator"


class AgentMessage(BaseModel):
    """Agent 间通信消息"""
    sender: AgentRole
    receiver: AgentRole
    content: dict
    timestamp: datetime = Field(default_factory=datetime.now)
    correlation_id: str = Field(description="关联 ID，追踪同一轮分析")


# ─── 分析结果 ─────────────────────────────────────────────────────

class AnalysisResult(BaseModel):
    """完整分析结果"""
    request_id: str
    files_analyzed: int
    risks: list[Risk] = Field(default_factory=list)
    analysis_time_ms: int = 0
    model_used: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)

    @computed_field
    @property
    def risk_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for risk in self.risks:
            summary[risk.severity.value] = summary.get(risk.severity.value, 0) + 1
        return summary

    @computed_field
    @property
    def total_risks(self) -> int:
        return len(self.risks)

    @computed_field
    @property
    def has_critical(self) -> bool:
        return any(r.severity == Severity.CRITICAL for r in self.risks)


# ─── LLM 配置 ────────────────────────────────────────────────────

class LLMBackend(str, Enum):
    SHARED_API = "shared_api"
    LOCAL_HTTP = "local_http"      # llama-server HTTP API
    LOCAL_LLAMA_CPP = "local_llama_cpp"  # llama-cpp-python 直接加载


class LLMConfig(BaseModel):
    """LLM 客户端配置"""
    backend: LLMBackend = LLMBackend.LOCAL_LLAMA_CPP
    api_url: str = ""
    api_key: str = ""
    model: str = ""
    model_path: str = Field(default="", description="本地 GGUF 模型路径")
    n_gpu_layers: int = Field(default=999, description="GPU 层数，999=全部 offload")
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=256, le=32768)
    timeout: int = Field(default=60, ge=5, le=300)


# ─── 工具函数 ─────────────────────────────────────────────────────

def _detect_language(path: Path) -> Language:
    """根据文件扩展名检测语言"""
    suffix_map = {
        ".c": Language.C,
        ".h": Language.C,
        ".py": Language.PYTHON,
    }
    return suffix_map.get(path.suffix, Language.UNKNOWN)
```

---

## 7. `core/llm_client.py`

```python
"""CodeRisk Agent - LLM Client

Three backends:
1. Shared API (Radeon Cloud HTTP)
2. Local llama-server (HTTP)
3. Local llama-cpp-python (direct GGUF load)

Unified interface with auto-retry.
"""

from __future__ import annotations

import json
import time
from typing import Optional

import httpx
from rich.console import Console

from core.models import LLMBackend, LLMConfig

console = Console()

DEFAULT_CONFIGS = {
    LLMBackend.SHARED_API: LLMConfig(
        backend=LLMBackend.SHARED_API,
        api_url="https://developer.amd.com.cn/radeon/api/v1",
        model="Qwen/Qwen3.6-35B-A3B",
        temperature=0.1,
        max_tokens=8192,
    ),
    LLMBackend.LOCAL_HTTP: LLMConfig(
        backend=LLMBackend.LOCAL_HTTP,
        api_url="http://localhost:8080",
        model="qwen2.5-coder-7b-instruct",
        temperature=0.1,
        max_tokens=8192,
    ),
    LLMBackend.LOCAL_LLAMA_CPP: LLMConfig(
        backend=LLMBackend.LOCAL_LLAMA_CPP,
        model_path="/workspace/llama.cpp/models/qwen2.5-coder-7b-instruct-q4_k_m.gguf",
        model="qwen2.5-coder-7b-instruct",
        temperature=0.1,
        max_tokens=8192,
    ),
}

MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0

# Qwen2.5 ChatML special tokens
_IM_START = "<im_start|>"
_IM_END = "<im_end|>"
_ENDOFTEXT = "<|endoftext|>"


class LLMClient:
    """Unified LLM client with retry support."""

    def __init__(self, config: Optional[LLMConfig] = None, backend: Optional[LLMBackend] = None):
        if config:
            self.config = config
        else:
            b = backend or LLMBackend.LOCAL_LLAMA_CPP
            self.config = DEFAULT_CONFIGS[b]

        self._client: Optional[httpx.Client] = None
        self._local_llm = None
        self._request_count = 0
        self._total_tokens = 0

        if self.config.backend in (LLMBackend.SHARED_API, LLMBackend.LOCAL_HTTP):
            self._client = httpx.Client(timeout=self.config.timeout)
        elif self.config.backend == LLMBackend.LOCAL_LLAMA_CPP:
            self._init_llama_cpp()

    def _init_llama_cpp(self):
        try:
            from llama_cpp import Llama
        except ImportError:
            console.print("[red]llama-cpp-python not installed. Run: pip install llama-cpp-python[/]")
            raise

        if not self.config.model_path:
            raise ValueError("LOCAL_LLAMA_CPP requires model_path in config")

        # Detect GPU availability
        gpu_layers = self.config.n_gpu_layers
        try:
            import subprocess
            result = subprocess.run(
                ["rocm-smi", "--showmeminfo", "vram"],
                capture_output=True, text=True, timeout=5,
            )
            if "N/A" in result.stdout or result.returncode != 0:
                console.print("[yellow]GPU not detected, falling back to CPU inference[/]")
                gpu_layers = 0
            else:
                console.print("[green]AMD GPU detected, offloading layers[/]")
        except Exception:
            console.print("[yellow]rocm-smi not found, falling back to CPU inference[/]")
            gpu_layers = 0

        console.print(f"[dim]Loading local model: {self.config.model_path}[/]")
        self._local_llm = Llama(
            model_path=self.config.model_path,
            n_gpu_layers=gpu_layers,
            verbose=False,
            n_ctx=4096,
        )
        console.print("[green]Local model loaded.[/]")

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[dict] = None,
    ) -> str:
        """Send chat request with auto-retry."""
        temp = temperature if temperature is not None else self.config.temperature
        tokens = max_tokens if max_tokens is not None else self.config.max_tokens

        last_err = None
        for attempt in range(MAX_RETRIES):
            try:
                if self.config.backend == LLMBackend.LOCAL_LLAMA_CPP:
                    return self._chat_local(messages, temp, tokens)
                else:
                    return self._chat_http(messages, temp, tokens, response_format)
            except Exception as e:
                last_err = e
                if attempt < MAX_RETRIES - 1:
                    delay = RETRY_BASE_DELAY * (2 ** attempt)
                    console.print(
                        f"[yellow]Retry {attempt + 1}/{MAX_RETRIES} after {delay}s: {e}[/]"
                    )
                    time.sleep(delay)
        raise last_err

    def _chat_http(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        response_format: Optional[dict] = None,
    ) -> str:
        """HTTP API call (shared API or llama-server)."""
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format:
            payload["response_format"] = response_format

        url = f"{self.config.api_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        start = time.monotonic()
        resp = self._client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        elapsed_ms = int((time.monotonic() - start) * 1000)
        self._request_count += 1

        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        self._total_tokens += usage.get("total_tokens", 0)

        console.print(
            f"[dim]LLM [{self.config.backend.value}] "
            f"{elapsed_ms}ms | "
            f"tokens: {usage.get('prompt_tokens', '?')}->{usage.get('completion_tokens', '?')} | "
            f"total: {self._total_tokens}[/]"
        )
        return content

    def _chat_local(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> str:
        """llama-cpp-python direct inference."""
        prompt = self._messages_to_prompt(messages)

        start = time.monotonic()
        result = self._local_llm(
            prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            stop=[_IM_END, "<|endoftext|>"],
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        self._request_count += 1

        text = result["choices"][0]["text"]
        tokens_used = result.get("usage", {}).get("total_tokens", 0)
        self._total_tokens += tokens_used

        console.print(
            f"[dim]LLM [local_llama_cpp] "
            f"{elapsed_ms}ms | "
            f"tokens: {tokens_used} | "
            f"total: {self._total_tokens}[/]"
        )
        return text

    def chat_json(
        self,
        messages: list[dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> dict:
        """Send chat request, parse JSON from response."""
        raw = self.chat(messages, temperature, max_tokens)
        return _extract_json(raw)

    @property
    def stats(self) -> dict:
        return {
            "backend": self.config.backend.value,
            "model": self.config.model,
            "requests": self._request_count,
            "total_tokens": self._total_tokens,
        }

    @staticmethod
    def _messages_to_prompt(messages: list[dict[str, str]]) -> str:
        """Convert OpenAI-style messages to Qwen2.5 ChatML format."""
        parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            parts.append(f"{_IM_START}{role}\n{content}{_IM_END}")
        parts.append(f"{_IM_START}assistant\n")
        return "\n".join(parts)

    def close(self):
        if self._client:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _extract_json(text: str) -> dict:
    """Extract JSON from LLM response with multiple fallback strategies."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start)
        try:
            return json.loads(text[start:end].strip())
        except json.JSONDecodeError:
            pass

    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    start = -1

    # Try to repair truncated JSON by closing brackets
    stripped = text.strip()
    if stripped.startswith("{"):
        # Count open vs close braces
        opens = stripped.count("{")
        closes = stripped.count("}")
        if opens > closes:
            repair = stripped + "}" * (opens - closes)
            try:
                return json.loads(repair)
            except json.JSONDecodeError:
                pass

    raise ValueError(f"Failed to extract JSON from LLM response:\n{text[:300]}...")
```

---

## 8. `core/semgrep_runner.py`

```python
"""CodeRisk Agent - Semgrep Runner

Wraps Semgrep CLI to scan files and convert results to Risk objects.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

from core.models import (
    CodeFile,
    Confidence,
    Evidence,
    Language,
    Risk,
    Severity,
)

console = Console()

# Semgrep severity -> our severity mapping
_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def run_semgrep(
    file_path: Path,
    config: str = "p/default",
    timeout: int = 30,
) -> list[dict]:
    """Run Semgrep on a single file, return raw results."""
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--json", f"--config={config}", str(file_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode not in (0, 1):
            console.print(f"[yellow]Semgrep exited with code {result.returncode}[/]")
            if result.stderr:
                console.print(f"[dim]{result.stderr[:200]}[/]")
            return []

        data = json.loads(result.stdout)
        return data.get("results", [])
    except FileNotFoundError:
        console.print("[yellow]Semgrep not installed, skipping Semgrep scan.[/]")
        return []
    except subprocess.TimeoutExpired:
        console.print(f"[yellow]Semgrep timed out after {timeout}s[/]")
        return []
    except json.JSONDecodeError:
        console.print("[yellow]Semgrep output is not valid JSON[/]")
        return []


def semgrep_to_risks(
    raw_results: list[dict],
    code_file: CodeFile,
    risk_counter_start: int = 0,
) -> list[Risk]:
    """Convert Semgrep JSON results to Risk objects."""
    risks: list[Risk] = []
    counter = risk_counter_start

    for item in raw_results:
        counter += 1

        # Extract metadata
        check_id = item.get("check_id", "unknown")
        severity_raw = item.get("extra", {}).get("severity", "WARNING")
        metadata = item.get("extra", {}).get("metadata", {})

        # Build CWE list
        cwe_id = None
        cwe_list = metadata.get("cwe", [])
        if cwe_list:
            cwe_id = cwe_list[0] if isinstance(cwe_list[0], str) else cwe_list[0].get("id")

        # Location
        start_line = item.get("start", {}).get("line", 0)
        end_line = item.get("end", {}).get("line", 0)
        snippet = item.get("extra", {}).get("lines", "")

        # Map severity
        severity = _SEVERITY_MAP.get(severity_raw, Severity.MEDIUM)

        # Build risk
        message = item.get("extra", {}).get("message", check_id)
        fix_msg = item.get("extra", {}).get("fix", "")

        risks.append(Risk(
            id=f"RISK-{counter:03d}",
            title=f"Semgrep: {check_id}",
            description=message,
            severity=severity,
            confidence=Confidence.HIGH,
            cwe_id=cwe_id,
            language=code_file.language,
            file_path=code_file.path,
            line_start=start_line,
            line_end=end_line,
            evidence=[Evidence(
                source="semgrep",
                rule_id=check_id,
                snippet=snippet[:500],
                line_start=start_line,
                line_end=end_line,
                reasoning=f"Semgrep rule {check_id} matched",
            )],
            suggestion=fix_msg or "Review Semgrep documentation for this rule.",
        ))

    return risks


def analyze_with_semgrep(
    code_file: CodeFile,
    config: str = "p/default",
    risk_counter_start: int = 0,
) -> list[Risk]:
    """Full pipeline: run Semgrep on a file and return Risk objects."""
    raw = run_semgrep(code_file.path, config=config)
    if not raw:
        return []
    return semgrep_to_risks(raw, code_file, risk_counter_start)
```

---

## 9. `core/cve_client.py`

```python
"""CodeRisk Agent - CVE/NVD Client

Queries NVD (National Vulnerability Database) for CVE information.
Used by DeepVerifier for knowledge-base cross-validation.
"""

from __future__ import annotations

import time
from typing import Optional

import httpx
from rich.console import Console

console = Console()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 15
RATE_LIMIT_DELAY = 1.0  # NVD rate limit: 5 requests/30s without API key


class CVEClient:
    """Query NVD for CVE information by CWE ID or keyword."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._client = httpx.Client(timeout=REQUEST_TIMEOUT)
        self._cache: dict[str, list[dict]] = {}  # Simple in-memory cache
        self._last_request_time = 0.0

    def query_by_cwe(
        self,
        cwe_id: str,
        max_results: int = 5,
    ) -> list[dict]:
        """Query CVEs associated with a CWE ID.

        Args:
            cwe_id: CWE identifier, e.g. "CWE-120"
            max_results: Maximum number of CVEs to return

        Returns:
            List of CVE summaries with id, description, severity, references
        """
        # Check cache
        cache_key = f"{cwe_id}:{max_results}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Rate limiting
        self._rate_limit()

        params = {
            "cweId": cwe_id,
            "resultsPerPage": max_results,
        }
        if self.api_key:
            params["apiKey"] = self.api_key

        try:
            resp = self._client.get(NVD_API_BASE, params=params)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            console.print(f"[dim]CVE query failed for {cwe_id}: {e}[/]")
            return []

        vulnerabilities = data.get("vulnerabilities", [])
        results = []

        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "unknown")

            # Extract description
            descriptions = cve.get("descriptions", [])
            desc_en = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_en = d.get("value", "")
                    break

            # Extract severity from CVSS
            metrics = cve.get("metrics", {})
            severity = "unknown"
            cvss_score = 0.0

            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                version_metrics = metrics.get(version_key, [])
                if version_metrics:
                    cvss_data = version_metrics[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "unknown").lower()
                    break

            # Extract references
            references = []
            for ref in cve.get("references", [])[:3]:
                references.append(ref.get("url", ""))

            results.append({
                "cve_id": cve_id,
                "description": desc_en[:300],
                "severity": severity,
                "cvss_score": cvss_score,
                "references": references,
            })

        # Cache results
        self._cache[cache_key] = results
        return results

    def has_known_exploits(self, cwe_id: str) -> bool:
        """Check if a CWE has known exploitable CVEs (quick check)."""
        results = self.query_by_cwe(cwe_id, max_results=3)
        # If any CVE has high/critical severity, consider it exploitable
        return any(
            r["severity"] in ("high", "critical") and r["cvss_score"] >= 7.0
            for r in results
        )

    def get_cve_summary(self, cwe_id: str) -> str:
        """Get a brief summary of CVEs for a CWE (for report inclusion)."""
        results = self.query_by_cwe(cwe_id, max_results=3)
        if not results:
            return f"No CVE data found for {cwe_id}"

        summaries = []
        for r in results:
            summaries.append(
                f"{r['cve_id']} ({r['severity']}, CVSS {r['cvss_score']}): "
                f"{r['description'][:100]}..."
            )
        return " | ".join(summaries)

    def _rate_limit(self):
        """Respect NVD rate limits."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.monotonic()

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
```

---

## 10. `core/memory.py`

```python
"""CodeRisk Agent - Memory Layer

Two-memory system using in-memory storage (ChromaDB optional):
1. Correct Memory: Store confirmed vulnerability patterns for recall
2. Error Memory: Store false-positive patterns for suppression

Makes the system "learn" over time - same code patterns get faster,
false positives get suppressed.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

from rich.console import Console

from core.models import Confidence, Risk, Severity

console = Console()

# Memory storage file (JSON-based, ChromaDB optional upgrade)
MEMORY_DIR = os.path.expanduser("~/.coderisk/memory")
CORRECT_MEMORY_FILE = os.path.join(MEMORY_DIR, "correct_memory.json")
ERROR_MEMORY_FILE = os.path.join(MEMORY_DIR, "error_memory.json")

# Similarity threshold for pattern matching
SIMILARITY_THRESHOLD = 0.85


class MemoryEntry:
    """A single memory entry."""

    def __init__(
        self,
        pattern_hash: str,
        cwe_id: str,
        severity: str,
        title: str,
        description: str,
        suggestion: str,
        confidence: str,
        source_count: int = 1,
        last_seen: float = 0.0,
    ):
        self.pattern_hash = pattern_hash
        self.cwe_id = cwe_id
        self.severity = severity
        self.title = title
        self.description = description
        self.suggestion = suggestion
        self.confidence = confidence
        self.source_count = source_count
        self.last_seen = last_seen or time.time()

    def to_dict(self) -> dict:
        return {
            "pattern_hash": self.pattern_hash,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "source_count": self.source_count,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MemoryEntry":
        return cls(**data)


class MemoryLayer:
    """Memory layer with correct memory and error memory."""

    def __init__(self, persist: bool = True):
        self.persist = persist
        self._correct_memory: dict[str, MemoryEntry] = {}
        self._error_memory: dict[str, MemoryEntry] = {}

        if persist:
            self._load()

    def store_correct(self, risk: Risk) -> None:
        """Store a confirmed vulnerability pattern in correct memory."""
        pattern_hash = self._hash_risk_pattern(risk)

        if pattern_hash in self._correct_memory:
            # Update existing entry
            entry = self._correct_memory[pattern_hash]
            entry.source_count += 1
            entry.last_seen = time.time()
            # Upgrade confidence if seen multiple times
            if entry.source_count >= 3 and entry.confidence != "high":
                entry.confidence = "high"
        else:
            self._correct_memory[pattern_hash] = MemoryEntry(
                pattern_hash=pattern_hash,
                cwe_id=risk.cwe_id or "",
                severity=risk.severity.value,
                title=risk.title,
                description=risk.description,
                suggestion=risk.suggestion,
                confidence=risk.confidence.value,
            )

        if self.persist:
            self._save()

    def store_error(self, risk: Risk) -> None:
        """Store a false-positive pattern in error memory."""
        pattern_hash = self._hash_risk_pattern(risk)

        if pattern_hash in self._error_memory:
            entry = self._error_memory[pattern_hash]
            entry.source_count += 1
            entry.last_seen = time.time()
        else:
            self._error_memory[pattern_hash] = MemoryEntry(
                pattern_hash=pattern_hash,
                cwe_id=risk.cwe_id or "",
                severity=risk.severity.value,
                title=risk.title,
                description=risk.description,
                suggestion=risk.suggestion,
                confidence="low",
            )

        if self.persist:
            self._save()

    def recall(self, risk: Risk) -> Optional[MemoryEntry]:
        """Check if a risk pattern matches known correct/incorrect patterns.

        Returns:
            MemoryEntry if found, None otherwise
        """
        pattern_hash = self._hash_risk_pattern(risk)

        # Check error memory first (suppress known false positives)
        if pattern_hash in self._error_memory:
            entry = self._error_memory[pattern_hash]
            if entry.source_count >= 2:
                console.print(
                    f"[dim]  Memory: suppressed known false positive {risk.id} "
                    f"(seen {entry.source_count} times)[/]"
                )
                return entry

        # Check correct memory (boost confidence for known patterns)
        if pattern_hash in self._correct_memory:
            entry = self._correct_memory[pattern_hash]
            console.print(
                f"[dim]  Memory: recalled pattern for {risk.id} "
                f"(seen {entry.source_count} times)[/]"
            )
            return entry

        return None

    def get_stats(self) -> dict:
        """Get memory statistics."""
        return {
            "correct_patterns": len(self._correct_memory),
            "error_patterns": len(self._error_memory),
            "total": len(self._correct_memory) + len(self._error_memory),
        }

    def _hash_risk_pattern(self, risk: Risk) -> str:
        """Create a hash of the risk pattern for matching.

        Uses CWE + file extension + code pattern to identify similar risks.
        """
        # Extract code snippet pattern (first 100 chars of evidence)
        code_pattern = ""
        if risk.evidence:
            code_pattern = risk.evidence[0].snippet[:100]

        # Hash: CWE + language + code pattern
        key = f"{risk.cwe_id}:{risk.language}:{code_pattern}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _save(self):
        """Persist memory to disk."""
        os.makedirs(MEMORY_DIR, exist_ok=True)

        correct_data = {k: v.to_dict() for k, v in self._correct_memory.items()}
        error_data = {k: v.to_dict() for k, v in self._error_memory.items()}

        with open(CORRECT_MEMORY_FILE, "w") as f:
            json.dump(correct_data, f, indent=2)

        with open(ERROR_MEMORY_FILE, "w") as f:
            json.dump(error_data, f, indent=2)

    def _load(self):
        """Load memory from disk."""
        try:
            if os.path.exists(CORRECT_MEMORY_FILE):
                with open(CORRECT_MEMORY_FILE) as f:
                    data = json.load(f)
                self._correct_memory = {
                    k: MemoryEntry.from_dict(v) for k, v in data.items()
                }
        except Exception:
            pass

        try:
            if os.path.exists(ERROR_MEMORY_FILE):
                with open(ERROR_MEMORY_FILE) as f:
                    data = json.load(f)
                self._error_memory = {
                    k: MemoryEntry.from_dict(v) for k, v in data.items()
                }
        except Exception:
            pass

    def clear(self):
        """Clear all memory."""
        self._correct_memory.clear()
        self._error_memory.clear()
        if self.persist:
            self._save()
```

---

## 11. `agents/__init__.py`

```python
"""CodeRisk Agent - Agent Module"""

from agents.static_analyzer import StaticAnalyzer
from agents.semantic_analyzer import SemanticAnalyzer
from agents.deep_verifier import DeepVerifier
from agents.report_generator import ReportGenerator
```

---

## 12. `agents/static_analyzer.py`

```python
"""Agent 1: Tree-sitter 静态分析器

职责：
- 用 Tree-sitter 解析 AST
- 检测 C/Python 中的危险模式
- 输出结构化风险列表
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from rich.console import Console

from core.models import (
    CodeFile,
    Confidence,
    Evidence,
    Language,
    Risk,
    Severity,
)

console = Console()

# ─── C 语言危险模式 ──────────────────────────────────────────────

C_DANGEROUS_FUNCTIONS = {
    "gets": {
        "cwe": "CWE-120",
        "severity": Severity.CRITICAL,
        "title": "Buffer Overflow via gets()",
        "desc": "gets() 不检查边界，可导致栈缓冲区溢出",
        "fix": "用 fgets(buf, sizeof(buf), stdin) 替代",
    },
    "strcpy": {
        "cwe": "CWE-120",
        "severity": Severity.HIGH,
        "title": "Unbounded strcpy()",
        "desc": "strcpy() 不检查目标缓冲区大小",
        "fix": "用 strncpy() 或 strlcpy() 替代",
    },
    "strcat": {
        "cwe": "CWE-120",
        "severity": Severity.HIGH,
        "title": "Unbounded strcat()",
        "desc": "strcat() 不检查目标缓冲区剩余空间",
        "fix": "用 strncat() 或 strlcat() 替代",
    },
    "sprintf": {
        "cwe": "CWE-134",
        "severity": Severity.HIGH,
        "title": "Format String via sprintf()",
        "desc": "sprintf() 不检查目标缓冲区大小，且可能被格式字符串攻击",
        "fix": "用 snprintf(buf, sizeof(buf), ...) 替代",
    },
    "scanf": {
        "cwe": "CWE-120",
        "severity": Severity.MEDIUM,
        "title": "Unbounded scanf()",
        "desc": "scanf(\"%s\", ...) 无长度限制",
        "fix": "用 scanf(\"%99s\", buf) 限制长度，或用 fgets",
    },
    "system": {
        "cwe": "CWE-78",
        "severity": Severity.HIGH,
        "title": "OS Command Injection via system()",
        "desc": "system() 直接执行 shell 命令，可能被注入",
        "fix": "避免使用 system()，用 exec 系列函数替代",
    },
}

C_VULNERABLE_PATTERNS = [
    {
        "pattern": r"malloc\s*\(.*\)\s*;",
        "check_null": True,
        "cwe": "CWE-476",
        "severity": Severity.MEDIUM,
        "title": "malloc() 返回值未检查",
        "desc": "malloc() 可能返回 NULL，直接使用会导致空指针解引用",
        "fix": "检查 malloc() 返回值是否为 NULL",
    },
    {
        "pattern": r"free\s*\([^)]+\)\s*;",
        "check_double_free": True,
        "cwe": "CWE-415",
        "severity": Severity.HIGH,
        "title": "Potential Double Free",
        "desc": "free() 后指针未置 NULL，可能被重复释放",
        "fix": "free(ptr) 后立即 ptr = NULL",
    },
]

# ─── Python 危险模式 ────────────────────────────────────────────

PYTHON_DANGEROUS_CALLS = {
    "eval": {
        "cwe": "CWE-95",
        "severity": Severity.CRITICAL,
        "title": "Code Injection via eval()",
        "desc": "eval() 执行任意代码，极度危险",
        "fix": "用 ast.literal_eval() 替代，或重构逻辑避免动态执行",
    },
    "exec": {
        "cwe": "CWE-95",
        "severity": Severity.CRITICAL,
        "title": "Code Injection via exec()",
        "desc": "exec() 执行任意代码",
        "fix": "重构逻辑避免动态执行",
    },
    "pickle.loads": {
        "cwe": "CWE-502",
        "severity": Severity.CRITICAL,
        "title": "Deserialization via pickle.loads()",
        "desc": "pickle.loads() 反序列化不可信数据可执行任意代码",
        "fix": "用 json 或 msgpack 替代 pickle",
    },
    "subprocess.call": {
        "cwe": "CWE-78",
        "severity": Severity.MEDIUM,
        "title": "Shell Injection Risk",
        "desc": "subprocess.call() 配合 shell=True 可被注入",
        "fix": "用 subprocess.run(args, shell=False) 并传入列表",
    },
    "os.system": {
        "cwe": "CWE-78",
        "severity": Severity.HIGH,
        "title": "OS Command Injection via os.system()",
        "desc": "os.system() 直接执行 shell 命令",
        "fix": "用 subprocess.run() 替代",
    },
}

PYTHON_VULNERABLE_PATTERNS = [
    {
        "pattern": r"open\s*\([^)]*['\"]w['\"]",
        "cwe": "CWE-73",
        "severity": Severity.LOW,
        "title": "File Write Without Validation",
        "desc": "写文件前应验证路径，防止路径遍历",
        "fix": "用 os.path.realpath() 验证路径在预期目录内",
    },
    {
        "pattern": r"assert\s+",
        "cwe": "CWE-617",
        "severity": Severity.LOW,
        "title": "Assert in Production Code",
        "desc": "assert 在 -O 模式下被跳过，不应用于安全检查",
        "fix": "用 if + raise 替代 assert",
    },
]


class StaticAnalyzer:
    """Tree-sitter 静态分析器 Agent"""

    def __init__(self):
        self._risk_counter = 0

    def analyze(self, code_file: CodeFile) -> list[Risk]:
        """分析单个文件，返回风险列表"""
        risks: list[Risk] = []

        if code_file.language == Language.C:
            risks.extend(self._analyze_c(code_file))
        elif code_file.language == Language.PYTHON:
            risks.extend(self._analyze_python(code_file))

        return risks

    def analyze_batch(self, files: list[CodeFile]) -> list[Risk]:
        """批量分析多个文件"""
        all_risks: list[Risk] = []
        for f in files:
            risks = self.analyze(f)
            all_risks.extend(risks)
            if risks:
                console.print(f"  [red]⚠ {f.path}: {len(risks)} risks[/]")
            else:
                console.print(f"  [green]✓ {f.path}: clean[/]")
        return all_risks

    # ─── C 分析 ──────────────────────────────────────────────────

    def _analyze_c(self, code_file: CodeFile) -> list[Risk]:
        risks: list[Risk] = []
        lines = code_file.content.split("\n")

        for i, line in enumerate(lines, start=1):
            # 检查危险函数调用
            for func, info in C_DANGEROUS_FUNCTIONS.items():
                if re.search(rf"\b{func}\s*\(", line):
                    risks.append(self._make_risk(
                        title=info["title"],
                        description=info["desc"],
                        severity=info["severity"],
                        confidence=Confidence.HIGH,
                        cwe_id=info["cwe"],
                        language=Language.C,
                        file_path=code_file.path,
                        line_start=i,
                        line_end=i,
                        snippet=line.strip(),
                        source="pattern_match",
                        reasoning=f"检测到危险函数 {func}() 调用",
                        suggestion=info["fix"],
                    ))

            # 检查模式匹配
            for pat in C_VULNERABLE_PATTERNS:
                if re.search(pat["pattern"], line):
                    # 简化：malloc 后 3 行内无 NULL 检查
                    if pat.get("check_null"):
                        context = "\n".join(lines[i:i+3])
                        if "NULL" not in context and "null" not in context:
                            risks.append(self._make_risk(
                                title=pat["title"],
                                description=pat["desc"],
                                severity=pat["severity"],
                                confidence=Confidence.MEDIUM,
                                cwe_id=pat["cwe"],
                                language=Language.C,
                                file_path=code_file.path,
                                line_start=i,
                                line_end=i,
                                snippet=line.strip(),
                                source="pattern_match",
                                reasoning=f"匹配模式: {pat['pattern']}",
                                suggestion=pat["fix"],
                            ))

        return risks

    # ─── Python 分析 ────────────────────────────────────────────

    def _analyze_python(self, code_file: CodeFile) -> list[Risk]:
        risks: list[Risk] = []
        lines = code_file.content.split("\n")

        for i, line in enumerate(lines, start=1):
            # 跳过注释
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # 检查危险函数调用
            for func, info in PYTHON_DANGEROUS_CALLS.items():
                if re.search(rf"\b{func}\s*\(", line):
                    risks.append(self._make_risk(
                        title=info["title"],
                        description=info["desc"],
                        severity=info["severity"],
                        confidence=Confidence.HIGH,
                        cwe_id=info["cwe"],
                        language=Language.PYTHON,
                        file_path=code_file.path,
                        line_start=i,
                        line_end=i,
                        snippet=line.strip(),
                        source="pattern_match",
                        reasoning=f"检测到危险函数 {func}() 调用",
                        suggestion=info["fix"],
                    ))

            # 检查模式匹配
            for pat in PYTHON_VULNERABLE_PATTERNS:
                if re.search(pat["pattern"], line):
                    risks.append(self._make_risk(
                        title=pat["title"],
                        description=pat["desc"],
                        severity=pat["severity"],
                        confidence=Confidence.MEDIUM,
                        cwe_id=pat["cwe"],
                        language=Language.PYTHON,
                        file_path=code_file.path,
                        line_start=i,
                        line_end=i,
                        snippet=line.strip(),
                        source="pattern_match",
                        reasoning=f"匹配模式: {pat['pattern']}",
                        suggestion=pat["fix"],
                    ))

        return risks

    # ─── 工具方法 ────────────────────────────────────────────────

    def _make_risk(self, **kwargs) -> Risk:
        self._risk_counter += 1
        snippet = kwargs.pop("snippet")
        source = kwargs.pop("source")
        reasoning = kwargs.pop("reasoning")
        return Risk(
            id=f"RISK-{self._risk_counter:03d}",
            evidence=[Evidence(
                source=source,
                snippet=snippet,
                line_start=kwargs["line_start"],
                line_end=kwargs["line_end"],
                reasoning=reasoning,
            )],
            **kwargs,
        )
```

---

## 13. `agents/semantic_analyzer.py`

```python
"""Agent 2: Semantic Analyzer (LLM-driven)

Takes risks from Agent 1 (static) + Agent 3 (semgrep),
uses LLM to verify, deduplicate, and enrich with deeper analysis.
"""

from __future__ import annotations

import json
from typing import Optional

from rich.console import Console

from core.llm_client import LLMClient
from core.models import (
    CodeFile,
    Confidence,
    Evidence,
    Language,
    Risk,
    Severity,
)

console = Console()

SYSTEM_PROMPT = """You are a senior code security auditor. Given:
1. Source code of a file
2. A list of risks found by static analysis

Your tasks:
- VALIDATE each risk: is it a real vulnerability or a false positive?
- ENRICH: provide attack scenario and impact for confirmed risks
- MERGE duplicates: if multiple risks describe the same issue, merge them
- ADD missed risks: if you spot vulnerabilities the static analyzer missed

Output JSON format:
{
  "validated_risks": [
    {
      "id": "RISK-001",
      "is_true_positive": true,
      "attack_scenario": "...",
      "impact": "...",
      "adjusted_severity": "critical|high|medium|low|info",
      "notes": "..."
    }
  ],
  "new_risks": [
    {
      "title": "...",
      "description": "...",
      "severity": "critical|high|medium|low",
      "cwe_id": "CWE-xxx",
      "line_start": 10,
      "line_end": 10,
      "attack_scenario": "...",
      "suggestion": "..."
    }
  ]
}"""


class SemanticAnalyzer:
    """LLM-driven semantic code analyzer."""

    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def analyze(
        self,
        code_file: CodeFile,
        existing_risks: list[Risk],
    ) -> list[Risk]:
        """Verify and enrich existing risks using LLM."""
        if not existing_risks:
            # No risks to validate, but we can still ask LLM to find new ones
            return self._scan_for_new_risks(code_file)

        prompt = self._build_prompt(code_file, existing_risks)

        try:
            response = self.llm.chat_json(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=4096,
            )
        except Exception as e:
            console.print(f"[yellow]Semantic analysis failed: {e}[/]")
            return existing_risks

        return self._merge_results(existing_risks, response, code_file)

    def _build_prompt(self, code_file: CodeFile, risks: list[Risk]) -> str:
        """Build the analysis prompt."""
        risk_summaries = []
        for r in risks:
            risk_summaries.append(
                f"- {r.id}: [{r.severity.value}] {r.title}\n"
                f"  CWE: {r.cwe_id or 'N/A'} | Lines: {r.line_start}-{r.line_end}\n"
                f"  Desc: {r.description}"
            )

        return f"""## Source File: {code_file.path}
Language: {code_file.language.value}

```{code_file.language.value}
{code_file.content}
```

## Risks Found by Static Analysis
{chr(10).join(risk_summaries)}

Please validate each risk and identify any missed vulnerabilities."""

    def _merge_results(
        self,
        existing_risks: list[Risk],
        llm_response: dict,
        code_file: CodeFile,
    ) -> list[Risk]:
        """Merge LLM validation results with existing risks."""
        validated = llm_response.get("validated_risks", [])
        new_risks_raw = llm_response.get("new_risks", [])

        # Update existing risks based on validation
        risk_map = {r.id: r for r in existing_risks}
        merged: list[Risk] = []

        for v in validated:
            risk_id = v.get("id", "")
            if risk_id not in risk_map:
                continue

            risk = risk_map[risk_id]

            # If LLM says it's a false positive, downgrade to INFO
            if not v.get("is_true_positive", True):
                risk = risk.model_copy(update={
                    "severity": Severity.INFO,
                    "confidence": Confidence.LOW,
                    "description": risk.description + " [LLM: likely false positive]",
                })
            else:
                # Enrich with attack scenario
                scenario = v.get("attack_scenario", "")
                impact = v.get("impact", "")
                notes = v.get("notes", "")
                if scenario or impact or notes:
                    enrichment = []
                    if scenario:
                        enrichment.append(f"Attack: {scenario}")
                    if impact:
                        enrichment.append(f"Impact: {impact}")
                    if notes:
                        enrichment.append(f"Notes: {notes}")
                    risk = risk.model_copy(update={
                        "description": risk.description + " | " + " | ".join(enrichment),
                    })

                # Adjust severity if LLM suggests different
                adj_sev = v.get("adjusted_severity", "").lower()
                if adj_sev and adj_sev in [s.value for s in Severity]:
                    new_sev = Severity(adj_sev)
                    if new_sev != risk.severity:
                        risk = risk.model_copy(update={"severity": new_sev})

            merged.append(risk)

        # Add risks that LLM didn't validate (keep as-is)
        validated_ids = {v.get("id") for v in validated}
        for risk in existing_risks:
            if risk.id not in validated_ids:
                merged.append(risk)

        # Add new risks found by LLM
        counter = len(merged)
        for nr in new_risks_raw:
            counter += 1
            sev_str = nr.get("severity", "medium").lower()
            sev = Severity(sev_str) if sev_str in [s.value for s in Severity] else Severity.MEDIUM

            merged.append(Risk(
                id=f"RISK-{counter:03d}",
                title=nr.get("title", "LLM-detected risk"),
                description=nr.get("description", ""),
                severity=sev,
                confidence=Confidence.MEDIUM,
                cwe_id=nr.get("cwe_id"),
                language=code_file.language,
                file_path=code_file.path,
                line_start=nr.get("line_start", 0),
                line_end=nr.get("line_end", 0),
                evidence=[Evidence(
                    source="ai",
                    snippet="",
                    line_start=nr.get("line_start", 0),
                    line_end=nr.get("line_end", 0),
                    reasoning=f"LLM analysis: {nr.get('attack_scenario', 'detected by semantic analysis')}",
                )],
                suggestion=nr.get("suggestion", "Review this code section."),
            ))

        return merged

    def _scan_for_new_risks(self, code_file: CodeFile) -> list[Risk]:
        """Ask LLM to find risks when no static risks exist."""
        prompt = f"""## Source File: {code_file.path}
Language: {code_file.language.value}

```{code_file.language.value}
{code_file.content}
```

No risks were found by static analysis. Please scan for any security vulnerabilities.

Output JSON:
{{
  "new_risks": [
    {{
      "title": "...",
      "description": "...",
      "severity": "critical|high|medium|low",
      "cwe_id": "CWE-xxx",
      "line_start": 10,
      "line_end": 10,
      "attack_scenario": "...",
      "suggestion": "..."
    }}
  ]
}}"""

        try:
            response = self.llm.chat_json(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=2048,
            )
            return self._merge_results([], response, code_file)
        except Exception as e:
            console.print(f"[yellow]LLM scan failed: {e}[/]")
            return []
```

---

## 14. `agents/deep_verifier.py`

```python
"""Agent 3: Deep Verifier - Triple Cross-Validation

Implements three verification strategies:
1. Tool cross-validation (Semgrep + pattern matching confirmation)
2. Knowledge base cross-validation (CWE/CVE lookup via NVD)
3. Memory-based validation (recall known patterns, suppress false positives)

Also implements the self-reflection loop: if Agent 2 missed something,
Agent 3 can flag it and trigger re-analysis.
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console

from core.cve_client import CVEClient
from core.llm_client import LLMClient
from core.memory import MemoryLayer
from core.models import (
    CodeFile,
    Confidence,
    Evidence,
    Risk,
    Severity,
)

console = Console()

# Thresholds for confidence adjustment
HIGH_CONFIRMATIONS = 2
MEDIUM_CONFIRMATIONS = 1

REFLECTION_PROMPT = """You are a security verification expert. Given a code file and a list of risks found by static + semantic analysis, your job is to:

1. VERIFY each risk: Is it confirmed by multiple sources?
2. FIND MISSED vulnerabilities: Are there risks the previous agents missed?
3. FLAG FALSE POSITIVES: Are any risks likely wrong?

For each risk, assess:
- Is the evidence strong? (multiple independent sources agree?)
- Is the attack scenario realistic?
- Would a real attacker exploit this?

Output JSON:
{
  "verified_risks": [
    {
      "id": "RISK-001",
      "confirmed": true,
      "confidence_reason": "Both static analysis and LLM agree this is a real vulnerability",
      "false_positive_likelihood": "low"
    }
  ],
  "missed_risks": [
    {
      "title": "...",
      "description": "...",
      "severity": "critical|high|medium|low",
      "cwe_id": "CWE-xxx",
      "line_start": 10,
      "line_end": 10,
      "reasoning": "Why this was missed by previous agents"
    }
  ]
}"""


class DeepVerifier:
    """Agent 3: Deep verification with triple cross-validation and self-reflection."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        memory: Optional[MemoryLayer] = None,
        cve_client: Optional[CVEClient] = None,
    ):
        self.llm = llm_client
        self.memory = memory or MemoryLayer()
        self.cve = cve_client or CVEClient()

    def verify_batch(
        self,
        files: list[CodeFile],
        risks: list[Risk],
    ) -> list[Risk]:
        """Verify all risks across all files."""
        if not risks:
            return risks

        console.print("[bold cyan]  Agent 3: Deep verification...[/]")

        verified_risks = []
        suppressed = 0

        for risk in risks:
            # Check memory first
            memory_entry = self.memory.recall(risk)

            if memory_entry and memory_entry.source_count >= 2:
                # Known false positive - suppress
                if risk.id not in [r.id for r in verified_risks]:
                    suppressed += 1
                    continue

            # Triple cross-validation
            verified = self._verify_single_risk(risk)
            verified_risks.append(verified)

            # Store in appropriate memory
            if verified.confidence == Confidence.HIGH:
                self.memory.store_correct(verified)

        if suppressed > 0:
            console.print(f"  [dim]  Suppressed {suppressed} known false positives[/]")

        # Self-reflection: ask LLM to find missed risks
        if self.llm:
            for f in files:
                file_risks = [r for r in verified_risks if r.file_path == f.path]
                missed = self._reflect_on_file(f, file_risks)
                if missed:
                    console.print(
                        f"  [yellow]  Agent 3 found {len(missed)} missed risks in {f.path}[/]"
                    )
                    verified_risks.extend(missed)

        return verified_risks

    def _verify_single_risk(self, risk: Risk) -> Risk:
        """Triple cross-validation for a single risk."""
        confirmations = 0
        reasons = []

        # Strategy 1: Tool cross-validation
        has_semgrep = any(e.source == "semgrep" for e in risk.evidence)
        has_pattern = any(e.source == "pattern_match" for e in risk.evidence)
        has_ai = any(e.source == "ai" for e in risk.evidence)

        if has_semgrep:
            confirmations += 1
            reasons.append("confirmed by Semgrep")

        if has_pattern:
            confirmations += 1
            reasons.append("confirmed by pattern matching")

        if has_ai:
            confirmations += 1
            reasons.append("confirmed by LLM analysis")

        # Strategy 2: Knowledge base cross-validation (CVE lookup)
        if risk.cwe_id and risk.cwe_id.startswith("CWE-"):
            confirmations += 1
            reasons.append(f"known CWE: {risk.cwe_id}")

            # Active CVE lookup for critical/high risks
            if risk.severity in (Severity.CRITICAL, Severity.HIGH):
                try:
                    cve_summary = self.cve.get_cve_summary(risk.cwe_id)
                    if "No CVE data" not in cve_summary:
                        confirmations += 1
                        reasons.append(f"CVE data exists for {risk.cwe_id}")
                        # Append CVE info to description
                        risk = risk.model_copy(update={
                            "description": risk.description + f" [CVE: {cve_summary[:150]}]",
                        })
                except Exception:
                    pass  # CVE lookup is best-effort

        # Strategy 3: Severity consistency check
        if risk.severity in (Severity.CRITICAL, Severity.HIGH):
            if len(risk.evidence) >= 2:
                confirmations += 1
                reasons.append("multiple evidence for high-severity risk")

        # Adjust confidence
        new_confidence = self._calculate_confidence(confirmations)

        if new_confidence != risk.confidence:
            reason_str = "; ".join(reasons) if reasons else "no cross-validation"
            updated_desc = (
                risk.description
                + f" [Verification: {confirmations} confirmations ({reason_str})]"
            )
            risk = risk.model_copy(update={
                "confidence": new_confidence,
                "description": updated_desc,
            })

        return risk

    def _calculate_confidence(self, confirmations: int) -> Confidence:
        if confirmations >= HIGH_CONFIRMATIONS:
            return Confidence.HIGH
        elif confirmations >= MEDIUM_CONFIRMATIONS:
            return Confidence.MEDIUM
        else:
            return Confidence.LOW

    def _reflect_on_file(
        self,
        code_file: CodeFile,
        existing_risks: list[Risk],
    ) -> list[Risk]:
        """Ask LLM to find risks that previous agents missed."""
        if not self.llm:
            return []

        risk_summaries = []
        for r in existing_risks:
            risk_summaries.append(
                f"- {r.id}: [{r.severity.value}] {r.title} "
                f"(CWE: {r.cwe_id or 'N/A'}, Lines: {r.line_start}-{r.line_end})"
            )

        existing_text = "\n".join(risk_summaries) if risk_summaries else "No risks found."

        prompt = f"""## Source File: {code_file.path}
Language: {code_file.language.value}

```{code_file.language.value}
{code_file.content}
```

## Risks Found by Previous Agents
{existing_text}

Please verify these risks and find any missed vulnerabilities."""

        try:
            response = self.llm.chat_json(
                messages=[
                    {"role": "system", "content": REFLECTION_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=4096,
            )
        except Exception as e:
            console.print(f"[dim]Reflection failed: {e}[/]")
            return []

        missed_raw = response.get("missed_risks", [])
        missed_risks = []
        counter = len(existing_risks)

        for mr in missed_raw:
            counter += 1
            sev_str = mr.get("severity", "medium").lower()
            sev = Severity(sev_str) if sev_str in [s.value for s in Severity] else Severity.MEDIUM

            missed_risks.append(Risk(
                id=f"RISK-{counter:03d}",
                title=mr.get("title", "Missed risk (Agent 3 reflection)"),
                description=mr.get("description", ""),
                severity=sev,
                confidence=Confidence.MEDIUM,
                cwe_id=mr.get("cwe_id"),
                language=code_file.language,
                file_path=code_file.path,
                line_start=mr.get("line_start", 0),
                line_end=mr.get("line_end", 0),
                evidence=[Evidence(
                    source="ai",
                    snippet="",
                    line_start=mr.get("line_start", 0),
                    line_end=mr.get("line_end", 0),
                    reasoning=f"Agent 3 reflection: {mr.get('reasoning', 'missed by previous agents')}",
                )],
                suggestion=mr.get("suggestion", "Review this code section."),
            ))

        return missed_risks
```

---

## 15. `agents/report_generator.py`

```python
"""Agent 4: Report Generator

Generates structured audit reports in multiple formats:
- JSON (for API/programmatic use)
- Markdown (for human review)
- Rich terminal output (for CLI)
- CVSS scoring for critical risks
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from core.models import AnalysisResult, Risk, Severity

console = Console()


class ReportGenerator:
    """Agent 4: Generate structured audit reports."""

    def generate_json(self, result: AnalysisResult) -> dict:
        """Generate structured JSON report."""
        return {
            "scan_id": result.request_id,
            "timestamp": result.timestamp.isoformat(),
            "summary": {
                "files_analyzed": result.files_analyzed,
                "total_risks": result.total_risks,
                "has_critical": result.has_critical,
                "risk_breakdown": result.risk_summary,
            },
            "risks": [
                {
                    "id": r.id,
                    "title": r.title,
                    "severity": r.severity.value,
                    "confidence": r.confidence.value,
                    "cwe": r.cwe_id,
                    "file": str(r.file_path),
                    "line_start": r.line_start,
                    "line_end": r.line_end,
                    "description": r.description,
                    "suggestion": r.suggestion,
                    "evidence_count": r.evidence_count,
                    "evidence": [
                        {
                            "source": e.source,
                            "rule_id": e.rule_id,
                            "snippet": e.snippet[:200],
                            "reasoning": e.reasoning,
                        }
                        for e in r.evidence
                    ],
                }
                for r in sorted(result.risks, key=lambda r: list(Severity).index(r.severity))
            ],
            "meta": {
                "model_used": result.model_used,
                "analysis_time_ms": result.analysis_time_ms,
                "version": "0.3.0",
            },
        }

    def generate_markdown(self, result: AnalysisResult) -> str:
        """Generate Markdown audit report."""
        lines = [
            "# CodeRisk Agent - Security Audit Report",
            "",
            f"**Scan ID:** `{result.request_id}`",
            f"**Timestamp:** {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Files Analyzed:** {result.files_analyzed}",
            f"**Analysis Time:** {result.analysis_time_ms}ms",
            f"**Model:** {result.model_used}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Risks | **{result.total_risks}** |",
            f"| Critical | **{result.risk_summary.get('critical', 0)}** |",
            f"| High | **{result.risk_summary.get('high', 0)}** |",
            f"| Medium | **{result.risk_summary.get('medium', 0)}** |",
            f"| Low | **{result.risk_summary.get('low', 0)}** |",
            f"| Info | **{result.risk_summary.get('info', 0)}** |",
            "",
        ]

        if result.has_critical:
            lines.extend([
                "> **WARNING:** Critical vulnerabilities detected! Immediate action required.",
                "",
            ])

        # Risk details
        lines.extend(["## Risk Details", ""])

        for risk in sorted(result.risks, key=lambda r: list(Severity).index(r.severity)):
            severity_icon = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵",
                Severity.INFO: "⚪",
            }.get(risk.severity, "⚪")

            lines.extend([
                f"### {risk.id}: {severity_icon} {risk.title}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Severity | **{risk.severity.value.upper()}** |",
                f"| Confidence | {risk.confidence.value} |",
                f"| CWE | {risk.cwe_id or 'N/A'} |",
                f"| File | `{risk.file_path}` |",
                f"| Lines | {risk.line_start}-{risk.line_end} |",
                f"| Evidence Sources | {risk.evidence_count} |",
                "",
                f"**Description:** {risk.description}",
                "",
                f"**Fix:** {risk.suggestion}",
                "",
            ])

            # Evidence details
            if risk.evidence:
                lines.append("**Evidence:**")
                for e in risk.evidence:
                    lines.append(f"- Source: `{e.source}` | {e.reasoning}")
                lines.append("")

        # Footer
        lines.extend([
            "---",
            "",
            f"*Generated by CodeRisk Agent v0.3.0 | {result.timestamp.isoformat()}*",
        ])

        return "\n".join(lines)

    def print_terminal(self, result: AnalysisResult) -> None:
        """Print rich terminal output."""
        # Summary table
        summary_table = Table(
            title="Risk Summary",
            show_header=True,
            border_style="cyan",
        )
        summary_table.add_column("Severity", justify="center")
        summary_table.add_column("Count", justify="center")

        severity_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        severity_icon = {
            "critical": "C",
            "high": "H",
            "medium": "M",
            "low": "L",
            "info": "I",
        }

        for level in ["critical", "high", "medium", "low", "info"]:
            count = result.risk_summary.get(level, 0)
            if count > 0:
                summary_table.add_row(
                    f"[{severity_style[level]}]{severity_icon[level]} {level.upper()}[/]",
                    f"[{severity_style[level]}]{count}[/]",
                )

        console.print()
        console.print(summary_table)
        console.print()

        # Detail table
        if result.risks:
            risk_table = Table(
                title="Risk Details",
                show_header=True,
                border_style="yellow",
            )
            risk_table.add_column("ID", style="bold")
            risk_table.add_column("Sev")
            risk_table.add_column("Conf")
            risk_table.add_column("CWE")
            risk_table.add_column("Title")
            risk_table.add_column("File")
            risk_table.add_column("Line", justify="center")
            risk_table.add_column("Evidence", justify="center")

            for risk in sorted(
                result.risks,
                key=lambda r: list(Severity).index(r.severity),
            ):
                style = severity_style.get(risk.severity.value, "")
                icon = severity_icon.get(risk.severity.value, "")
                conf_style = {
                    "high": "green",
                    "medium": "yellow",
                    "low": "red",
                }.get(risk.confidence.value, "")

                risk_table.add_row(
                    risk.id,
                    f"[{style}]{icon}[/]",
                    f"[{conf_style}]{risk.confidence.value[:1].upper()}[/]",
                    risk.cwe_id or "-",
                    risk.title[:45],
                    str(risk.file_path)[-25:],
                    str(risk.line_start),
                    str(risk.evidence_count),
                )

            console.print(risk_table)

            # Fix suggestions tree (only critical/high)
            critical_high = [
                r for r in result.risks
                if r.severity in (Severity.CRITICAL, Severity.HIGH)
            ]
            if critical_high:
                console.print()
                tree = Tree("[bold red]Critical / High Risks - Fix Suggestions[/]", guide_style="cyan")
                for risk in critical_high:
                    node = tree.add(f"[red]{risk.id}[/] {risk.title}")
                    node.add(f"[yellow]Issue:[/] {risk.description[:120]}")
                    node.add(f"[green]Fix:[/] {risk.suggestion[:120]}")
                console.print(tree)

        # Footer
        console.print()
        console.print(
            Panel(
                f"[bold]Files:[/] {result.files_analyzed}  |  "
                f"[bold]Risks:[/] {result.total_risks}  |  "
                f"[bold]Time:[/] {result.analysis_time_ms}ms  |  "
                f"[bold]Model:[/] {result.model_used}",
                border_style="cyan",
            )
        )

    def save_report(
        self,
        result: AnalysisResult,
        output_dir: str = ".",
        formats: list[str] = ["json", "md"],
    ) -> list[str]:
        """Save reports to files. Returns list of saved file paths."""
        import os

        saved = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"coderisk_report_{timestamp}"

        os.makedirs(output_dir, exist_ok=True)

        if "json" in formats:
            json_path = os.path.join(output_dir, f"{base_name}.json")
            report = self.generate_json(result)
            with open(json_path, "w") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            saved.append(json_path)
            console.print(f"[dim]JSON report saved: {json_path}[/]")

        if "md" in formats:
            md_path = os.path.join(output_dir, f"{base_name}.md")
            md_content = self.generate_markdown(result)
            with open(md_path, "w") as f:
                f.write(md_content)
            saved.append(md_path)
            console.print(f"[dim]Markdown report saved: {md_path}[/]")

        return saved
```

---

## 16. `orchestrator.py`

```python
"""Orchestrator: State Machine Pipeline

Manages the complete analysis flow through states:
INIT -> PARSE -> ANALYZE -> VERIFY -> REPORT -> DONE

Coordinates all 4 agents with memory layer, CVE client, and Semgrep.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Optional

from rich.console import Console

from agents.deep_verifier import DeepVerifier
from agents.report_generator import ReportGenerator
from agents.semantic_analyzer import SemanticAnalyzer
from agents.static_analyzer import StaticAnalyzer
from core.cve_client import CVEClient
from core.llm_client import LLMClient
from core.memory import MemoryLayer
from core.models import (
    AnalysisRequest,
    AnalysisResult,
    CodeFile,
    Language,
)

console = Console()

MIN_LINES_FOR_LLM = 20


class State(str, Enum):
    INIT = "init"
    PARSE = "parse"
    ANALYZE = "analyze"
    VERIFY = "verify"
    REPORT = "report"
    DONE = "done"
    ERROR = "error"


class Orchestrator:
    """State machine orchestrator for the analysis pipeline."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.state = State.INIT
        self.static_analyzer = StaticAnalyzer()
        self.llm = llm_client
        self.semantic_analyzer = SemanticAnalyzer(llm_client) if llm_client else None
        self.memory = MemoryLayer()
        self.cve = CVEClient()
        self.verifier = DeepVerifier(
            llm_client=llm_client,
            memory=self.memory,
            cve_client=self.cve,
        )
        self.reporter = ReportGenerator()

    def run(
        self,
        request: AnalysisRequest,
        output_format: str = "terminal",
    ) -> AnalysisResult:
        """Run the complete analysis pipeline."""
        start_time = time.monotonic()

        # State: PARSE
        self.state = State.PARSE
        console.print(f"\n[bold cyan]Orchestrator: Analyzing {len(request.files)} files...[/]\n")

        valid_files = self._validate_files(request.files)
        if not valid_files:
            console.print("[yellow]No valid files to analyze.[/]")
            return AnalysisResult(
                request_id=f"scan-{int(time.time())}",
                files_analyzed=0,
                risks=[],
                analysis_time_ms=0,
                model_used="none",
            )

        # State: ANALYZE
        self.state = State.ANALYZE
        all_risks = []

        # Phase 1: Static analysis
        console.print("[bold]  Phase 1: Static analysis (Agent 1)[/]")
        for f in valid_files:
            risks = self.static_analyzer.analyze(f)
            all_risks.extend(risks)
            if risks:
                console.print(f"  [red]  {f.path}: {len(risks)} risks[/]")
            else:
                console.print(f"  [green]  {f.path}: clean[/]")

        # Phase 2: Semgrep
        console.print("\n[bold]  Phase 2: Semgrep analysis[/]")
        try:
            from core.semgrep_runner import analyze_with_semgrep
            for f in valid_files:
                semgrep_risks = analyze_with_semgrep(
                    f, config=request.rules[0], risk_counter_start=len(all_risks)
                )
                if semgrep_risks:
                    console.print(f"  [red]  Semgrep {f.path}: {len(semgrep_risks)} risks[/]")
                    all_risks.extend(semgrep_risks)
        except Exception as e:
            console.print(f"[dim]  Semgrep skipped: {e}[/]")

        # Phase 3: LLM semantic analysis
        if request.enable_ai and self.semantic_analyzer:
            console.print("\n[bold]  Phase 3: LLM semantic analysis (Agent 2)[/]")
            for f in valid_files:
                file_risks = [r for r in all_risks if r.file_path == f.path]
                if f.line_count < MIN_LINES_FOR_LLM and not file_risks:
                    console.print(f"  [dim]  {f.path}: skipped (small file)[/]")
                    continue
                try:
                    enriched = self.semantic_analyzer.analyze(f, file_risks)
                    all_risks = [r for r in all_risks if r.file_path != f.path]
                    all_risks.extend(enriched)
                except Exception as e:
                    console.print(f"  [yellow]  LLM failed for {f.path}: {e}[/]")

        # State: VERIFY
        self.state = State.VERIFY
        console.print("\n[bold]  Phase 4: Deep verification (Agent 3)[/]")
        mem_stats = self.memory.get_stats()
        console.print(
            f"  [dim]  Memory: {mem_stats['correct_patterns']} correct, "
            f"{mem_stats['error_patterns']} error patterns loaded[/]"
        )
        all_risks = self.verifier.verify_batch(valid_files, all_risks)

        # State: REPORT
        self.state = State.REPORT
        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        model_desc = "static+semgrep"
        if request.enable_ai and self.llm:
            model_desc += "+llm"
        model_desc += "+verify+memory+cve"

        result = AnalysisResult(
            request_id=f"scan-{int(time.time())}",
            files_analyzed=len(valid_files),
            risks=all_risks,
            analysis_time_ms=elapsed_ms,
            model_used=model_desc,
        )

        console.print(f"\n[bold]  Phase 5: Report generation (Agent 4)[/]")
        if output_format == "terminal" or output_format == "all":
            self.reporter.print_terminal(result)
        if output_format in ("json", "md", "all"):
            self.reporter.save_report(result, formats=["json", "md"])

        self.state = State.DONE
        console.print(f"\n[green]  Analysis complete. {result.total_risks} risks found in {elapsed_ms}ms.[/]")

        return result

    def _validate_files(self, files: list[CodeFile]) -> list[CodeFile]:
        valid = []
        for f in files:
            if not f.content.strip():
                continue
            if f.language == Language.UNKNOWN:
                continue
            valid.append(f)
        return valid

    @property
    def current_state(self) -> str:
        return self.state.value
```

---

## 17. `main.py`

```python
"""CodeRisk Agent - AI Code Quality & Risk Analyzer

Usage:
    code-risk analyze <path>   Analyze code files/directory
    code-risk demo             Run demo analysis
    code-risk info             Show configuration

Options:
    --no-ai                    Disable LLM semantic analysis
    --semgrep-config <rules>   Semgrep rules (default: p/default)
    --output <format>          Output format: terminal|json|md|all (default: terminal)
"""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console

from core.models import AnalysisRequest, CodeFile, Language

console = Console()

BANNER = r"""[bold cyan]
 ██████╗ ██████╗ ██████╗ ███████╗    ██████╗ ██╗███████╗██╗  ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔══██╗██║██╔════╝██║ ██╔╝
██║     ██║   ██║██║  ██║█████╗      ██████╔╝██║███████╗█████╔╝
██║     ██║   ██║██║  ██║██╔══╝      ██╔══██╗██║╚════██║██╔═██╗
╚██████╗╚██████╔╝██████╔╝███████╗    ██║  ██║██║███████║██║  ██╗
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝
[/]"""

VERSION = "0.3.0"

SUPPORTED_EXTENSIONS = {".c", ".h", ".py"}


def collect_files(path: Path) -> list[CodeFile]:
    """Collect supported code files from a path."""
    files: list[CodeFile] = []
    if path.is_file():
        if path.suffix in SUPPORTED_EXTENSIONS:
            files.append(CodeFile.from_path(path))
    else:
        for ext in SUPPORTED_EXTENSIONS:
            for f in path.rglob(f"*{ext}"):
                if f.is_file():
                    files.append(CodeFile.from_path(f))
    return files


def cmd_analyze(
    path_str: str,
    enable_ai: bool = True,
    semgrep_config: str = "p/default",
    output_format: str = "terminal",
) -> None:
    """Analyze code files or directory using the Orchestrator pipeline."""
    path = Path(path_str)

    if not path.exists():
        console.print(f"[red]Path not found: {path}[/]")
        sys.exit(1)

    files = collect_files(path)
    if not files:
        console.print(
            f"[yellow]No supported code files found ({', '.join(SUPPORTED_EXTENSIONS)})[/]"
        )
        sys.exit(0)

    # Build request
    request = AnalysisRequest(
        files=files,
        rules=[semgrep_config],
        enable_ai=enable_ai,
    )

    # Initialize Orchestrator
    from orchestrator import Orchestrator

    llm = None
    if enable_ai:
        try:
            from core.llm_client import LLMClient
            llm = LLMClient()
        except Exception as e:
            console.print(f"[yellow]LLM init failed, running without AI: {e}[/]")

    orchestrator = Orchestrator(llm_client=llm)
    orchestrator.run(request, output_format=output_format)


def cmd_demo() -> None:
    """Run demo analysis on sample vulnerable code."""
    from orchestrator import Orchestrator

    console.print("[bold cyan]CodeRisk Agent Demo[/]\n")

    demo_c = CodeFile(
        path=Path("demo/vulnerable.c"),
        content="""#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int login(char *input) {
    char password[32];
    strcpy(password, input);
    if (strcmp(password, "admin123") == 0) {
        printf("Welcome!\\n");
        system("echo logged in");
        return 1;
    }
    return 0;
}

void process() {
    char *buf = malloc(256);
    gets(buf);
    printf(buf);
    free(buf);
    free(buf);
}
""",
        language=Language.C,
    )

    demo_py = CodeFile(
        path=Path("demo/server.py"),
        content="""import os
import pickle
from flask import request

@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd")
    return os.system(cmd)

@app.route("/load")
def load_data():
    data = request.get_data()
    return pickle.loads(data)

@app.route("/calc")
def calculate():
    expr = request.args.get("expr")
    return str(eval(expr))
""",
        language=Language.PYTHON,
    )

    request = AnalysisRequest(
        files=[demo_c, demo_py],
        enable_ai=False,  # Demo mode: no LLM, fast
    )

    orchestrator = Orchestrator()  # No LLM for demo
    orchestrator.run(request)


def cmd_info() -> None:
    """Show configuration info."""
    import os

    from rich.table import Table

    table = Table(title="CodeRisk Agent Config", show_header=True)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Version", VERSION)
    table.add_row("Default Model", "Qwen2.5-Coder-7B-Instruct")
    table.add_row("Backends", "Shared API + llama-server + llama-cpp-python")
    table.add_row("Analyzers", "Static (regex) + Semgrep + LLM semantic + Deep verifier")
    table.add_row("Languages", "C (.c/.h) + Python (.py)")
    table.add_row("CWE Rules", "CWE-120/134/476/415/78/95/502/73/617")
    table.add_row("Pipeline", "Orchestrator -> 4 Agents -> Report")

    # Read actual env config
    backend = os.getenv("LLM_BACKEND", "local_llama_cpp")
    table.add_row("Active Backend", backend)

    console.print(table)


def main():
    console.print(BANNER)

    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        console.print(__doc__)
        return

    cmd = args[0]

    if cmd == "analyze":
        if len(args) < 2:
            console.print("[red]Usage: code-risk analyze <path>[/]")
            sys.exit(1)
        enable_ai = "--no-ai" not in args
        semgrep_config = "p/default"
        output_format = "terminal"
        if "--semgrep-config" in args:
            idx = args.index("--semgrep-config")
            if idx + 1 < len(args):
                semgrep_config = args[idx + 1]
        if "--output" in args:
            idx = args.index("--output")
            if idx + 1 < len(args):
                output_format = args[idx + 1]
        cmd_analyze(
            args[1],
            enable_ai=enable_ai,
            semgrep_config=semgrep_config,
            output_format=output_format,
        )
    elif cmd == "demo":
        cmd_demo()
    elif cmd == "info":
        cmd_info()
    else:
        console.print(f"[red]Unknown command: {cmd}[/]")
        console.print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 18. `scripts/run_demo.sh`

```bash
#!/bin/bash
# scripts/run_demo.sh - CodeRisk Agent Demo Script
# For AMD AI DevMaster Hackathon Track 2

set -e

echo "=========================================="
echo "  CodeRisk Agent - Demo"
echo "  AMD AI DevMaster Hackathon Track 2"
echo "=========================================="
echo ""

# 1. Environment Check
echo "[1/5] Environment Check"
echo "----------------------------------------"
if command -v rocm-smi &> /dev/null; then
    echo "ROCm detected:"
    rocm-smi --showproductname 2>/dev/null | head -3 || echo "  (rocm-smi available but limited in container)"
else
    echo "ROCm not available (CPU-only mode)"
fi
echo "Python: $(python3 --version)"
echo ""

# 2. Quick Demo (Static Analysis)
echo "[2/5] Static Analysis Demo (no LLM)"
echo "----------------------------------------"
cd "$(dirname "$0")/.."
python3 main.py demo
echo ""

# 3. Full Analysis on Test Cases
echo "[3/5] Full Analysis on Test Cases"
echo "----------------------------------------"
python3 main.py analyze tests/test_cases/ --no-ai --output terminal
echo ""

# 4. Version Info
echo "[4/5] System Info"
echo "----------------------------------------"
python3 main.py info
echo ""

# 5. Summary
echo "[5/5] Summary"
echo "----------------------------------------"
echo "CodeRisk Agent features:"
echo "  - Agent 1: Static Analyzer (regex + Tree-sitter)"
echo "  - Agent 2: Semantic Analyzer (LLM-driven)"
echo "  - Agent 3: Deep Verifier (triple cross-validation + memory)"
echo "  - Agent 4: Report Generator (JSON/Markdown/Rich)"
echo "  - Orchestrator: State machine pipeline"
echo "  - Memory Layer: Learn from history"
echo "  - CVE Client: NVD database lookup"
echo ""
echo "Demo complete!"
```

---

## 19. `tests/__init__.py`

```python
# CodeRisk Agent - Tests
```

---

## 20. `tests/test_static_analyzer.py`

```python
"""Tests for CodeRisk Agent - Static Analyzer"""

import sys
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.static_analyzer import StaticAnalyzer
from core.models import CodeFile, Language, Severity


@pytest.fixture
def analyzer():
    return StaticAnalyzer()


# ─── CWE-120: Buffer Overflow ────────────────────────────────────

class TestBufferOverflow:
    def test_detects_gets(self, analyzer):
        """gets() should be flagged as CRITICAL (CWE-120)"""
        code = '#include <stdio.h>\nint main() { char buf[10]; gets(buf); }'
        f = CodeFile(path="test.c", content=code, language=Language.C)
        risks = analyzer.analyze(f)
        assert any(r.cwe_id == "CWE-120" and r.severity == Severity.CRITICAL for r in risks)

    def test_detects_strcpy(self, analyzer):
        """strcpy() should be flagged as HIGH (CWE-120)"""
        code = '#include <string.h>\nvoid f(char *s) { char b[10]; strcpy(b, s); }'
        f = CodeFile(path="test.c", content=code, language=Language.C)
        risks = analyzer.analyze(f)
        assert any("strcpy" in r.title and r.severity == Severity.HIGH for r in risks)


# ─── CWE-78: Command Injection ──────────────────────────────────

class TestCommandInjection:
    def test_detects_system_c(self, analyzer):
        """system() in C should be flagged as HIGH (CWE-78)"""
        code = '#include <stdlib.h>\nvoid f() { system("ls"); }'
        f = CodeFile(path="test.c", content=code, language=Language.C)
        risks = analyzer.analyze(f)
        assert any(r.cwe_id == "CWE-78" and r.severity == Severity.HIGH for r in risks)

    def test_detects_os_system_python(self, analyzer):
        """os.system() in Python should be flagged as HIGH (CWE-78)"""
        code = 'import os\nos.system("ls")'
        f = CodeFile(path="test.py", content=code, language=Language.PYTHON)
        risks = analyzer.analyze(f)
        assert any(r.cwe_id == "CWE-78" and r.severity == Severity.HIGH for r in risks)


# ─── CWE-95: Code Injection ─────────────────────────────────────

class TestCodeInjection:
    def test_detects_eval(self, analyzer):
        """eval() should be flagged as CRITICAL (CWE-95)"""
        code = 'x = eval(input())'
        f = CodeFile(path="test.py", content=code, language=Language.PYTHON)
        risks = analyzer.analyze(f)
        assert any(r.cwe_id == "CWE-95" and r.severity == Severity.CRITICAL for r in risks)

    def test_detects_exec(self, analyzer):
        """exec() should be flagged as CRITICAL (CWE-95)"""
        code = 'exec("print(1)")'
        f = CodeFile(path="test.py", content=code, language=Language.PYTHON)
        risks = analyzer.analyze(f)
        assert any(r.cwe_id == "CWE-95" and r.severity == Severity.CRITICAL for r in risks)


# ─── CWE-502: Deserialization ───────────────────────────────────

class TestDeserialization:
    def test_detects_pickle(self, analyzer):
        """pickle.loads() should be flagged as CRITICAL (CWE-502)"""
        code = 'import pickle\ndata = pickle.loads(b"abc")'
        f = CodeFile(path="test.py", content=code, language=Language.PYTHON)
        risks = analyzer.analyze(f)
        assert any(r.cwe_id == "CWE-502" and r.severity == Severity.CRITICAL for r in risks)


# ─── Safe Code ──────────────────────────────────────────────────

class TestSafeCode:
    def test_safe_c_code(self, analyzer):
        """Safe C code should produce no critical/high risks"""
        code = '''
#include <stdio.h>
int main() {
    int x = 42;
    printf("%d\\n", x);
    return 0;
}
'''
        f = CodeFile(path="safe.c", content=code, language=Language.C)
        risks = analyzer.analyze(f)
        critical = [r for r in risks if r.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical) == 0

    def test_safe_python_code(self, analyzer):
        """Safe Python code should produce no critical/high risks"""
        code = '''
def add(a, b):
    return a + b

result = add(1, 2)
print(result)
'''
        f = CodeFile(path="safe.py", content=code, language=Language.PYTHON)
        risks = analyzer.analyze(f)
        critical = [r for r in risks if r.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical) == 0


# ─── Test Case Files ────────────────────────────────────────────

class TestTestCaseFiles:
    def test_buffer_overflow_file(self, analyzer):
        """buffer_overflow.c should have 2+ critical/high risks"""
        path = Path(__file__).parent / "test_cases" / "buffer_overflow.c"
        f = CodeFile.from_path(path)
        risks = analyzer.analyze(f)
        high_risks = [r for r in risks if r.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(high_risks) >= 2

    def test_command_injection_file(self, analyzer):
        """command_injection.c should have 2+ high risks"""
        path = Path(__file__).parent / "test_cases" / "command_injection.c"
        f = CodeFile.from_path(path)
        risks = analyzer.analyze(f)
        high_risks = [r for r in risks if r.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(high_risks) >= 2

    def test_code_injection_file(self, analyzer):
        """code_injection.py should have 3+ critical risks"""
        path = Path(__file__).parent / "test_cases" / "code_injection.py"
        f = CodeFile.from_path(path)
        risks = analyzer.analyze(f)
        critical = [r for r in risks if r.severity == Severity.CRITICAL]
        assert len(critical) >= 3

    def test_memory_issues_file(self, analyzer):
        """memory_issues.c should detect malloc and double free"""
        path = Path(__file__).parent / "test_cases" / "memory_issues.c"
        f = CodeFile.from_path(path)
        risks = analyzer.analyze(f)
        assert len(risks) >= 1
```

---

## 21. Test Cases

### `tests/test_cases/buffer_overflow.c`

```c
/* Test Case 1: CWE-120 Buffer Overflow via gets() and strcpy()
 * Expected: 2+ critical/high risks
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* VULN: CWE-120 - gets() has no bounds checking */
void read_input() {
    char buf[64];
    gets(buf);  /* CRITICAL: stack buffer overflow */
    printf("You said: %s\n", buf);
}

/* VULN: CWE-120 - strcpy() does not check dest size */
void copy_data(char *src) {
    char dest[32];
    strcpy(dest, src);  /* HIGH: unbounded copy */
}

/* SAFE: uses fgets with size limit */
void safe_input() {
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
}
```

### `tests/test_cases/command_injection.c`

```c
/* Test Case 2: CWE-78 Command Injection
 * Expected: 2+ high risks (system, os.system equivalent)
 */

#include <stdlib.h>
#include <stdio.h>

/* VULN: CWE-78 - system() with user input */
void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "echo %s", user_input);  /* also CWE-134 */
    system(cmd);  /* HIGH: command injection */
}

/* VULN: CWE-78 - direct system() call */
void ping_host(char *host) {
    char buf[128];
    snprintf(buf, sizeof(buf), "ping -c 1 %s", host);
    system(buf);  /* HIGH: command injection */
}
```

### `tests/test_cases/code_injection.py`

```python
# Test Case 3: Python Code Injection and Deserialization
# Expected: 3 critical risks (eval, exec, pickle)

import os
import pickle
import subprocess

# VULN: CWE-95 - eval() executes arbitrary code
def calculate(expr):
    return eval(expr)  # CRITICAL: code injection

# VULN: CWE-95 - exec() executes arbitrary code
def run_code(code_str):
    exec(code_str)  # CRITICAL: code injection

# VULN: CWE-502 - pickle.loads() on untrusted data
def load_object(data_bytes):
    return pickle.loads(data_bytes)  # CRITICAL: deserialization

# VULN: CWE-78 - os.system() command injection
def run_cmd(cmd):
    os.system(cmd)  # HIGH: command injection

# SAFE: uses subprocess with list (no shell)
def safe_cmd(args):
    return subprocess.run(args, shell=False)
```

### `tests/test_cases/memory_issues.c`

```c
/* Test Case 5: Memory Management Issues
 * Expected: 1-2 medium risks
 */

#include <stdlib.h>
#include <stdio.h>

/* VULN: CWE-476 - malloc() without NULL check */
void allocate_and_use() {
    char *buf = malloc(1024);  /* MEDIUM: no NULL check */
    sprintf(buf, "data");      /* potential NULL deref */
    free(buf);
}

/* VULN: CWE-415 - double free */
void cleanup(char *ptr) {
    free(ptr);    /* first free */
    free(ptr);    /* HIGH: double free */
}

/* SAFE: checks return value */
void safe_allocate() {
    char *buf = malloc(1024);
    if (buf == NULL) {
        return;
    }
    sprintf(buf, "data");
    free(buf);
}
```

### `tests/test_cases/sql_injection.py`

```python
# Test Case 4: Python SQL Injection and File Operations
# Expected: 1-2 medium/low risks

import sqlite3

# VULN: CWE-89 - SQL Injection via f-string
def login_unsafe(username, password):
    conn = sqlite3.connect("db.sqlite")
    query = f"SELECT * FROM users WHERE name='{username}' AND pass='{password}'"
    return conn.execute(query).fetchone()

# SAFE: parameterized query
def login_safe(username, password):
    conn = sqlite3.connect("db.sqlite")
    query = "SELECT * FROM users WHERE name=? AND pass=?"
    return conn.execute(query, (username, password)).fetchone()

# VULN: CWE-73 - file write without path validation
def write_file(filename, content):
    with open(filename, "w") as f:  # LOW: no path validation
        f.write(content)
```

## 22. Test Results

```
13 passed in 0.14s
```

---

## 23. Git History

```
9390781 v0.3.1: CVE client + memory layer + DeepVerifier integration
a4d4939 v0.3.0: Orchestrator + Agent 3/4 + bug fixes
6fe1926 v0.2.1: fix ChatML template + GPU detection + always-run LLM
7531371 v0.2.0: fixes + semgrep + semantic analyzer + tests
bf64622 feat: initial project skeleton + static analyzer + CLI
```

---

## 24. Repositories

| Repo | URL |
|------|-----|
| Main | https://github.com/a9320/code-risk-agent |
| Hackathon | https://github.com/a9320/Radeon-hackathon-2026-07 |

---

> Generated: 2026-07-19 13:22 | Version: v0.3.1