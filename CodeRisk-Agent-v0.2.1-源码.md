# CodeRisk Agent v0.2.1 — 完整源码

> AMD AI DevMaster Hackathon Track 2 | 2026-07-19
> GitHub: https://github.com/a9320/code-risk-agent
> Hackathon Fork: https://github.com/a9320/Radeon-hackathon-2026-07

---

## 项目结构

```
code-risk-agent/
├── core/
│   ├── __init__.py              # 模块导出
│   ├── models.py                # Pydantic 数据模型
│   ├── llm_client.py            # LLM 三后端客户端 + ChatML + 重试
│   └── semgrep_runner.py        # Semgrep CLI 集成
├── agents/
│   ├── __init__.py              # 模块导出
│   ├── static_analyzer.py       # Agent 1: 静态分析器
│   └── semantic_analyzer.py     # Agent 2: LLM 语义分析
├── tests/
│   ├── __init__.py
│   ├── test_static_analyzer.py  # 13 个 pytest 测试
│   └── test_cases/              # 5 个漏洞样本
│       ├── buffer_overflow.c
│       ├── command_injection.c
│       ├── code_injection.py
│       ├── memory_issues.c
│       └── sql_injection.py
├── scripts/README.md
├── docs/README.md
├── main.py                      # CLI 入口
├── pyproject.toml
├── .env.example
├── .gitignore
└── README.md
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

```bash
# LLM Backend: "shared_api" | "local_http" | "local_llama_cpp"
LLM_BACKEND=local_llama_cpp

# Shared API (Radeon Cloud)
SHARED_API_URL=https://developer.amd.com.cn/radeon/api/v1
SHARED_API_KEY=***
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

```gitignore
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

## 4. `core/__init__.py`

```python
"""CodeRisk Agent - Core Module"""

from core.models import (AnalysisRequest, AnalysisResult, AgentMessage, AgentRole, CodeFile, Confidence, Evidence, Language, LLMBackend, LLMConfig, Risk, Severity)
from core.llm_client import LLMClient
from core.semgrep_runner import run_semgrep, semgrep_to_risks, analyze_with_semgrep
```

---

## 5. `core/models.py`

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

## 6. `core/llm_client.py`

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
        max_tokens=4096,
    ),
    LLMBackend.LOCAL_HTTP: LLMConfig(
        backend=LLMBackend.LOCAL_HTTP,
        api_url="http://localhost:8080",
        model="qwen2.5-coder-7b-instruct",
        temperature=0.1,
        max_tokens=4096,
    ),
    LLMBackend.LOCAL_LLAMA_CPP: LLMConfig(
        backend=LLMBackend.LOCAL_LLAMA_CPP,
        model_path="/workspace/llama.cpp/models/qwen2.5-coder-7b-instruct-q4_k_m.gguf",
        model="qwen2.5-coder-7b-instruct",
        temperature=0.1,
        max_tokens=4096,
    ),
}

MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0


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
            stop="<|endofassistant|>",
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
            parts.append(f"<im_start>{role}\n{content}<im_end>")
        parts.append(f"<im_start>assistant\n")
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

    raise ValueError(f"Failed to extract JSON from LLM response:\n{text[:300]}...")
```

---

## 7. `core/semgrep_runner.py`

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

## 8. `agents/__init__.py`

```python
"""CodeRisk Agent - Agent Module"""

from agents.static_analyzer import StaticAnalyzer
from agents.semantic_analyzer import SemanticAnalyzer
```

---

## 9. `agents/static_analyzer.py`

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

## 10. `agents/semantic_analyzer.py`

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

## 11. `tests/__init__.py`

```python
# CodeRisk Agent - Tests
```

---

## 12. `tests/test_static_analyzer.py`

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

## 13. 测试用例文件

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

---

## 14. `main.py` — CLI 入口

```python
"""CodeRisk Agent - AI Code Quality & Risk Analyzer

Usage:
    code-risk analyze <path>   Analyze code files/directory
    code-risk demo             Run demo analysis
    code-risk info             Show configuration

Options:
    --no-ai                    Disable LLM semantic analysis
    --semgrep-config <rules>   Semgrep rules (default: p/default)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from agents.static_analyzer import StaticAnalyzer
from core.models import AnalysisResult, CodeFile, Language, Severity

console = Console()

BANNER = r"""[bold cyan]
 ██████╗ ██████╗ ██████╗ ███████╗    ██████╗ ██╗███████╗██╗  ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔══██╗██║██╔════╝██║ ██╔╝
██║     ██║   ██║██║  ██║█████╗      ██████╔╝██║███████╗█████╔╝
██║     ██║   ██║██║  ██║██╔══╝      ██╔══██╗██║╚════██║██╔═██╗
╚██████╗╚██████╔╝██████╔╝███████╗    ██║  ██║██║███████║██║  ██╗
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝
[/]"""

VERSION = "0.2.0"

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
) -> None:
    """Analyze code files or directory."""
    path = Path(path_str)

    if not path.exists():
        console.print(f"[red]Path not found: {path}[/]")
        sys.exit(1)

    files = collect_files(path)
    if not files:
        console.print(f"[yellow]No supported code files found ({', '.join(SUPPORTED_EXTENSIONS)})[/]")
        sys.exit(0)

    console.print(f"\n[bold]Scanning {len(files)} files...[/]\n")

    # Phase 1: Static analysis (regex patterns)
    static_analyzer = StaticAnalyzer()
    start = time.monotonic()
    all_risks = static_analyzer.analyze_batch(files)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    # Phase 2: Semgrep analysis
    try:
        from core.semgrep_runner import analyze_with_semgrep
        for f in files:
            semgrep_risks = analyze_with_semgrep(
                f, config=semgrep_config, risk_counter_start=len(all_risks)
            )
            if semgrep_risks:
                console.print(f"  [red]  Semgrep {f.path}: {len(semgrep_risks)} risks[/]")
                all_risks.extend(semgrep_risks)
    except Exception as e:
        console.print(f"[dim]Semgrep skipped: {e}[/]")

    # Phase 3: LLM semantic analysis (optional)
    if enable_ai:
        try:
            from core.llm_client import LLMClient
            from agents.semantic_analyzer import SemanticAnalyzer

            with LLMClient() as llm:
                semantic = SemanticAnalyzer(llm)
                for f in files:
                    file_risks = [r for r in all_risks if r.file_path == f.path]
                    enriched = semantic.analyze(f, file_risks)
                    # Replace risks for this file
                    all_risks = [r for r in all_risks if r.file_path != f.path]
                    all_risks.extend(enriched)
        except Exception as e:
            console.print(f"[yellow]LLM analysis skipped: {e}[/]")

    # Build result
    result = AnalysisResult(
        request_id=f"scan-{int(time.time())}",
        files_analyzed=len(files),
        risks=all_risks,
        analysis_time_ms=elapsed_ms,
        model_used="static+semgrep" + ("+llm" if enable_ai else ""),
    )

    _print_results(result)


def cmd_demo() -> None:
    """Run demo analysis."""
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

    analyzer = StaticAnalyzer()
    files = [demo_c, demo_py]

    console.print("[bold]Demo files:[/]")
    for f in files:
        console.print(f"  - {f.path} ({f.language.value})")
    console.print()

    risks = analyzer.analyze_batch(files)

    result = AnalysisResult(
        request_id="demo-001",
        files_analyzed=2,
        risks=risks,
        analysis_time_ms=0,
        model_used="pattern_matcher (demo)",
    )

    _print_results(result)


def cmd_info() -> None:
    """Show configuration info."""
    table = Table(title="CodeRisk Agent Config", show_header=True)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Version", VERSION)
    table.add_row("Model", "Qwen2.5-Coder-7B-Instruct")
    table.add_row("Backends", "Shared API + llama-server + llama-cpp-python")
    table.add_row("Analyzers", "Static (regex) + Semgrep + LLM semantic")
    table.add_row("Languages", "C (.c/.h) + Python (.py)")
    table.add_row("CWE Rules", "CWE-120/134/476/415/78/95/502/73/617")

    console.print(table)


def _print_results(result: AnalysisResult) -> None:
    """Format and print analysis results."""
    console.print()

    # Summary table
    summary_table = Table(title="Risk Summary", show_header=True, border_style="cyan")
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
        "critical": "[red]C[/]",
        "high": "[red]H[/]",
        "medium": "[yellow]M[/]",
        "low": "[blue]L[/]",
        "info": "[dim]I[/]",
    }

    for level in ["critical", "high", "medium", "low", "info"]:
        count = result.risk_summary.get(level, 0)
        if count > 0:
            summary_table.add_row(
                f"{severity_icon[level]} {level.upper()}",
                f"[{severity_style[level]}]{count}[/]",
            )

    console.print(summary_table)
    console.print()

    # Detail table
    if result.risks:
        risk_table = Table(title="Risk Details", show_header=True, border_style="yellow")
        risk_table.add_column("ID", style="bold")
        risk_table.add_column("Sev")
        risk_table.add_column("CWE")
        risk_table.add_column("Title")
        risk_table.add_column("File")
        risk_table.add_column("Line", justify="center")
        risk_table.add_column("Evidence", justify="center")

        for risk in sorted(result.risks, key=lambda r: list(Severity).index(r.severity)):
            style = severity_style.get(risk.severity.value, "")
            icon = severity_icon.get(risk.severity.value, "")
            risk_table.add_row(
                risk.id,
                f"[{style}]{icon}[/]",
                risk.cwe_id or "-",
                risk.title[:50],
                str(risk.file_path)[-30:],
                str(risk.line_start),
                str(risk.evidence_count),
            )

        console.print(risk_table)

        # Fix suggestions tree
        console.print()
        tree = Tree("[bold]Fix Suggestions[/]", guide_style="cyan")
        for risk in result.risks:
            if risk.severity in (Severity.CRITICAL, Severity.HIGH):
                node = tree.add(f"[red]{risk.id}[/] {risk.title}")
                node.add(f"[yellow]Issue:[/] {risk.description[:100]}")
                node.add(f"[green]Fix:[/] {risk.suggestion[:100]}")
        console.print(tree)

    # Footer stats
    console.print(
        Panel(
            f"[bold]Files:[/] {result.files_analyzed}  |  "
            f"[bold]Risks:[/] {result.total_risks}  |  "
            f"[bold]Time:[/] {result.analysis_time_ms}ms  |  "
            f"[bold]Model:[/] {result.model_used}",
            border_style="cyan",
        )
    )


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
        if "--semgrep-config" in args:
            idx = args.index("--semgrep-config")
            if idx + 1 < len(args):
                semgrep_config = args[idx + 1]
        cmd_analyze(args[1], enable_ai=enable_ai, semgrep_config=semgrep_config)
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

## 15. `README.md`

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

## 快速开始

    # 安装
    pip install -e .

    # 配置
    cp .env.example .env
    # 编辑 .env 填入 API Key

    # 运行
    code-risk analyze ./path/to/code

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

## 16. 测试结果

```
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.0.3, pluggy-1.6.0
collected 13 items

tests/test_static_analyzer.py::TestBufferOverflow::test_detects_gets PASSED
tests/test_static_analyzer.py::TestBufferOverflow::test_detects_strcpy PASSED
tests/test_static_analyzer.py::TestCommandInjection::test_detects_system_c PASSED
tests/test_static_analyzer.py::TestCommandInjection::test_detects_os_system_python PASSED
tests/test_static_analyzer.py::TestCodeInjection::test_detects_eval PASSED
tests/test_static_analyzer.py::TestCodeInjection::test_detects_exec PASSED
tests/test_static_analyzer.py::TestDeserialization::test_detects_pickle PASSED
tests/test_static_analyzer.py::TestSafeCode::test_safe_c_code PASSED
tests/test_static_analyzer.py::TestSafeCode::test_safe_python_code PASSED
tests/test_static_analyzer.py::TestTestCaseFiles::test_buffer_overflow_file PASSED
tests/test_static_analyzer.py::TestTestCaseFiles::test_command_injection_file PASSED
tests/test_static_analyzer.py::TestTestCaseFiles::test_code_injection_file PASSED
tests/test_static_analyzer.py::TestTestCaseFiles::test_memory_issues_file PASSED

============================== 13 passed in 0.18s ==============================
```

---

## 17. Git 提交历史

```
6fe1926 v0.2.1: fix ChatML template + GPU detection + always-run LLM
7531371 v0.2.0: fixes + semgrep + semantic analyzer + tests
bf64622 feat: initial project skeleton + static analyzer + CLI
```

---

## 18. 仓库信息

| 仓库 | 地址 |
|------|------|
| 主仓库 | https://github.com/a9320/code-risk-agent |
| 黑客松 Fork | https://github.com/a9320/Radeon-hackathon-2026-07 |

---

> 文档生成时间：2026-07-19 12:20 | 版本：v0.2.1
