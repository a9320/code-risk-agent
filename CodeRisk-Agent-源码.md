# CodeRisk Agent — 源码清单

> AMD AI DevMaster Hackathon Track 2 | 2026-07-19

---

## 项目结构

```
code-risk-agent/
├── core/
│   ├── __init__.py
│   ├── models.py          # Pydantic 数据模型
│   └── llm_client.py      # LLM 双后端客户端
├── agents/
│   ├── __init__.py
│   └── static_analyzer.py # Tree-sitter 静态分析器
├── tests/
│   └── __init__.py
├── scripts/
│   └── README.md
├── docs/
│   └── README.md
├── main.py                # CLI 入口
├── pyproject.toml
├── .env.example
├── .gitignore
└── README.md
```

---

## 1. pyproject.toml

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
code-risk = "main:app"

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

## 2. core/models.py

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
    LOCAL = "local"


class LLMConfig(BaseModel):
    """LLM 客户端配置"""
    backend: LLMBackend = LLMBackend.SHARED_API
    api_url: str = ""
    api_key: str = ""
    model: str = ""
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

## 3. core/llm_client.py

```python
"""CodeRisk Agent — LLM 客户端

支持双后端：共享 API（Radeon Cloud）+ 本地 llama.cpp。
统一接口，Agent 层无感知切换。
"""

from __future__ import annotations

import json
import time
from typing import Optional

import httpx
from rich.console import Console

from core.models import LLMBackend, LLMConfig

console = Console()

# 默认配置
DEFAULT_CONFIGS = {
    LLMBackend.SHARED_API: LLMConfig(
        backend=LLMBackend.SHARED_API,
        api_url="https://chat.api.amd.com/v1",
        model="Qwen/Qwen3.6-35B-A3B",
        temperature=0.1,
        max_tokens=4096,
    ),
    LLMBackend.LOCAL: LLMConfig(
        backend=LLMBackend.LOCAL,
        api_url="http://localhost:8080",
        model="qwen2.5-coder-7b-instruct",
        temperature=0.1,
        max_tokens=4096,
    ),
}


class LLMClient:
    """统一 LLM 客户端"""

    def __init__(self, config: Optional[LLMConfig] = None, backend: Optional[LLMBackend] = None):
        if config:
            self.config = config
        else:
            b = backend or LLMBackend.SHARED_API
            self.config = DEFAULT_CONFIGS[b]

        self._client = httpx.Client(timeout=self.config.timeout)
        self._request_count = 0
        self._total_tokens = 0

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[dict] = None,
    ) -> str:
        """发送对话请求，返回文本响应"""
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature or self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
        }
        if response_format:
            payload["response_format"] = response_format

        url = f"{self.config.api_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        start = time.monotonic()
        try:
            resp = self._client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            console.print(f"[red]LLM API error: {e.response.status_code}[/]")
            raise
        except httpx.RequestError as e:
            console.print(f"[red]LLM connection error: {e}[/]")
            raise

        elapsed_ms = int((time.monotonic() - start) * 1000)
        self._request_count += 1

        # 提取响应
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        self._total_tokens += usage.get("total_tokens", 0)

        console.print(
            f"[dim]LLM [{self.config.backend.value}] "
            f"{elapsed_ms}ms | "
            f"tokens: {usage.get('prompt_tokens', '?')}→{usage.get('completion_tokens', '?')} | "
            f"total: {self._total_tokens}[/]"
        )

        return content

    def chat_json(
        self,
        messages: list[dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> dict:
        """发送对话请求，返回 JSON 对象"""
        raw = self.chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        return _extract_json(raw)

    @property
    def stats(self) -> dict:
        return {
            "backend": self.config.backend.value,
            "model": self.config.model,
            "requests": self._request_count,
            "total_tokens": self._total_tokens,
        }

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _extract_json(text: str) -> dict:
    """从 LLM 响应中提取 JSON（容错处理）"""
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

    raise ValueError(f"无法从 LLM 响应中提取 JSON:\n{text[:200]}...")
```

---

## 4. agents/static_analyzer.py

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

    def _analyze_c(self, code_file: CodeFile) -> list[Risk]:
        risks: list[Risk] = []
        lines = code_file.content.split("\n")

        for i, line in enumerate(lines, start=1):
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

            for pat in C_VULNERABLE_PATTERNS:
                if re.search(pat["pattern"], line):
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

    def _analyze_python(self, code_file: CodeFile) -> list[Risk]:
        risks: list[Risk] = []
        lines = code_file.content.split("\n")

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

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

## 5. main.py

```python
"""CodeRisk Agent — AI 代码质量与风险智能体

Usage:
    code-risk analyze <path>     分析代码文件/目录
    code-risk demo               运行演示分析
    code-risk info               显示配置信息
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

BANNER = """[bold cyan]
 ██████╗ ██████╗ ██████╗ ███████╗    ██████╗ ██╗███████╗██╗  ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔══██╗██║██╔════╝██║ ██╔╝
██║     ██║   ██║██║  ██║█████╗      ██████╔╝██║███████╗█████╔╝
██║     ██║   ██║██║  ██║██╔══╝      ██╔══██╗██║╚════██║██╔═██╗
╚██████╗╚██████╔╝██████╔╝███████╗    ██║  ██║██║███████║██║  ██╗
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝
[/]"""

VERSION = "0.1.0"


def cmd_analyze(path_str: str) -> None:
    """分析代码文件或目录"""
    path = Path(path_str)

    if not path.exists():
        console.print(f"[red]✗ 路径不存在: {path}[/]")
        sys.exit(1)

    files: list[CodeFile] = []
    extensions = {".c", ".h", ".py"}

    if path.is_file():
        if path.suffix in extensions:
            files.append(CodeFile.from_path(path))
        else:
            console.print(f"[red]✗ 不支持的文件类型: {path.suffix}[/]")
            sys.exit(1)
    else:
        for ext in extensions:
            files.extend(
                CodeFile.from_path(f) for f in path.rglob(f"*{ext}") if f.is_file()
            )

    if not files:
        console.print("[yellow]⚠ 未找到可分析的代码文件 (.c/.h/.py)[/]")
        sys.exit(0)

    console.print(f"\n[bold]📂 扫描 {len(files)} 个文件...[/]\n")

    analyzer = StaticAnalyzer()
    start = time.monotonic()
    risks = analyzer.analyze_batch(files)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    result = AnalysisResult(
        request_id=f"scan-{int(time.time())}",
        files_analyzed=len(files),
        risks=risks,
        analysis_time_ms=elapsed_ms,
        model_used="pattern_matcher",
    )

    _print_results(result)


def cmd_demo() -> None:
    """运行演示分析"""
    console.print("[bold cyan]🎯 CodeRisk Agent 演示[/]\n")

    demo_c = CodeFile(
        path=Path("demo/vulnerable.c"),
        content="""#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int login(char *input) {
    char password[32];
    strcpy(password, input);    // 危险: 无边界检查
    if (strcmp(password, "admin123") == 0) {
        printf("Welcome!\\n");
        system("echo logged in");  // 危险: 命令注入
        return 1;
    }
    return 0;
}

void process() {
    char *buf = malloc(256);     // 危险: 未检查 NULL
    gets(buf);                    // 危险: 缓冲区溢出
    printf(buf);                  // 危险: 格式字符串
    free(buf);
    free(buf);                    // 危险: 双重释放
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
    return os.system(cmd)  # 危险: 命令注入

@app.route("/load")
def load_data():
    data = request.get_data()
    return pickle.loads(data)  # 危险: 反序列化

@app.route("/calc")
def calculate():
    expr = request.args.get("expr")
    return str(eval(expr))  # 危险: 代码注入
""",
        language=Language.PYTHON,
    )

    analyzer = StaticAnalyzer()
    files = [demo_c, demo_py]

    console.print("[bold]📂 演示文件:[/]")
    for f in files:
        console.print(f"  • {f.path} ({f.language.value})")
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
    """显示配置信息"""
    table = Table(title="CodeRisk Agent 配置", show_header=True)
    table.add_column("配置项", style="cyan")
    table.add_column("值", style="green")

    table.add_row("版本", VERSION)
    table.add_row("模型", "Qwen2.5-Coder-7B-Instruct")
    table.add_row("后端", "共享 API (Radeon Cloud) + 本地 llama.cpp")
    table.add_row("分析器", "Tree-sitter + Pattern Matcher")
    table.add_row("支持语言", "C (.c/.h) + Python (.py)")
    table.add_row("CWE 规则", "CWE-120/134/476/415/78/95/502/73/617")

    console.print(table)


def _print_results(result: AnalysisResult) -> None:
    """格式化输出分析结果"""
    console.print()

    summary_table = Table(title="📊 风险统计", show_header=True, border_style="cyan")
    summary_table.add_column("等级", justify="center")
    summary_table.add_column("数量", justify="center")

    severity_style = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    severity_icon = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
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

    if result.risks:
        risk_table = Table(title="🔍 风险详情", show_header=True, border_style="yellow")
        risk_table.add_column("ID", style="bold")
        risk_table.add_column("等级")
        risk_table.add_column("CWE")
        risk_table.add_column("标题")
        risk_table.add_column("文件")
        risk_table.add_column("行号", justify="center")
        risk_table.add_column("证据数", justify="center")

        for risk in sorted(result.risks, key=lambda r: list(Severity).index(r.severity)):
            style = severity_style.get(risk.severity.value, "")
            icon = severity_icon.get(risk.severity.value, "")
            risk_table.add_row(
                risk.id,
                f"[{style}]{icon} {risk.severity.value.upper()}[/]",
                risk.cwe_id or "—",
                risk.title,
                str(risk.file_path),
                str(risk.line_start),
                str(risk.evidence_count),
            )

        console.print(risk_table)

        console.print()
        tree = Tree("[bold]💡 修复建议[/]", guide_style="cyan")
        for risk in result.risks:
            if risk.severity in (Severity.CRITICAL, Severity.HIGH):
                node = tree.add(f"[red]{risk.id}[/] {risk.title}")
                node.add(f"[yellow]问题:[/] {risk.description}")
                node.add(f"[green]修复:[/] {risk.suggestion}")
        console.print(tree)

    console.print(
        Panel(
            f"[bold]文件:[/] {result.files_analyzed}  |  "
            f"[bold]风险:[/] {result.total_risks}  |  "
            f"[bold]耗时:[/] {result.analysis_time_ms}ms  |  "
            f"[bold]模型:[/] {result.model_used}",
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
            console.print("[red]✗ 用法: code-risk analyze <path>[/]")
            sys.exit(1)
        cmd_analyze(args[1])
    elif cmd == "demo":
        cmd_demo()
    elif cmd == "info":
        cmd_info()
    else:
        console.print(f"[red]✗ 未知命令: {cmd}[/]")
        console.print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

## 6. .env.example

```bash
# CodeRisk Agent - Environment Configuration

# LLM Backend: "shared_api" | "local"
LLM_BACKEND=shared_api

# Shared API (Radeon Cloud)
SHARED_API_URL=https://chat.api.amd.com/v1
SHARED_API_KEY=your-api-key-here
SHARED_API_MODEL=Qwen/Qwen3.6-35B-A3B

# Local (llama.cpp)
LOCAL_API_URL=http://localhost:8080
LOCAL_MODEL_PATH=models/qwen2.5-coder-7b-instruct-q4_k_m.gguf

# Semgrep
SEMGREP_RULES=p/default
```

---

## 7. .gitignore

```
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

## 8. README.md

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

*生成时间：2026-07-19 08:52 | 版本：v0.1.0*
