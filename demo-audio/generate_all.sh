#!/bin/bash
# Generate all demo voiceover audio files using edge-tts
# Voice: zh-CN-YunxiNeural (阳光男声)
OUTDIR="$(dirname "$0")"

edge-tts --voice zh-CN-YunxiNeural --text "2024年3月29日，微软工程师Andres Freund在Openwall安全邮件列表上发布了这条震惊全球的消息。他在调试SSH登录延迟时，偶然发现了XZ Utils中被植入的后门。" --write-media "$OUTDIR/scene0a-openwall.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "这个漏洞被分配了CVE-2024-3094，CVSS评分是满分10.0。这意味着它是理论上最危险的安全漏洞。" --write-media "$OUTDIR/scene0b-cve.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "消息一出，全球安全社区迅速响应。几乎所有主流Linux发行版都紧急发布了安全公告。" --write-media "$OUTDIR/scene0c-hackernews.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "一个命令，开始分析。" --write-media "$OUTDIR/scene0d-transition.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "这是测试目录，里面有我们准备好的C和Python漏洞样本。一行命令，分析开始。" --write-media "$OUTDIR/scene1a-start.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "Orchestrator启动，开始调度四个Agent。" --write-media "$OUTDIR/scene1b-orchestrator.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "Phase 1，静态分析，快速扫描已知模式。Phase 2，Semgrep加污点分析，并行执行。Phase 3，LLM语义分析，真正的代码理解。Phase 4，深度验证，三重交叉验证。" --write-media "$OUTDIR/scene1c-phases.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "分析完成。25个风险检出，覆盖C和Python文件。我们来看具体结果。" --write-media "$OUTDIR/scene1d-done.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "Agent 1 发现了这里的 strcpy 调用。但如果只到这里，和 Semgrep 没有区别。" --write-media "$OUTDIR/scene2a-strcpy.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "这是 Semgrep 的结果：strcpy 被一律标记为高风险。它是按固定规则报警的，不理解上下文。" --write-media "$OUTDIR/scene2b-semgrep.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "但我们的Agent会进一步分析上下文。这个 src 其实是一个固定字符串，根本不来自用户输入。所以它自动把这条告警降级了，帮开发者省掉一次误报排查。" --write-media "$OUTDIR/scene2c-downgrade.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "同时，Agent 3 的自省循环发现了一个 Semgrep 完全遗漏的问题：malloc 返回值没有做 NULL 检查。内存分配失败时程序直接崩溃。" --write-media "$OUTDIR/scene2d-malloc.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "每个风险都附带 CWE 分类、CVE 关联和具体修复建议。看这条：strcpy 缓冲区溢出，修复方案是 strncpy 加边界检查，开发者可以直接复制使用。" --write-media "$OUTDIR/scene2e-fix.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "系统还有记忆能力。第一次扫描建立模式库，第二次遇到类似代码时直接召回，检测更快，误报更少。越用越准。" --write-media "$OUTDIR/scene3-memory.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "这是刚才分析的性能数据。全部在本地 AMD GPU 上完成。" --write-media "$OUTDIR/scene4a-gpu.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "105个token每秒，意味着什么？几百行代码，几秒钟出结果。而且全程在您自己的GPU上完成，代码从不上传云端。" --write-media "$OUTDIR/scene4b-speed.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "48GB 显存，32B 参数模型，GPU 利用率稳定。这就是本地 AI 安全审计的实力。" --write-media "$OUTDIR/scene4c-vram.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "这些数据都记录在项目的 ROCm 优化文档中，可复现、可验证。" --write-media "$OUTDIR/scene4d-docs.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "CodeRisk Agent 已完全开源。支持 JSON、Markdown、SARIF 2.1.0 多种报告格式，可集成到 CI/CD 流程。" --write-media "$OUTDIR/scene5a-opensource.mp3"

edge-tts --voice zh-CN-YunxiNeural --text "四个 AI Agent，编排流水线，记忆学习，实时 CVE 验证，全部运行在本地 AMD GPU 上。谢谢观看。" --write-media "$OUTDIR/scene5b-end.mp3"

echo "=== All audio files generated ==="
ls -lh "$OUTDIR"/*.mp3
