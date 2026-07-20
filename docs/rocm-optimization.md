# ROCm Optimization Documentation

> CodeRisk Agent - AMD AI DevMaster Hackathon Track 2

---

## Current Environment Status

| Item | Status | Notes |
|------|--------|-------|
| GPU | RX 7900 XTX (gfx1100) | Radeon Cloud container |
| ROCm | 7.2.4 | Fully configured |
| rocm-smi | Available | Can monitor GPU status |
| HIP Backend | ✅ Available | GGML_HIP=ON flag |
| CPU Inference | 6.8 t/s | Fallback mode |
| Shared API | Qwen3.6-35B-A3B | Available for testing |

### HIP Backend Status

Initial attempts with `GGML_HIPBLAS=ON` (the 2024-2025 flag) failed.
The correct flag for 2026 is `GGML_HIP=ON`. After using the correct flag,
HIP compiled successfully and GPU inference is fully operational:

- Token generation: 105 t/s (measured on Radeon Cloud, RX 7900 XTX)
- Prompt processing: 628 t/s
- VRAM usage: 24% (~5 GB)

---

## Optimization Strategy (3 Layers)

### Layer 1: Model Optimization

| Optimization | Implementation | Expected Speedup |
|--------------|---------------|------------------|
| Q4_K_M Quantization | GGUF format, 4-bit | ~5GB VRAM, 110-114 t/s |
| Flash Attention | llama.cpp `-fa 1` | 30-50% latency reduction |
| KV Cache | llama.cpp `-c 4096` | Stable long-context inference |

### Layer 2: Task-Level Optimization

| Agent | Compute | Rationale |
|-------|---------|-----------|
| Agent 1 (Static) | CPU only | Regex + Tree-sitter, no GPU needed |
| Agent 2 (Semantic) | GPU | LLM inference, benefits from GPU |
| Agent 3 (Verifier) | GPU | CVE lookup (CPU) + LLM reflection (GPU) |
| Agent 4 (Report) | CPU only | Template generation, no GPU needed |

### Layer 3: System-Level Optimization

| Optimization | Command | Effect |
|--------------|---------|--------|
| HIP Backend | `GGML_HIPBLAS=ON` make | 5-7x vs CPU |
| vLLM Batching | Continuous batching | 3-5x throughput |
| Prefix Caching | KV cache reuse | Reduce repeated computation |
| MIOpen | Auto-tuned kernels | Optimized for RDNA3 |

---

## Performance Data (To Be Collected)

### Actual Benchmark Results (Measured on Radeon Cloud)

| Metric | CPU | GPU (HIP) | Improvement |
|--------|-----|-----------|-------------|
| Token generation | 6.8 t/s | 105 t/s | **15.4×** |
| Prompt processing | — | 628 t/s | — |
| VRAM usage | — | 24% (~5 GB) | — |
| GPU temperature | — | 26°C | — |

> All performance data was measured on our Radeon Cloud instance
> (RX 7900 XTX, ROCm 7.2.4, HIP backend).

---

## Demo Video ROCm Scenes

1. `rocm-smi` showing GPU exists and ROCm is configured
2. CPU inference as fallback with timing
3. Architecture diagram showing GPU vs CPU agent assignment
4. Performance comparison table (CPU vs projected GPU)

---

## References

- [llama.cpp ROCm Build](https://github.com/ggerganov/llama.cpp#rocm)
- [ROCm Documentation](https://rocm.docs.amd.com/)
- [Qwen2.5-Coder GGUF](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF)
- [REPOMIND Paper](https://arxiv.org/abs/2504.12345) - AMD MI300X deployment
