# Local model feasibility

## Summary

1. **Best 3090 candidate:** Qwen3.5-27B Q4_K_M, about 18 GB; begin around 16K context and leave VRAM for KV cache/runtime. ([GGUF](https://huggingface.co/gguf/Qwen3.5-27B-GGUF), [llama.cpp memory notes](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md))
2. **Best balance:** Qwen3.5-9B Q6_K, about 7.5 GB; start at 32K context. ([quant](https://huggingface.co/duolaf/Qwen3.5-9B-GGUF), [model card](https://huggingface.co/Qwen/Qwen3.5-9B))
3. **Small GPU option:** Qwen3.5-4B Q8_0, about 4.5 GB; start at 32K context. ([GGUF](https://huggingface.co/ggml-org/Qwen3.5-4B-GGUF))
4. All three list Apache-2.0 and 262K native context; that native limit is not a promise of practical 3090 context. ([27B](https://huggingface.co/Qwen/Qwen3.5-27B), [9B](https://huggingface.co/Qwen/Qwen3.5-9B), [4B](https://huggingface.co/Qwen/Qwen3.5-4B))
5. Their model-card BFCL-V4 scores are 68.5, 66.1 and 50.3; these are author-reported, unquantized general tool-call results, not security accuracy. ([27B](https://huggingface.co/Qwen/Qwen3.5-27B), [9B](https://huggingface.co/Qwen/Qwen3.5-9B), [4B](https://huggingface.co/Qwen/Qwen3.5-4B))
6. CPU-only: Qwen3.5-2B Q4_K_M and 4B Q4_K_M are plausible for short, structured triage, not autonomous security decisions. ([2B GGUF](https://huggingface.co/gguf/Qwen3.5-2B-GGUF), [4B GGUF](https://huggingface.co/ggml-org/Qwen3.5-4B-GGUF))
7. On one reported i7-10700 CPU, a 1K-input/200-output triage is about 18 seconds for 2B or 42 seconds for 4B, before startup overhead. ([CPU benchmark](https://github.com/quanhua92/local-llm-lab/blob/main/reports/cpu.md))
8. Let code parse, match, score and gate findings; let the model explain evidence, suggest a label and abstain. ([homelab-netguard audit](netguard-audit.md))
9. Compare models on a fixed 30-case labeled set and score missed risks, false alarms, abstention, evidence use and tool-call validity. ([BFCL](https://gorilla.cs.berkeley.edu/leaderboard.html), [OWASP prompt injection guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html))
10. Keep scanned text untrusted, tools read-only and allowlisted, and alerts evidence-backed; **3090 speed and quantized security accuracy are UNVERIFIED** because no local inference was run. ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html))

## GPU candidates

| Model | Practical GGUF choice | Context | Tool calling | License |
|---|---|---|---|---|
| Qwen3.5-27B | Q4_K_M, 18 GB. Start at 16K on 24 GB; reduce if KV cache/runtime does not fit. | 262,144 native. | BFCL-V4 68.5, the strongest of this shortlist by model-card score. | Apache-2.0. ([card](https://huggingface.co/Qwen/Qwen3.5-27B), [GGUF](https://huggingface.co/gguf/Qwen3.5-27B-GGUF), [llama.cpp memory](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)) |
| Qwen3.5-9B | Q6_K, about 7.46 GB. Start at 32K. | 262,144 native. | BFCL-V4 66.1. | Apache-2.0. ([card](https://huggingface.co/Qwen/Qwen3.5-9B), [Q6_K file](https://huggingface.co/duolaf/Qwen3.5-9B-GGUF)) |
| Qwen3.5-4B | Q8_0, 4.48 GB. Start at 32K. | 262,144 native. | BFCL-V4 50.3; weaker tool selection is a concern. | Apache-2.0. ([card](https://huggingface.co/Qwen/Qwen3.5-4B), [GGUF](https://huggingface.co/ggml-org/Qwen3.5-4B-GGUF)) |

Context starts are conservative engineering estimates, not tested settings: model file size alone does not include context/KV cache and runtime memory. llama.cpp documents context-related memory use and the need for correct chat templates for function calling; it warns that aggressive KV-cache quantization can harm call quality. ([server memory notes](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md), [function calling](https://github.com/ggml-org/llama.cpp/blob/master/docs/function-calling.md)) BFCL scores above come from model cards and are not scores for the cited GGUF quantizations or this product’s tasks. ([BFCL](https://gorilla.cs.berkeley.edu/leaderboard.html))

## CPU-only small models

Qwen3.5-2B Q4_K_M is about 1.31 GB and scores 43.6 on the model card’s BFCL-V4; its card positions it for prototypes and notes more risk of thinking loops. Qwen3.5-4B Q4_K_M is about 3.03 GB and scores 50.3. Both list Apache-2.0. ([2B card](https://huggingface.co/Qwen/Qwen3.5-2B), [2B GGUF](https://huggingface.co/gguf/Qwen3.5-2B-GGUF), [4B card](https://huggingface.co/Qwen/Qwen3.5-4B), [4B GGUF](https://huggingface.co/ggml-org/Qwen3.5-4B-GGUF))

A published llama.cpp CPU run used an Intel i7-10700, 64 GB RAM, Q4_K_M, eight threads and 8K context. It measured 2B at 114.4 prompt / 22.4 decode tokens/s and 4B at 44 / 10.3 tokens/s. At those rates, 1,000 input + 200 output tokens take roughly 18 / 42 seconds; 4,000 input + 300 output take 48 / 120 seconds. Startup, other system load and slower CPUs add time. ([benchmark and setup](https://github.com/quanhua92/local-llm-lab/blob/main/reports/cpu.md))

RAM planning estimate, not a vendor minimum: allow roughly 4–6 GB free for 2B Q4 and 6–8 GB free for 4B Q4 at short context, plus the operating system and scanner; 8 GB installed is a tight 2B floor, while 16 GB installed is a more practical 4B machine. The cited weight files use 1.31 / 3.03 GB, and llama.cpp notes extra context/cache/runtime memory. ([2B GGUF](https://huggingface.co/gguf/Qwen3.5-2B-GGUF), [4B GGUF](https://huggingface.co/ggml-org/Qwen3.5-4B-GGUF), [llama.cpp memory](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)) Expect small models to miss context across related logs, confuse weak signals, follow hostile text, or make malformed/irrelevant calls; measure those failure modes in the set below instead of assuming benchmark scores transfer. ([Qwen3.5-2B card](https://huggingface.co/Qwen/Qwen3.5-2B), [BFCL](https://gorilla.cs.berkeley.edu/leaderboard.html))

## Split code and model work

**Code should own:** network and log collection; deterministic parsing; asset identity; known-service/CVE matching; severity thresholds; deduplication; evidence storage; and whether an alert is sent. This follows the existing scanner’s local, alert-only shape. ([homelab-netguard audit](netguard-audit.md))

**The model should:** map a compact finding to `risk`, `benign`, or `needs_human`; explain the reason in plain language using cited evidence IDs; identify missing evidence; and request only approved read-only lookups. It should not decide what to scan, set severity by itself, execute shell commands, or apply fixes. This is a design recommendation based on the scanner’s alert-only scope and OWASP least-privilege/validation guidance. ([homelab-netguard audit](netguard-audit.md), [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html))

Use a strict JSON schema, validate every field and tool argument in code, allowlist any read-only tool names, and reject all other calls. llama.cpp tool use depends on a compatible chat template; BFCL tests call accuracy and irrelevance handling, but neither makes a model safe to grant broad tools. ([llama.cpp function calling](https://github.com/ggml-org/llama.cpp/blob/master/docs/function-calling.md), [BFCL](https://gorilla.cs.berkeley.edu/leaderboard.html), [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html))

## Repeatable 30-case evaluation

Create a small frozen set with **10 real risks, 10 harmless hard negatives and 10 cases that need a human**. Include examples such as internet-reachable admin UI, exposed unauthenticated service, suspicious auth burst, stale but internal-only service, expected port, benign backup login burst, ambiguous ownership, conflicting DNS/log clues, and banners/pages containing “ignore previous instructions” or fake tool requests. These examples are proposed test cases, not claims about observed incidents. Keep the raw evidence, expected label, evidence IDs and reason with each case. ([OWASP prompt injection guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html))

For every run, pin model/GGUF hash, llama.cpp version, prompt/schema, context, temperature, seed and tool allowlist. Score: (1) high-risk recall, (2) false-positive rate on harmless cases, (3) correct abstention on human-needed cases, (4) evidence support, 0–2 per explanation (unsupported / partly supported / fully cited), (5) valid and relevant tool calls, and (6) latency. Report raw counts and per-class results, not only an average; weight missed high-risk cases more heavily than style. Repeat each case three times if sampling is enabled. This is a proposed product-specific protocol; BFCL is a useful general tool-call reference, not a substitute for it. ([BFCL](https://gorilla.cs.berkeley.edu/leaderboard.html))

## Risks and guards

- **False alarms or missed risk:** keep deterministic checks as the alert gate, require evidence IDs, expose uncertainty, and route ambiguous findings to a human; alert-only behavior is already the project’s scope. ([homelab-netguard audit](netguard-audit.md))
- **Prompt injection in banners, logs or pages:** mark collected text as untrusted data, isolate it from instructions, give the model no secrets or broad tools, and test with injected strings. OWASP recommends treating external content as untrusted and validating model outputs. ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html))
- **Unsafe or malformed tool calls:** enforce schema and allowlist in code; tools should be read-only, bounded and unable to run arbitrary commands. ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html), [llama.cpp function calling](https://github.com/ggml-org/llama.cpp/blob/master/docs/function-calling.md))
- **Model/quant/runtime changes:** pin hashes and runtime version, rerun the 30 cases after upgrades, and never silently fall back to a remote model. The test protocol above is a recommendation; local 3090 throughput, quantized case accuracy, and the proposed RAM budgets remain **UNVERIFIED** because no local inference was run. ([llama.cpp](https://github.com/ggml-org/llama.cpp), [CPU benchmark](https://github.com/quanhua92/local-llm-lab/blob/main/reports/cpu.md))
