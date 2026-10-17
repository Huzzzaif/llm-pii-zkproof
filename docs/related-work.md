# Related work and venues (scanned 2026-10-16)

## Closest prior work
- **Reef** — Angel et al., USENIX Security 2024, ePrint 2023/1886. Proves a committed document matches *or does not match* a regex. ZKPriv must cite it as the base for tier 1 and differentiate on: LLM-output binding, semantic PII, registry and receipts, evaluation.
- **ZK proofs of generalized regex matching** — Londhe et al., PoPETs 2026, ePrint 2026/1284. NFA path witnesses in Circom and Noir; existence proofs only. Benchmarked on an M4 Pro.
- **zk-regex** (zkEmail) — DFA circuits. Audited by zkSecurity; robustness issues found in the compiler.
- **zkLLM** (CCS'24, arXiv 2404.16109), **zkGPT** (USENIX Sec'25), **DeepProve** (ePrint 2026/1112), **OpenLLM** (ePrint 2026/1578), **NANOZK** (ICLR'26). These prove inference integrity, not output content.
- **FairProof** (ICML'24), **zkLoRA/VeriLoRA** (NDSS'26), **ZKPROV** (arXiv 2506.20915), **zkLLMPoT** (arXiv 2610.08258), **ZK-APEX** (arXiv 2512.09953). These prove model or training properties.
- **Zero-Knowledge Middleboxes** (USENIX Sec'22). Policy compliance of hidden traffic; the closest conceptual template.
- **Distributional privacy leakage in LLMs with ZK** (NeurIPS'26). Per-output checks can miss cross-query leakage; this is a limitation to address.
- **Verifiable redaction:** zkTax (arXiv 2311.13008), VerITAS (ePrint 2024/1066), EURECOM. These prove a redaction is correct, not that the result is free of PII.
- **Receipts:** IETF draft-chueayen-attestation-receipts, draft-crovia-seal; Verifiability-First Agents (arXiv 2512.17259).
- **TOPLOC** (ICML'25), Optimistic TEE-Rollups (arXiv 2512.20176). Integrity only.

## Toolchain findings
- Primary: **Noir + Barretenberg UltraHonk.** About 15 gates per DFA byte-step using lookups. Universal setup. Proofs are ~14 KB and verify in ~1–2 s.
- Fallback: **circom + zk-regex + snarkjs/rapidsnark.** Groth16 proofs are 805 B and verify in ~188 ms, but each regex step costs O(transitions) per byte and needs a per-circuit setup.
- Non-match requires a forced search-DFA (Σ*R) over every byte. A path witness can't prove absence.
- Pitfalls: padding and length binding; bytes vs tokens; Unicode confusables; overlapping matches; `\b` unsupported; obfuscation.

## Venues
| Venue | Deadline | Notes |
|---|---|---|
| PoPETs 2027 Issue 3 / **Issue 4** | Nov 30, 2026 / **Feb 28, 2027** | Primary target: Issue 4 |
| AsiaCCS 2027 round 2 | Dec 11, 2026 | Stretch |
| EuroS&P 2027 | Dec 2, 2026 | Likely too soon |
| USENIX Security 2027 cycle 2 | Jan 26, 2027 | Ambitious fallback |
| CCS 2027 | cycles TBA | |
| TrustCom / CNS 2027 | CFPs not out; historically mid-2027 | Safety net |
