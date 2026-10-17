# ZKPriv v2 — Design

Status: draft 1, 2026-10-16. Target venue: **PoPETs 2027 Issue 4 (Feb 28, 2027)**. Stretch: AsiaCCS 2027 round 2 (Dec 11, 2026). Fallback: USENIX Security 2027 cycle 2 (Jan 26, 2027), or IEEE TrustCom/CNS 2027.

## 1. One-sentence claim

ZKPriv lets a cloud LLM provider attach a short, publicly verifiable proof to every response. The proof shows that the response contains no PII forbidden by the provider's currently registered policy. It reveals neither the prompt, the response nor the weights, and a user who receives a non-compliant response holds evidence an auditor can check.

## 2. Positioning against prior work

| Work | What it proves | What ZKPriv adds |
|---|---|---|
| Reef (USENIX Sec '24) | A committed document matches / does not match a regex | Binding to an LLM response a user actually received. Semantic PII. A policy registry with rollback protection. Accountable receipts. An LLM-output evaluation. |
| zk-regex / Londhe et al. (PoPETs '26) | A regex **match exists** (path witness) | A sound **non-match** proof: a forced search-DFA run over every byte, with padding and Unicode safety |
| zkLLM, zkGPT, DeepProve | Output came from model M | A property of the output's **content**. ZKPriv composes with them through the shared output commitment. |
| ZK Middleboxes (USENIX Sec '22) | Encrypted traffic satisfies a policy | The same pattern applied to LLM outputs, with semantic PII and receipts |
| FairProof, zkLoRA, ZKPROV | Model or training properties | Per-response output properties |
| Signed AI receipts (IETF drafts) | That a response was produced and logged | That the logged response is **compliant**, without revealing it |
| Distributional leakage (NeurIPS '26) | Per-output checks can miss cross-query leakage | Discussed as a limitation. Optional per-user aggregation of proofs (stretch). |

**Contributions (draft):**
1. **The output-compliance statement.** A formal definition of a compliance receipt, with soundness, binding, non-repudiation and zero-knowledge, and a construction that meets it.
2. **Sound in-circuit absence detection for structured PII.** A forced search-DFA (Σ*R) run over the committed UTF-8 bytes, which proves that no accepting state is reached. It handles overlapping matches, length and padding binding, and confusable Unicode digits. Luhn is folded into the card DFA so random 16-digit strings don't cause false holds.
3. **Two-tier semantic PII.**
   - Tier 2a is cryptographic: in-circuit gazetteer lookup for names and places from a committed dictionary.
   - Tier 2b is attested: TEE-signed open-vocabulary NER labels, verified in-circuit.
   - The paper states exactly which guarantee survives a TEE compromise.
4. **A policy registry and receipts.** A hash-chained, append-only policy log with version and freshness checks. Receipts are (response, opening, proof, policy version, request id), so a user can prove a violation to an auditor.
5. **An implementation and evaluation.**
   - Noir/UltraHonk circuits.
   - Measured gates, prove/verify time, memory and proof size on an Apple M4 Pro.
   - Detector accuracy on ai4privacy and on real LLM outputs, including extraction attacks.
   - An adversarial obfuscation suite.
   - The overhead relative to LLM generation time.

## 3. Threat model

- **Provider S:** malicious. It controls everything outside an optional TEE and may want to serve PII to a targeted user while appearing compliant to everyone else.
- **User U:** honest for their own checks. U verifies the proof and the commitment opening before accepting a response.
- **Auditor / any verifier V:** sees only receipts that users forward, plus the public registry.
- **Out of scope:**
  - PII not expressible by the active detectors, such as paraphrased or obfuscated forms. This is measured and reported.
  - Cross-query aggregation leakage.
  - Side channels.

**Why ZK adds value over TEE attestation alone (reviewers will ask):**
- Tier 1 and tier 2a hold **even if the TEE is compromised.** U checks that the response it received opens the commitment, and the proof shows the committed bytes are free of detectable PII.
- Verification is **public and offline.** A regulator can check a receipt without contacting the provider, without trusting a hardware vendor, and without seeing the text.
- **Non-repudiation.** A provider can't produce a valid receipt for a non-compliant response, so a response without a valid receipt is itself evidence of a violation.

## 4. Statement proven

Public inputs: `com_y`, `h_pol`, `v`, `pid`, and for tier 2b, `pk_enclave`.
Private witness: response bytes `y[0..N)`, length `len`, blinding `ρ`, policy `P`, gazetteer membership witnesses, and for tier 2b, signed labels.

| Id | Predicate | Notes |
|---|---|---|
| P1 | `com_y = Poseidon2(pack(y), len, ρ, pid)`, with `y[i] = 0` for `i ≥ len` | Binds the length and blocks padding hiding. Binding `pid` prevents replay. |
| P2 | `h_pol = Poseidon2(P)` and `P.version = v` | The registry supplies `h_pol` for `v` and checks freshness outside the circuit |
| P3 | For each detector `D_k` enabled in `P.mask`: the forced search-DFA over `y[0..len)` never reaches an accepting state | Functional (state, byte) → next lookup tables. Detectors run separately, not as a product. |
| P4 | Allowlist: spans matching an allowlisted pattern (for example the provider's support phone number) are skipped | Implemented as allowlist DFAs, or a Merkle membership check on exempt values |
| P5 (tier 2a) | For each word token, either it is not in the committed gazetteer, or its category is permitted | A lookup or Merkle non-membership check against a committed gazetteer root in `P` |
| P6 (tier 2b) | `Verify(pk_enclave, (com_y, label_digest))` and `label_digest` has no prohibited categories | An ECDSA/Ed25519 black-box check in Noir |
| P7 | Canonicalization guard: if `P.ascii_only`, every byte < 0x80, or confusable code points are rejected | Prevents fullwidth digits and zero-width joiners slipping past ASCII `\d` |

**Detectors, v1:** US SSN; email; US/E.164 phone; payment card (13–19 digits plus Luhn); IPv4; date of birth (numeric date formats); US ZIP+4; IBAN (stretch). Each is a hand-checked regex compiled to a minimized DFA and checked against a reference implementation by differential testing.

## 5. Architecture

```
User ──prompt──▶ Provider (TEE: LLM ─▶ response y ─▶ NER labels ─▶ sign)
                         │
                         └─▶ Noir prover(y, ρ, P, labels) ─▶ π
User ◀── (y, ρ, π, v, pid) ──┘
User: check com_y = H(y, len, ρ, pid); fetch h_pol(v) from registry; Verify(π)
Auditor ◀── forwarded receipts (no y needed to verify compliance)
```

## 6. Evaluation plan (every number generated by `scripts/`)

1. **Circuit cost:** gates as a function of `N` ∈ {64, 128, 256, 512, 1024} and the number of detectors, plus a per-component breakdown.
2. **Performance on the M4 Pro (24 GB):** witness time, prove time, verify time, peak memory and proof size. Report the median and IQR over 10 runs.
3. **Baselines:**
   - circom + zk-regex (Groth16) for the same detectors.
   - Reef's reported numbers, marked as reported, not rerun.
   - The cost of a full zkGPT/DeepProve inference proof (reported) to show composition overhead.
4. **Detector accuracy:**
   - ai4privacy (English, seed 42; the IDs are frozen in `eval/ids.json`), per type.
   - Comparison with Presidio and with a Python reference implementation of the same regexes. In-circuit and reference must agree on 100% of inputs.
5. **Real LLM outputs:**
   - Llama 3.1 8B / 3.2 3B through Ollama, with prompts that elicit PII: RAG over synthetic records, "repeat the record", and extraction-style prompts.
   - Measure how many PII-bearing responses ZKPriv blocks, by type.
6. **Adversarial suite:** spelled-out digits, separators, Unicode confusables, split across lines, and base64. Report what is caught and what isn't (an honest limitations table).
7. **End-to-end overhead:** proof time compared with LLM generation time for the same response length.

## 7. Milestones

| Week of | Milestone |
|---|---|
| Oct 19 | Toolchain installed; SSN detector circuit, plus non-match and padding tests |
| Oct 26 | All v1 detectors with differential tests; commitment and policy predicates |
| Nov 2 | Benchmarks harness; first cost/performance tables |
| Nov 9 | Tier 2a gazetteer and tier 2b signature check; receipt and registry prototype |
| Nov 16 | LLM-output collection and the adversarial suite |
| Nov 23 | circom baseline; full evaluation run |
| Nov 30 – Dec 11 | Security definitions and proofs; paper draft. Decide whether AsiaCCS (Dec 11) is feasible. |
| Jan – Feb 2027 | Internal review, polish, artifact; PoPETs Issue 4 (Feb 28) |

## 8. Open questions

- **Tier 2a gazetteer size against cost.** Top-N US first and last names (Census/SSA). Choose between per-word Merkle proofs and lookup tables.
- **Tokenization boundary.** The circuit works on UTF-8 bytes after detokenization. The paper must say why token-ID commitments are unsafe.
- **Aggregating many receipts with recursion.** A stretch goal, relevant to distributional leakage.
- **Co-author roles.** To agree with Ghazal Mahdian and Prof. Jalooli.
