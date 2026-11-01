# SOC Alert Triage Assistant

Agentic RAG that maps raw security alerts to **MITRE ATT&CK** techniques, assigns a severity, and produces an
analyst report with mitigations and sources. It **refuses** when nothing in the knowledge base fits, and it
defends itself against **prompt injection hidden inside logs**.

## Architecture (LangGraph)

```
alert text (untrusted)
   -> sanitize      strip injection (regex + leetspeak/homoglyph/base64 handling)
   -> retrieve      hybrid BM25 + TF-IDF (reciprocal rank fusion) over 706 ATT&CK techniques
   -> rerank        OPTIONAL LLM picks best of top-5 (validated against the candidate list)
   -> classify      deterministic: technique, severity by tactic, refuse below a calibrated threshold
   -> report        template report, or LLM summary grounded only in the retrieved entry
```

Design rule: **the verdict (technique + severity) is decided by deterministic code, not by the LLM.**
Even if an injection slips past the sanitizer, it cannot downgrade an alert.

## Run it

Requires Python 3.10+.

```bash
# 1. set up
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. run the tests
python -m pytest -q

# 3. reproduce the evaluation (writes RESULTS.md and data/config.json)
python evaluate.py

# 4. start the web app  ->  http://localhost:8501
streamlit run app.py
```

Optional extras:

```bash
# LLM-written summaries + LLM reranking (needs an Anthropic API key)
export ANTHROPIC_API_KEY=sk-ant-...          # Windows PowerShell: $env:ANTHROPIC_API_KEY="..."
export LLM_RERANK=1                          # turn on the rerank step
python evaluate.py --llm-rerank              # adds an LLM-rerank row to RESULTS.md

# Embedding retriever (downloads a small model the first time)
pip install sentence-transformers
python evaluate.py --embeddings

# Refresh the ATT&CK knowledge base from MITRE
python scripts/build_kb.py

# Docker
docker build -t soc-triage . && docker run -p 8501:8501 soc-triage
```

## Deploy for a live link (Streamlit Community Cloud, free)

1. Push this folder to a public GitHub repo (the 2 MB `data/attack_kb.json` is included, so nothing to download).
2. Go to share.streamlit.io, choose the repo, set the main file to `app.py`, and deploy.
3. (Optional) add `ANTHROPIC_API_KEY` under *Secrets* to enable LLM summaries.
4. Put the live URL at the top of this README and on your resume.

## Results (see RESULTS.md for full tables)

Method: dev and test splits of hand-written alerts (written in log style, not copied from ATT&CK wording).
The refusal threshold is tuned on dev only; test numbers are never tuned on.

| Metric (test split) | Result |
|---|---|
| Top-1 technique (parent-level), hybrid retriever | 62% |
| Right technique within top-5, hybrid | 83% |
| Real alerts still mapped after refusal threshold | 92% |
| Benign alerts correctly refused | 67% |
| Prompt-injection variants: caught by sanitizer | 13/15 |
| Prompt-injection variants: verdict unchanged or raised | 15/15 |

How I got here (also the story to tell in interviews): my first version scored 100% because I wrote the KB and the
test alerts myself (leakage). Switching to the full ATT&CK dataset and an independent test set dropped top-1 to about 46%.
Adding ATT&CK's own procedure examples (real tool names and command lines) to the searchable text, filtering log
boilerplate, and moving to hybrid retrieval raised it to 62%. I also found and fixed a bug where my own
`[REMOVED-INJECTION]` marker contained the word "injection" and pulled retrieval toward SQL-injection techniques.

## Limitations (be upfront about these)

- Small evaluation set (48 real + 24 benign alerts, synthetic). Numbers are indicative, not a benchmark.
- Lexical retrieval is the bottleneck: top-5 is 83% but top-1 is 62%. An LLM or cross-encoder reranker is the next step.
- Refusal relies on a keyword match score, a weak signal. A third of benign alerts still get mapped.
- Sanitizer misses non-English attacks and instructions split across words (listed as known gaps in the suite).
- Severity is by tactic only; it ignores asset criticality and context.
- The embedding and LLM-rerank paths are optional and I could not benchmark them without model/API access. Run the commands above to fill in those rows.

## Project layout

```
app.py                  Streamlit UI (single alert + batch CSV)
evaluate.py             retriever comparison, threshold calibration, injection suite -> RESULTS.md
soc_triage/             guardrails.py, retriever.py, pipeline.py
scripts/build_kb.py     downloads MITRE ATT&CK STIX -> data/attack_kb.json
data/                   attack_kb.json, alerts.json (dev/test), injection_tests.json, config.json
tests/                  pytest suite
```

## Data, license and ethics

- Code: MIT License (see `LICENSE`).
- Knowledge base: derived from MITRE ATT&CK(R), a registered trademark of The MITRE Corporation. ATT&CK content is
  used under MITRE's Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). Keep that
  attribution and re-check their current notice wording before redistributing.
- All alerts in `data/` are synthetic.
- Only use this tooling on systems you are authorized to test.
