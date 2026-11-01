"""Evaluation: retriever comparison, refusal calibration, injection robustness.

    python evaluate.py                 # TF-IDF vs BM25 vs hybrid, threshold calibration, injection suite
    python evaluate.py --embeddings    # also test embedding retrievers (needs sentence-transformers)

Method: threshold is tuned on the DEV split only; every number reported for the TEST split
is computed after that, with nothing tuned on it.
"""
import json, sys, pathlib, argparse
import numpy as np
from soc_triage.retriever import Retriever
from soc_triage import pipeline
from soc_triage.guardrails import sanitize

ROOT = pathlib.Path(__file__).parent
parent = lambda tid: tid.split(".")[0]

def load(split):
    return [a for a in json.loads((ROOT / "data/alerts.json").read_text()) if a["split"] == split]

def retrieval_metrics(R, alerts, mode):
    mapped = [a for a in alerts if a["labels"]]
    top1 = top1p = top3p = top5p = 0
    for a in mapped:
        res = R.search(a["text"], k=5, mode=mode)
        ids = [r["id"] for r in res]
        want, want_p = set(a["labels"]), {parent(x) for x in a["labels"]}
        top1 += ids[0] in want
        top1p += parent(ids[0]) in want_p
        top3p += any(parent(i) in want_p for i in ids[:3])
        top5p += any(parent(i) in want_p for i in ids[:5])
    n = len(mapped)
    return {"n": n, "top1_exact": top1 / n, "top1_parent": top1p / n, "top3_parent": top3p / n, "top5_parent": top5p / n}

MISS_COST = 3.0   # a missed real alert is treated as 3x worse than sending a benign one to a human

def calibrate(R, dev, mode):
    """Pick the confidence threshold on DEV: maximise MISS_COST*TPR + true-refusal-rate."""
    conf = [(R.search(a["text"], k=1, mode=mode)[0]["confidence"], bool(a["labels"])) for a in dev]
    best, best_t = -1, 8.0
    vals = sorted({c for c, _ in conf})
    for t in [(a + b) / 2 for a, b in zip(vals, vals[1:])]:
        tpr = np.mean([c >= t for c, m in conf if m])
        trr = np.mean([c < t for c, m in conf if not m])
        if MISS_COST * tpr + trr > best + 1e-9:
            best, best_t = MISS_COST * tpr + trr, float(round(t, 2))
    return best_t

def refusal_metrics(R, alerts, mode, t):
    pos = [R.search(a["text"], k=1, mode=mode)[0]["confidence"] >= t for a in alerts if a["labels"]]
    neg = [R.search(a["text"], k=1, mode=mode)[0]["confidence"] < t for a in alerts if not a["labels"]]
    return {"real_alerts_kept": float(np.mean(pos)), "benign_refused": float(np.mean(neg)), "n_benign": len(neg)}

def injection_suite():
    tests = json.loads((ROOT / "data/injection_tests.json").read_text())
    base = pipeline.triage({"raw": tests[-1]["text"]})
    rows, detected, unchanged = [], 0, 0
    for t in tests[:-1]:
        _, flagged = sanitize(t["text"])
        out = pipeline.triage({"raw": t["text"]})
        same = (out["technique"].get("id") == base["technique"].get("id")
                and out["severity"] in (base["severity"], "High", "Critical")
                and not out["refused"])
        detected += flagged; unchanged += same
        rows.append((t["name"], flagged, same))
    return rows, detected, unchanged, base

def pct(x): return f"{x:.0%}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--embeddings", action="store_true")
    ap.add_argument("--llm-rerank", action="store_true", help="also measure LLM reranking of the top-5 (needs ANTHROPIC_API_KEY)")
    args = ap.parse_args()
    dev, test = load("dev"), load("test")
    R = Retriever(use_embeddings=args.embeddings)
    modes = ["tfidf", "bm25", "hybrid"] + (["embed", "hybrid_embed"] if args.embeddings else [])

    md = ["# Evaluation results", "",
          f"KB: {len(R.kb)} ATT&CK techniques/sub-techniques. Dev: {len(dev)} alerts, Test: {len(test)} alerts "
          f"({sum(1 for a in test if a['labels'])} real, {sum(1 for a in test if not a['labels'])} benign).", "",
          "## Retrieval (real alerts only; 'parent' = sub-technique counts as correct if the parent technique matches)", "",
          "| Retriever | Split | Top-1 exact | Top-1 parent | Top-3 parent | Top-5 parent |", "|---|---|---|---|---|---|"]
    for m in modes:
        for name, split in (("dev", dev), ("test", test)):
            r = retrieval_metrics(R, split, m)
            md.append(f"| {m} | {name} | {pct(r['top1_exact'])} | {pct(r['top1_parent'])} | {pct(r['top3_parent'])} | {pct(r['top5_parent'])} |")

    if args.llm_rerank:
        md += ["", "## LLM rerank of hybrid top-5 (real alerts only)", "", "| Split | Top-1 exact | Top-1 parent |", "|---|---|---|"]
        for name, split in (("dev", dev), ("test", test)):
            mapped = [a for a in split if a["labels"]]
            ex = pa = 0
            for a in mapped:
                c = R.search(a["text"], k=5, mode="hybrid")
                pick = pipeline.llm_rerank(a["text"], c) or c[0]["id"]
                ex += pick in set(a["labels"]); pa += parent(pick) in {parent(x) for x in a["labels"]}
            md.append(f"| {name} | {pct(ex/len(mapped))} | {pct(pa/len(mapped))} |")

    best_mode = "hybrid_embed" if args.embeddings else "hybrid"
    t = calibrate(R, dev, best_mode)
    rd, rt = refusal_metrics(R, dev, best_mode, t), refusal_metrics(R, test, best_mode, t)
    md += ["", f"## Refusal (retriever = {best_mode}; threshold {t} tuned on dev only, a missed real alert weighted {MISS_COST:g}x a benign one)", "",
           "| Split | Real alerts still mapped | Benign alerts refused |", "|---|---|---|",
           f"| dev | {pct(rd['real_alerts_kept'])} | {pct(rd['benign_refused'])} |",
           f"| test | {pct(rt['real_alerts_kept'])} | {pct(rt['benign_refused'])} |"]

    (ROOT / "data/config.json").write_text(json.dumps({"min_confidence": t, "retriever": best_mode}, indent=1))
    pipeline.CONFIG.update({"min_confidence": t, "retriever": best_mode})
    rows, det, unch, base = injection_suite()
    md += ["", "## Prompt-injection suite", "",
           f"Clean baseline: {base['technique'].get('id')} / {base['severity']}.", "",
           "| Attack | Caught by sanitizer | Verdict unchanged or raised |", "|---|---|---|"]
    md += [f"| {n} | {'yes' if f else 'NO'} | {'yes' if s else 'NO'} |" for n, f, s in rows]
    md += ["", f"**Sanitizer caught {det}/{len(rows)}; verdict unaffected in {unch}/{len(rows)}.** "
               "Verdicts come from deterministic code, so attacks the sanitizer misses still cannot downgrade severity."]

    text = "\n".join(md)
    print(text)
    (ROOT / "RESULTS.md").write_text(text + "\n")

if __name__ == "__main__":
    main()
