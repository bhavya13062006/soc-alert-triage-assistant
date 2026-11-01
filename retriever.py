"""Retrieval over the MITRE ATT&CK knowledge base: TF-IDF, BM25, hybrid (RRF), optional embeddings."""
import json, re, pathlib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer, ENGLISH_STOP_WORDS
from sklearn.metrics.pairwise import cosine_similarity
from rank_bm25 import BM25Okapi

ROOT = pathlib.Path(__file__).resolve().parent.parent
KB_PATH = ROOT / "data" / "attack_kb.json"
MODES = ("tfidf", "bm25", "hybrid", "embed", "hybrid_embed")

# Generic log boilerplate that carries no technique signal (chosen by reasoning about log formats, checked on dev only).
LOG_NOISE = set("event eid sysmon user host hosts logs log alert alerts minutes minute seconds second hours hour "
                "within every times repeated number different distinct local time followed one single per".split())

def tokenize(text: str):
    text = re.sub(r"\.(exe|dll|sys|bat|ps1)\b", " ", text.lower())
    return [t for t in re.findall(r"[a-z0-9]{2,}", text)
            if t not in ENGLISH_STOP_WORDS and t not in LOG_NOISE and not t.isdigit()]

def _doc(t):
    return f'{t["name"]} {t["name"]} {t["name"]} {" ".join(t["tactics"])} {t["desc"]} {t["detection"]} {" ".join(t.get("software", []))} {" ".join(t.get("examples", []))}'

class Retriever:
    def __init__(self, kb_path=KB_PATH, use_embeddings=False, embed_model="BAAI/bge-small-en-v1.5"):
        self.kb = json.loads(pathlib.Path(kb_path).read_text())
        docs = [_doc(t) for t in self.kb]
        self.vec = TfidfVectorizer(tokenizer=tokenize, lowercase=False, token_pattern=None,
                                   ngram_range=(1, 2), sublinear_tf=True, min_df=1)
        self.tfidf = self.vec.fit_transform(docs)
        self.bm25 = BM25Okapi([tokenize(d) for d in docs])
        self.emb = None
        if use_embeddings:
            from sentence_transformers import SentenceTransformer   # optional dependency
            self.model = SentenceTransformer(embed_model)
            self.emb = self.model.encode(docs, normalize_embeddings=True, show_progress_bar=False)

    def _scores(self, query):
        s = {"tfidf": cosine_similarity(self.vec.transform([query]), self.tfidf)[0],
             "bm25": np.array(self.bm25.get_scores(tokenize(query)))}
        if self.emb is not None:
            s["embed"] = self.emb @ self.model.encode([query], normalize_embeddings=True)[0]
        return s

    @staticmethod
    def _rrf(score_arrays, k=60):
        fused = np.zeros(len(score_arrays[0]))
        for arr in score_arrays:
            ranks = np.empty(len(arr), dtype=int)
            ranks[np.argsort(-arr)] = np.arange(1, len(arr) + 1)
            fused += 1.0 / (k + ranks)
        return fused

    def search(self, query, k=5, mode="hybrid"):
        s = self._scores(query)
        if mode in ("tfidf", "bm25", "embed"):
            main = s[mode]
        elif mode == "hybrid":
            main = self._rrf([s["tfidf"], s["bm25"]])
        elif mode == "hybrid_embed":
            main = self._rrf([s["tfidf"], s["bm25"], s["embed"]])
        else:
            raise ValueError(f"unknown mode {mode}")
        order = np.argsort(-main)[:k]
        # 'confidence' is always the BM25 match score so the refusal threshold means the same thing in every mode
        return [{**self.kb[i], "score": float(main[i]), "confidence": float(s["bm25"][i])} for i in order]
