
import numpy as np
from collections import defaultdict
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer


DOCUMENTS = []
YARA_RULES = []
CATEGORIES = []

original_embeddings = np.array([])

class DummyEmbedder:
    def encode(self, texts):
        return np.random.rand(len(texts), 384)

EMBED_MODEL = DummyEmbedder()


def generate_yara(prompt):
    '''
    Placeholder LLM generation function.
    Replace with your OpenAI / Ollama / HuggingFace call.
    '''
    return f"""rule generated_rule {{
    meta:
        description = "Generated from prompt"

    strings:
        $a = "malware"

    condition:
        $a
}}"""

def format_yara_rule(raw_rule, query, category):
    '''
    Post-processing for YARA formatting.
    '''
    return raw_rule

def retrieve(query, k=3):
    '''
    Placeholder dense retrieval.
    Replace with FAISS / Chroma / Pinecone retrieval.
    '''
    results = []

    for i in range(min(k, len(DOCUMENTS))):
        results.append({
            "description": DOCUMENTS[i],
            "yara_rule": YARA_RULES[i] if i < len(YARA_RULES) else "",
            "category": CATEGORIES[i] if i < len(CATEGORIES) else "malware",
            "score": 0.9 - (i * 0.1),
            "idx": i
        })

    return results


TFIDF_VECTORIZER = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=5000
)

TFIDF_MATRIX = (
    TFIDF_VECTORIZER.fit_transform(
        DOCUMENTS if DOCUMENTS else ["dummy"]
    )
)


def sparse_retrieve(query, k=5):

    q_vec = TFIDF_VECTORIZER.transform([query])

    scores = cosine_similarity(
        q_vec,
        TFIDF_MATRIX
    )[0]

    top_k_idx = np.argsort(scores)[::-1][:k]

    results = []

    for idx in top_k_idx:

        results.append({
            "description": DOCUMENTS[idx] if idx < len(DOCUMENTS) else "",
            "yara_rule": YARA_RULES[idx] if idx < len(YARA_RULES) else "",
            "category": CATEGORIES[idx] if idx < len(CATEGORIES) else "malware",
            "score": float(scores[idx]),
            "idx": idx
        })

    return results


def hybrid_retrieve(
    query,
    k_dense=3,
    k_sparse=3,
    k_final=3
):

    dense_docs = retrieve(query, k=k_dense)

    sparse_docs = sparse_retrieve(query, k=k_sparse)

    rrf_scores = defaultdict(float)
    rrf_data = {}

    for rank, doc in enumerate(dense_docs):

        idx = doc["idx"]

        rrf_scores[idx] += 1.0 / (rank + 60)

        rrf_data[idx] = doc

    for rank, doc in enumerate(sparse_docs):

        idx = doc["idx"]

        rrf_scores[idx] += 1.0 / (rank + 60)

        if idx not in rrf_data:
            rrf_data[idx] = doc

    top_idxs = sorted(
        rrf_scores.keys(),
        key=lambda x: rrf_scores[x],
        reverse=True
    )[:k_final]

    results = []

    for idx in top_idxs:

        results.append({
            **rrf_data[idx],
            "rrf_score": rrf_scores[idx]
        })

    return results


if __name__ == "__main__":
    query = "Ransomware using bitcoin payment"

    docs = hybrid_retrieve(query)

    print(docs)
