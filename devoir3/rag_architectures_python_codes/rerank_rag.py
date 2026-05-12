
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


def rerank(query, docs, top_k=2):
    '''
    Re-ranking using dense score + keyword overlap.
    '''

    query_words = set(query.lower().split())

    reranked = []

    for doc in docs:

        dense_score = doc["score"]

        doc_words = set(
            doc["description"].lower().split()
        )

        overlap = len(query_words & doc_words) / (
            len(query_words) + 1e-8
        )

        combined_score = (
            0.7 * dense_score +
            0.3 * overlap
        )

        reranked.append({
            **doc,
            "rerank_score": combined_score
        })

    reranked.sort(
        key=lambda x: x["rerank_score"],
        reverse=True
    )

    return reranked[:top_k]


def rag_rerank(query, k_retrieve=5, k_final=2):

    docs = retrieve(query, k=k_retrieve)

    reranked_docs = rerank(
        query,
        docs,
        top_k=k_final
    )

    context = "\n".join([
        f"{d['description']}\n{d['yara_rule']}"
        for d in reranked_docs
    ])

    prompt = f"""
Use the best retrieved examples below:

{context}

Generate a YARA rule for:
{query}
"""

    raw = generate_yara(prompt)

    top_cat = (
        reranked_docs[0]["category"]
        if reranked_docs else "malware"
    )

    rule = format_yara_rule(
        raw,
        query,
        top_cat
    )

    return rule, reranked_docs


if __name__ == "__main__":
    query = "Email phishing trojan"

    rule, docs = rag_rerank(query)

    print(rule)
