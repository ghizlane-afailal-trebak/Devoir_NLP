
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


def reformulate_query(original_query, first_hop_docs):

    categories = [
        d["category"]
        for d in first_hop_docs
    ]

    dominant_cat = (
        max(set(categories), key=categories.count)
        if categories else "malware"
    )

    enriched = (
        f"{original_query} AND {dominant_cat} behavior"
    )

    return enriched


def multi_hop_rag(
    query,
    hops=2,
    k_per_hop=3
):

    all_docs = []

    current_query = query

    for hop in range(hops):

        hop_docs = retrieve(
            current_query,
            k=k_per_hop
        )

        all_docs.extend(hop_docs)

        if hop < hops - 1:
            current_query = reformulate_query(
                current_query,
                hop_docs
            )

    seen = set()
    unique_docs = []

    for doc in all_docs:

        if doc["idx"] not in seen:

            seen.add(doc["idx"])

            unique_docs.append(doc)

    context = "\n".join([
        d["description"]
        for d in unique_docs
    ])

    prompt = f"""
Multi-hop context:
{context}

Generate a YARA rule for:
{query}
"""

    raw = generate_yara(prompt)

    top_cat = (
        unique_docs[0]["category"]
        if unique_docs else "malware"
    )

    rule = format_yara_rule(
        raw,
        query,
        top_cat
    )

    return rule, unique_docs


if __name__ == "__main__":
    query = "Advanced malware lateral movement"

    rule, docs = multi_hop_rag(query)

    print(rule)
