
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


def rag_classic(query, k=3):
    '''
    Classic RAG architecture.
    '''

    docs = retrieve(query, k=k)

    context_parts = []

    for i, doc in enumerate(docs):
        context_parts.append(
            f"Example {i+1} ({doc['category']}):"
        )

        context_parts.append(
            f"Description: {doc['description']}"
        )

        context_parts.append(
            f"YARA Rule:\n{doc['yara_rule']}"
        )

    context = "\n".join(context_parts)

    prompt = f"""
You are a YARA expert.

Use the following retrieved examples:
{context}

Generate a YARA rule for:
{query}
"""

    raw = generate_yara(prompt)

    top_cat = docs[0]["category"] if docs else "malware"

    rule = format_yara_rule(
        raw,
        query,
        top_cat
    )

    return rule, docs


if __name__ == "__main__":
    query = "Keylogger malware stealing credentials"

    rule, docs = rag_classic(query)

    print(rule)
