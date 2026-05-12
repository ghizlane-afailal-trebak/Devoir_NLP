
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

from baseline_rag import llm_no_rag
from rerank_rag import rag_rerank
from hybrid_rag import hybrid_retrieve


def graph_rag(query):
    '''
    Placeholder graph pipeline.
    '''
    return (
        generate_yara(query),
        []
    )


def rag_hybrid(query):
    '''
    Wrapper around hybrid retrieval.
    '''
    docs = hybrid_retrieve(query)

    prompt = f"Generate YARA for: {query}"

    raw = generate_yara(prompt)

    return raw, docs


def agentic_rag(query):

    strategy_log = []

    query_lower = query.lower()

    if len(query.split()) < 5:

        strategy = "baseline"

    elif any(word in query_lower for word in [
        "encrypt",
        "aes",
        "bitcoin",
        "ransom"
    ]):

        strategy = "graph"

    elif any(word in query_lower for word in [
        "keylogger",
        "capture",
        "email"
    ]):

        strategy = "rerank"

    else:

        strategy = "hybrid"

    strategy_log.append(
        f"Selected strategy: {strategy}"
    )

    if strategy == "baseline":

        rule = llm_no_rag(query)

        docs = []

    elif strategy == "graph":

        rule, docs = graph_rag(query)

    elif strategy == "rerank":

        rule, docs = rag_rerank(query)

    else:

        rule, docs = rag_hybrid(query)

    return rule, docs, strategy_log


if __name__ == "__main__":

    query = "Ransomware encrypting documents"

    rule, docs, logs = agentic_rag(query)

    print(logs)
    print(rule)
