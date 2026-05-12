
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

import networkx as nx

def graph_retrieve(query, G, k=3):

    q_emb = EMBED_MODEL.encode([query]).astype(np.float32)

    q_norm = q_emb / (
        np.linalg.norm(q_emb) + 1e-8
    )

    node_indices = list(G.nodes())

    if len(node_indices) == 0:
        return []

    node_embs = original_embeddings[node_indices]

    sims = cosine_similarity(
        q_norm,
        node_embs
    )[0]

    best_idx = node_indices[np.argmax(sims)]

    neighbors = list(G.neighbors(best_idx))

    candidate_nodes = [best_idx] + neighbors

    results = []

    for idx in candidate_nodes[:k]:

        results.append({
            "description": DOCUMENTS[idx] if idx < len(DOCUMENTS) else "",
            "yara_rule": YARA_RULES[idx] if idx < len(YARA_RULES) else "",
            "category": CATEGORIES[idx] if idx < len(CATEGORIES) else "malware",
            "idx": idx
        })

    return results


if __name__ == "__main__":

    G = nx.Graph()

    G.add_nodes_from([0, 1, 2])

    G.add_edge(0, 1)

    query = "Botnet malware"

    docs = graph_retrieve(query, G)

    print(docs)
