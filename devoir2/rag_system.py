# rag_system.py

def ask_legal_assistant(question, llm_name="simulation", top_k=5, verbose=False):
    """
    Version simple améliorée pour tester Streamlit
    """

    q = question.lower()

    # ── Réponses simulées enrichies ───────────────────────────────────────────
    if any(word in q for word in ["alcool", "ivresse", "boire"]):
        response = "🚫 Conduite en état d'ivresse : amende + suspension du permis (Article 183)."

    elif any(word in q for word in ["permis", "conduire", "conduite"]):
        response = "📄 Le permis de conduire est obligatoire pour conduire un véhicule (Article 1)."

    elif any(word in q for word in ["points", "probatoire"]):
        response = "📊 Le permis probatoire est doté d’un capital de points spécifique (Article 23)."

    elif any(word in q for word in ["vitesse", "excès"]):
        response = "⚠️ Le dépassement de vitesse est sanctionné selon la gravité (Article 184)."

    elif any(word in q for word in ["controle", "documents"]):
        response = "📑 Le conducteur doit présenter permis, carte grise et assurance lors d’un contrôle."

    # ── Hors domaine ──────────────────────────────────────────────────────────
    elif any(word in q for word in ["cuisine", "couscous", "recette", "football"]):
        return {
            "question": question,
            "response": "⚠️ Question hors domaine. Je réponds uniquement au Code de la Route Marocain.",
            "docs": [],
            "is_out_of_domain": True
        }

    # ── Par défaut ────────────────────────────────────────────────────────────
    else:
        response = "🤖 Réponse simulée : système RAG non encore connecté."

    return {
        "question": question,
        "response": response,
        "docs": [],
        "is_out_of_domain": False
    }