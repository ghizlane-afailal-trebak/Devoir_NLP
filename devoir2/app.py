# ══════════════════════════════════════════════════════════════════════════════
# app.py — Interface Streamlit pour le RAG Code de la Route Marocain
# Lancer avec : streamlit run app.py
# ══════════════════════════════════════════════════════════════════════════════

import streamlit as st
import os, sys
sys.path.insert(0, os.path.dirname(__file__))

st.set_page_config(
    page_title="Assistant Code de la Route Marocain",
    page_icon="🏛️",
    layout="wide"
)

# ── CSS personnalisé ──────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1a73e8, #34a853);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.5rem; font-weight: bold;
    }
    .response-box {
        background: #f8f9fa; border-left: 4px solid #1a73e8;
        padding: 15px; border-radius: 4px; margin: 10px 0;
    }
    .article-badge {
        background: #e8f0fe; color: #1a73e8;
        padding: 2px 8px; border-radius: 12px;
        font-size: 0.85rem; margin: 2px;
    }
    .ood-warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; }
</style>
""", unsafe_allow_html=True)

# ── En-tête ───────────────────────────────────────────────────────────────────
col1, col2 = st.columns([4, 1])
with col1:
    st.markdown('<p class="main-header">🏛️ Assistant Juridique</p>', unsafe_allow_html=True)
    st.markdown("**Code de la Route Marocain — Loi n° 52-05** | Master IASD, FST Tanger")
with col2:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/2/2c/Flag_of_Morocco.svg/200px-Flag_of_Morocco.svg.png",
             width=80)

st.divider()

# ── Barre latérale ────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")
    
    model_choice = st.selectbox(
        "🤖 Modèle LLM",
        ["gemini", "mistral-small-latest", "qwen-plus", "simulation"],
        index=3
    )
    top_k = st.slider("📄 Documents récupérés (top-k)", 1, 10, 5)
    show_docs = st.checkbox("Afficher les articles sources", value=True)
    show_scores = st.checkbox("Afficher les scores de similarité", value=False)
    
    st.divider()
    st.markdown("### 💡 Questions suggérées")
    suggested = [
        "Âge minimum permis catégorie B ?",
        "Amende conduite sans permis ?",
        "Points du permis probatoire ?",
        "Sanction alcool au volant ?",
        "Conditions contrôle technique ?",
    ]
    for s in suggested:
        if st.button(s, key=s, use_container_width=True):
            st.session_state["question"] = s

# ── Zone de question ──────────────────────────────────────────────────────────
question = st.text_area(
    "❓ Posez votre question sur le Code de la Route Marocain",
    value=st.session_state.get("question", ""),
    placeholder="Ex : Quelle est l'amende pour griller un feu rouge ?",
    height=100,
    key="question_input"
)

if st.button("🔍 Chercher", type="primary", use_container_width=True):
    if not question.strip():
        st.warning("⚠️ Veuillez entrer une question.")
    else:
        with st.spinner("🔄 Analyse en cours..."):
            # Appel au système RAG
            try:
                from rag_system import ask_legal_assistant
                result = ask_legal_assistant(question, llm_name=model_choice,
                                              top_k=top_k, verbose=False)
            except ImportError:
                result = {
                    "question"        : question,
                    "response"        : "[Importer le module rag_system.py]",
                    "docs"            : [],
                    "is_out_of_domain": False,
                }
        
        # ── Affichage du résultat ──────────────────────────────────────────────
        if result.get("is_out_of_domain"):
            st.markdown(
                f'<div class="ood-warning">🚫 <b>Question hors domaine</b><br>{result["ood_reason"]}</div>',
                unsafe_allow_html=True
            )
        
        st.markdown("### 💬 Réponse")
        st.markdown(
            f'<div class="response-box">{result["response"]}</div>',
            unsafe_allow_html=True
        )
        
        if show_docs and result["docs"]:
            st.markdown("### 📚 Articles sources")
            for doc in result["docs"]:
                score_str = f" (score: {doc['score']:.2f})" if show_scores else ""
                with st.expander(f"📄 {doc['article']} — {doc['titre']}{score_str}"):
                    st.write(doc["contenu"])

# ── Pied de page ──────────────────────────────────────────────────────────────
st.divider()
st.caption("🏛️ Basé sur la Loi n° 52-05 portant Code de la Route | Master IASD 2026 | FST Tanger")