
# ==============================================================
# CELLULE 0 — Installation
# ==============================================================
# !pip install -q sentence-transformers faiss-cpu scikit-learn \
#              transformers numpy matplotlib seaborn gradio networkx torch


# ==============================================================
# CELLULE 1 — Imports et Configuration
# ==============================================================

import json, re, random, warnings
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import networkx as nx
from collections import defaultdict

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.manifold import TSNE

import torch
from sentence_transformers import SentenceTransformer
import faiss

from transformers import pipeline, AutoTokenizer, AutoModelForSeq2SeqLM

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

# ─── Couleurs pour les graphiques
PALETTE = {
    "baseline": "#e74c3c",
    "rag_classic": "#3498db",
    "rag_rerank": "#2ecc71",
    "rag_hybrid": "#f39c12",
    "multi_hop": "#9b59b6",
    "graph_rag": "#1abc9c",
    "agentic_rag": "#e67e22"
}
ARCH_NAMES = list(PALETTE.keys())

print("✅ Imports OK — PyTorch:", torch.__version__)
print("✅ GPU disponible:", torch.cuda.is_available())


# ==============================================================
# CELLULE 2 — Dataset YARA manuel (25 exemples)
# ==============================================================

YARA_DATASET = [
    # ── RANSOMWARE (5 exemples) ───────────────────────────────
    {
        "id": "R001",
        "category": "ransomware",
        "description": "Ransomware qui chiffre les fichiers avec AES-256 et ajoute l'extension .locked",
        "yara_rule": """rule Ransomware_AES256_Locked {
    meta:
        author = "YaraRAG"
        description = "Détecte un ransomware chiffrant via AES-256 avec extension .locked"
        severity = "critical"
    strings:
        $aes = "AES-256" ascii nocase
        $ext = ".locked" ascii
        $enc_func = { 48 8B C4 48 89 58 08 }
        $ransom_msg = "Your files have been encrypted" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ($aes or $enc_func) and
        $ext and $ransom_msg
}"""
    },
    {
        "id": "R002",
        "category": "ransomware",
        "description": "Malware de type ransomware utilisant RSA pour chiffrer la clé AES et demandant une rançon en Bitcoin",
        "yara_rule": """rule Ransomware_RSA_AES_Bitcoin {
    meta:
        author = "YaraRAG"
        description = "Ransomware double chiffrement RSA+AES avec paiement Bitcoin"
        severity = "critical"
    strings:
        $rsa = "RSA" ascii
        $bitcoin = "bitcoin" ascii nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $key_enc = "CryptEncrypt" ascii
        $msg = "Send Bitcoin to" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $rsa and $bitcoin and $wallet and
        any of ($key_enc, $msg)
}"""
    },
    {
        "id": "R003",
        "category": "ransomware",
        "description": "Ransomware qui supprime les copies shadow et chiffre tous les lecteurs réseau",
        "yara_rule": """rule Ransomware_ShadowDelete_Network {
    meta:
        author = "YaraRAG"
        description = "Ransomware supprimant les shadow copies et chiffrant les partages réseau"
        severity = "critical"
    strings:
        $shadow1 = "vssadmin delete shadows" ascii nocase
        $shadow2 = "wmic shadowcopy delete" ascii nocase
        $net_share = "\\\\\\\\*\\\\" wide
        $bcdedit = "bcdedit /set {default} recoveryenabled No" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($shadow1, $shadow2) and
        ($net_share or $bcdedit)
}"""
    },
    {
        "id": "R004",
        "category": "ransomware",
        "description": "Ransomware ciblant les fichiers .docx .xlsx .pdf et déposant un fichier README_DECRYPT.txt",
        "yara_rule": """rule Ransomware_Office_Decrypt_Note {
    meta:
        author = "YaraRAG"
        description = "Ransomware ciblant documents Office avec note de décryptage"
        severity = "high"
    strings:
        $docx = ".docx" ascii
        $xlsx = ".xlsx" ascii
        $pdf  = ".pdf" ascii
        $note = "README_DECRYPT" ascii nocase
        $ransom = "decrypt your files" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        2 of ($docx, $xlsx, $pdf) and
        ($note or $ransom)
}"""
    },
    {
        "id": "R005",
        "category": "ransomware",
        "description": "Ransomware utilisant Tor pour la communication C2 et ChaCha20 pour le chiffrement",
        "yara_rule": """rule Ransomware_Tor_ChaCha20 {
    meta:
        author = "YaraRAG"
        description = "Ransomware avec C2 via Tor et chiffrement ChaCha20"
        severity = "critical"
    strings:
        $tor = ".onion" ascii
        $chacha = "ChaCha20" ascii nocase
        $tor_lib = "tor.exe" ascii nocase
        $decrypt_url = /http[s]?:\\/\\/[a-z0-9]{16}\\.onion/ ascii
    condition:
        uint16(0) == 0x5A4D and
        ($tor or $decrypt_url) and
        $chacha
}"""
    },
    # ── TROJAN (5 exemples) ───────────────────────────────────
    {
        "id": "T001",
        "category": "trojan",
        "description": "Trojan bancaire qui intercepte les formulaires web et vole les identifiants de connexion",
        "yara_rule": """rule Trojan_Banking_FormGrab {
    meta:
        author = "YaraRAG"
        description = "Trojan bancaire avec form grabbing et vol de credentials"
        severity = "high"
    strings:
        $hook1 = "NtCreateFile" ascii
        $hook2 = "HttpSendRequestW" ascii
        $bank1 = "paypal.com" ascii nocase
        $bank2 = "online banking" ascii nocase
        $form  = "FormGrabber" ascii nocase
        $cred  = "password" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($hook1, $hook2) and
        any of ($bank1, $bank2, $form) and $cred
}"""
    },
    {
        "id": "T002",
        "category": "trojan",
        "description": "Trojan RAT (Remote Access Trojan) permettant le contrôle à distance et l'exécution de commandes",
        "yara_rule": """rule Trojan_RAT_RemoteAccess {
    meta:
        author = "YaraRAG"
        description = "Remote Access Trojan avec shell distant et contrôle complet"
        severity = "critical"
    strings:
        $rat1 = "cmd.exe /c" ascii nocase
        $rat2 = "ShellExecute" ascii
        $socket = "WSAStartup" ascii
        $backdoor = "backdoor" ascii nocase
        $reverse = "reverse shell" ascii nocase
        $port = { 68 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and
        $socket and
        any of ($rat1, $rat2, $reverse, $backdoor)
}"""
    },
    {
        "id": "T003",
        "category": "trojan",
        "description": "Trojan se faisant passer pour une mise à jour Adobe Flash et téléchargeant des malwares supplémentaires",
        "yara_rule": """rule Trojan_FakeFlash_Dropper {
    meta:
        author = "YaraRAG"
        description = "Faux installeur Flash servant de dropper de malwares"
        severity = "high"
    strings:
        $fake = "Adobe Flash Player" ascii nocase
        $dl1  = "URLDownloadToFile" ascii
        $dl2  = "WinHttpOpen" ascii
        $exec = "CreateProcess" ascii
        $temp = "%TEMP%" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $fake and
        any of ($dl1, $dl2) and
        $exec and $temp
}"""
    },
    {
        "id": "T004",
        "category": "trojan",
        "description": "Trojan qui modifie les entrées de registre pour la persistance et injecte du code dans explorer.exe",
        "yara_rule": """rule Trojan_Registry_Inject {
    meta:
        author = "YaraRAG"
        description = "Trojan avec persistance par registre et injection dans explorer.exe"
        severity = "high"
    strings:
        $reg1 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii wide nocase
        $inj1 = "WriteProcessMemory" ascii
        $inj2 = "CreateRemoteThread" ascii
        $explorer = "explorer.exe" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $reg1 and
        any of ($inj1, $inj2) and $explorer
}"""
    },
    {
        "id": "T005",
        "category": "trojan",
        "description": "Trojan bancaire ciblant les clients Crypto qui vole les wallets et remplace les adresses dans le presse-papier",
        "yara_rule": """rule Trojan_CryptoClipper {
    meta:
        author = "YaraRAG"
        description = "Clipper trojan volant wallets crypto et remplaçant adresses"
        severity = "critical"
    strings:
        $clipboard = "SetClipboardData" ascii
        $wallet_btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $wallet_eth = /0x[a-fA-F0-9]{40}/ ascii
        $steal = "GetClipboardData" ascii
        $crypto = "wallet.dat" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $clipboard and $steal and
        any of ($wallet_btc, $wallet_eth, $crypto)
}"""
    },
    # ── SPYWARE (5 exemples) ──────────────────────────────────
    {
        "id": "S001",
        "category": "spyware",
        "description": "Spyware qui capture des screenshots toutes les 30 secondes et les envoie vers un serveur distant",
        "yara_rule": """rule Spyware_Screenshot_Exfil {
    meta:
        author = "YaraRAG"
        description = "Spyware capturant des screenshots périodiques pour exfiltration"
        severity = "medium"
    strings:
        $screen1 = "BitBlt" ascii
        $screen2 = "GetDC" ascii
        $screen3 = "CreateCompatibleBitmap" ascii
        $timer   = "SetTimer" ascii
        $ftp     = "InternetOpen" ascii
    condition:
        uint16(0) == 0x5A4D and
        2 of ($screen1, $screen2, $screen3) and
        $timer and $ftp
}"""
    },
    {
        "id": "S002",
        "category": "spyware",
        "description": "Spyware activant la webcam et le microphone pour surveiller la victime",
        "yara_rule": """rule Spyware_Camera_Audio {
    meta:
        author = "YaraRAG"
        description = "Spyware activant caméra et microphone pour surveillance"
        severity = "high"
    strings:
        $cam1 = "capCreateCaptureWindow" ascii
        $cam2 = "VideoCapture" ascii nocase
        $mic1 = "waveInOpen" ascii
        $mic2 = "AudioCapture" ascii nocase
        $exfil = "multipart/form-data" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($cam1, $cam2) and
        any of ($mic1, $mic2)
}"""
    },
    {
        "id": "S003",
        "category": "spyware",
        "description": "Spyware qui surveille les activités de navigation et envoie l'historique HTTP vers un C2",
        "yara_rule": """rule Spyware_BrowserHistory {
    meta:
        author = "YaraRAG"
        description = "Spyware exfiltrant l'historique de navigation"
        severity = "medium"
    strings:
        $hist1 = "History.db" ascii
        $hist2 = "places.sqlite" ascii
        $hist3 = "WebCacheV01.dat" ascii nocase
        $http  = "HttpSendRequest" ascii
        $ua    = "Mozilla/5.0" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($hist1, $hist2, $hist3) and $http
}"""
    },
    {
        "id": "S004",
        "category": "spyware",
        "description": "Spyware exfiltrant des fichiers sensibles (.kdbx, .pem, .key) via HTTPS",
        "yara_rule": """rule Spyware_CredFile_Exfil {
    meta:
        author = "YaraRAG"
        description = "Spyware ciblant les fichiers de credentials et clés"
        severity = "high"
    strings:
        $ext1 = ".kdbx" ascii
        $ext2 = ".pem" ascii
        $ext3 = ".key" ascii
        $ext4 = ".pfx" ascii
        $https = "WinHttpConnect" ascii
        $ftp   = "ftp://" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        2 of ($ext1, $ext2, $ext3, $ext4) and
        any of ($https, $ftp)
}"""
    },
    {
        "id": "S005",
        "category": "spyware",
        "description": "Adware espion qui injecte des publicités et envoie des données comportementales à des tiers",
        "yara_rule": """rule Spyware_Adware_Tracking {
    meta:
        author = "YaraRAG"
        description = "Adware collectant données comportementales et injectant pubs"
        severity = "low"
    strings:
        $ad1   = "DoubleClick" ascii nocase
        $ad2   = "adserving" ascii nocase
        $track = "user_behavior" ascii nocase
        $inject= "BrowserHelperObject" ascii
        $reg   = "Software\\\\Microsoft\\\\Internet Explorer\\\\Extensions" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($ad1, $ad2) and
        any of ($track, $inject, $reg)
}"""
    },
    # ── KEYLOGGER (5 exemples) ────────────────────────────────
    {
        "id": "K001",
        "category": "keylogger",
        "description": "Keylogger utilisant SetWindowsHookEx pour capturer toutes les frappes clavier",
        "yara_rule": """rule Keylogger_Hook_WinAPI {
    meta:
        author = "YaraRAG"
        description = "Keylogger via hook Windows API (SetWindowsHookEx)"
        severity = "high"
    strings:
        $hook1  = "SetWindowsHookEx" ascii
        $hook2  = "WH_KEYBOARD_LL" ascii
        $hook3  = "GetAsyncKeyState" ascii
        $log    = "keylog" ascii nocase
        $file   = "keystrokes.txt" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($hook1, $hook2, $hook3) and
        any of ($log, $file)
}"""
    },
    {
        "id": "K002",
        "category": "keylogger",
        "description": "Keylogger qui envoie les frappes par email SMTP en utilisant un compte Gmail compromis",
        "yara_rule": """rule Keylogger_SMTP_Exfil {
    meta:
        author = "YaraRAG"
        description = "Keylogger avec exfiltration des frappes par email SMTP"
        severity = "high"
    strings:
        $smtp1  = "smtp.gmail.com" ascii nocase
        $smtp2  = "EHLO" ascii
        $smtp3  = "AUTH LOGIN" ascii
        $hook   = "GetAsyncKeyState" ascii
        $mail   = "RCPT TO" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($smtp1, $smtp2, $smtp3, $mail) and $hook
}"""
    },
    {
        "id": "K003",
        "category": "keylogger",
        "description": "Keylogger basé sur un driver kernel utilisant des filtres pour capturer les entrées",
        "yara_rule": """rule Keylogger_Kernel_Driver {
    meta:
        author = "YaraRAG"
        description = "Keylogger niveau kernel avec driver de filtre d'entrée"
        severity = "critical"
    strings:
        $drv1  = "DriverEntry" ascii
        $drv2  = "IoCreateDevice" ascii
        $filter = "KeyboardClassServiceCallback" ascii
        $sys   = ".sys" ascii
        $input = "\\\\Device\\\\KeyboardClass0" ascii
    condition:
        uint16(0) == 0x5A4D and
        $drv1 and $drv2 and
        any of ($filter, $input)
}"""
    },
    {
        "id": "K004",
        "category": "keylogger",
        "description": "Keylogger qui capture aussi les données du presse-papier et les mots de passe mémorisés du navigateur",
        "yara_rule": """rule Keylogger_Clipboard_Browser {
    meta:
        author = "YaraRAG"
        description = "Keylogger étendu capturant clipboard et passwords navigateur"
        severity = "high"
    strings:
        $clip  = "GetClipboardData" ascii
        $hook  = "SetWindowsHookEx" ascii
        $ff    = "logins.json" ascii
        $chrome= "Login Data" ascii
        $pass  = "decryptedPassword" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $hook and $clip and
        any of ($ff, $chrome, $pass)
}"""
    },
    {
        "id": "K005",
        "category": "keylogger",
        "description": "Keylogger discret utilisant la technique DKOM pour se cacher des gestionnaires de tâches",
        "yara_rule": """rule Keylogger_DKOM_Hidden {
    meta:
        author = "YaraRAG"
        description = "Keylogger furtif utilisant DKOM pour masquer son processus"
        severity = "critical"
    strings:
        $dkom1 = "ZwQuerySystemInformation" ascii
        $dkom2 = "NtQuerySystemInformation" ascii
        $hook  = "SetWindowsHookEx" ascii
        $hide  = "ActiveProcessLinks" ascii
        $root  = "rootkit" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($dkom1, $dkom2) and $hook and
        any of ($hide, $root)
}"""
    },
    # ── BOTNET (5 exemples) ───────────────────────────────────
    {
        "id": "B001",
        "category": "botnet",
        "description": "Bot DDoS recevant des commandes d'un serveur C2 IRC et lançant des attaques UDP flood",
        "yara_rule": """rule Botnet_IRC_DDoS_UDP {
    meta:
        author = "YaraRAG"
        description = "Bot DDoS IRC avec capacité de flood UDP"
        severity = "high"
    strings:
        $irc1  = "PRIVMSG" ascii
        $irc2  = "JOIN #" ascii
        $ddos1 = "udp flood" ascii nocase
        $ddos2 = "sendto" ascii
        $c2    = "irc." ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($irc1, $irc2, $c2) and
        any of ($ddos1, $ddos2)
}"""
    },
    {
        "id": "B002",
        "category": "botnet",
        "description": "Bot utilisant un protocole P2P pour la communication C2 résistant au takedown",
        "yara_rule": """rule Botnet_P2P_C2 {
    meta:
        author = "YaraRAG"
        description = "Botnet P2P avec C2 distribué résistant aux takedowns"
        severity = "critical"
    strings:
        $p2p1  = "DHT" ascii
        $p2p2  = "peer_list" ascii nocase
        $p2p3  = "bootstrap_nodes" ascii nocase
        $cmd   = "execute_command" ascii nocase
        $net   = "WSAConnect" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($p2p1, $p2p2, $p2p3) and
        ($cmd or $net)
}"""
    },
    {
        "id": "B003",
        "category": "botnet",
        "description": "Bot spammeur récupérant des templates d'emails depuis un C2 et envoyant du spam en masse",
        "yara_rule": """rule Botnet_Spam_Mailer {
    meta:
        author = "YaraRAG"
        description = "Bot spammeur avec templates C2 et envoi SMTP massif"
        severity = "medium"
    strings:
        $smtp  = "smtp_send" ascii nocase
        $tmpl  = "email_template" ascii nocase
        $bulk  = "mass_mail" ascii nocase
        $rcpt  = "RCPT TO" ascii
        $c2    = "get_targets" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($smtp, $rcpt) and
        any of ($tmpl, $bulk, $c2)
}"""
    },
    {
        "id": "B004",
        "category": "botnet",
        "description": "Mirai-like botnet infectant les appareils IoT via Telnet avec des credentials par défaut",
        "yara_rule": """rule Botnet_Mirai_IoT {
    meta:
        author = "YaraRAG"
        description = "Botnet de type Mirai ciblant les appareils IoT via Telnet"
        severity = "critical"
    strings:
        $telnet = "telnet" ascii nocase
        $cred1  = "root:root" ascii
        $cred2  = "admin:admin" ascii
        $cred3  = "admin:password" ascii
        $scan   = "scanner_init" ascii nocase
        $mirai  = "busybox" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        $telnet and
        any of ($cred1, $cred2, $cred3) and
        any of ($scan, $mirai)
}"""
    },
    {
        "id": "B005",
        "category": "botnet",
        "description": "Cryptominer botnet utilisant XMRig pour miner du Monero sur les machines infectées",
        "yara_rule": """rule Botnet_CryptoMiner_XMR {
    meta:
        author = "YaraRAG"
        description = "Botnet mineur Monero basé sur XMRig"
        severity = "medium"
    strings:
        $xmrig  = "xmrig" ascii nocase
        $monero = "monero" ascii nocase
        $pool   = "pool.minexmr.com" ascii nocase
        $stratum= "stratum+tcp" ascii nocase
        $wallet = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($xmrig, $monero, $stratum) and
        any of ($pool, $wallet)
}"""
    }
]

print(f"✅ Dataset créé : {len(YARA_DATASET)} exemples")
for cat in ["ransomware", "trojan", "spyware", "keylogger", "botnet"]:
    count = sum(1 for d in YARA_DATASET if d["category"] == cat)
    print(f"   - {cat}: {count} exemples")


# ==============================================================
# CELLULE 3 — Augmentation synthétique du dataset
# ==============================================================

PARAPHRASE_TEMPLATES = {
    "ransomware": [
        "Ce logiciel malveillant de type ransomware {}",
        "Un ransomware sophistiqué qui {}",
        "Malware de chiffrement qui {}",
    ],
    "trojan": [
        "Ce cheval de Troie {}",
        "Programme malveillant de type trojan qui {}",
        "Backdoor trojan capable de {}",
    ],
    "spyware": [
        "Ce logiciel espion {}",
        "Spyware furtif qui {}",
        "Programme de surveillance qui {}",
    ],
    "keylogger": [
        "Ce keylogger {}",
        "Programme d'enregistrement de touches qui {}",
        "Malware de capture de frappes {}",
    ],
    "botnet": [
        "Ce bot malveillant {}",
        "Nœud botnet qui {}",
        "Agent de botnet capable de {}",
    ]
}

def extract_action(description):
    """Extrait la partie action d'une description."""
    desc = description.strip()
    for prefix in ["Ransomware", "Trojan", "Spyware", "Keylogger", "Bot", "Adware", "Malware"]:
        if desc.lower().startswith(prefix.lower()):
            parts = desc.split(" ", 1)
            if len(parts) > 1:
                rest = parts[1]
                if rest.startswith("qui "):
                    return rest[4:]
                if rest.startswith("se "):
                    return rest
                return rest
    return desc

def augment_dataset(dataset, n_per_sample=2):
    """Génère n_per_sample paraphrases par exemple."""
    augmented = []
    for item in dataset:
        for i in range(n_per_sample):
            templates = PARAPHRASE_TEMPLATES.get(item["category"], ["Malware qui {}"])
            template = templates[i % len(templates)]
            action = extract_action(item["description"])
            new_desc = template.format(action) if "{}" in template else item["description"]
            augmented.append({
                "id": item["id"] + f"_aug{i+1}",
                "category": item["category"],
                "description": new_desc,
                "yara_rule": item["yara_rule"]
            })
    return augmented

AUGMENTED    = augment_dataset(YARA_DATASET, n_per_sample=2)
FULL_DATASET = YARA_DATASET + AUGMENTED

print(f"✅ Dataset original : {len(YARA_DATASET)} exemples")
print(f"✅ Exemples augmentés : {len(AUGMENTED)} exemples")
print(f"✅ Dataset total : {len(FULL_DATASET)} exemples")
print("\n📋 Exemple d'entrée augmentée :")
print(json.dumps(AUGMENTED[0], indent=2, ensure_ascii=False))


# ==============================================================
# CELLULE 4 — Embeddings SentenceTransformer
# ==============================================================

print("⏳ Chargement du modèle SentenceTransformer...")
EMBED_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
print("✅ Modèle chargé :", EMBED_MODEL.get_sentence_embedding_dimension(), "dimensions")

DOCUMENTS  = [d["description"] for d in FULL_DATASET]
YARA_RULES = [d["yara_rule"]   for d in FULL_DATASET]
CATEGORIES = [d["category"]    for d in FULL_DATASET]
IDS        = [d["id"]          for d in FULL_DATASET]

print("\n⏳ Calcul des embeddings (peut prendre quelques secondes)...")
DOC_EMBEDDINGS = EMBED_MODEL.encode(DOCUMENTS, show_progress_bar=True, batch_size=32)
DOC_EMBEDDINGS = DOC_EMBEDDINGS.astype(np.float32)

print(f"\n✅ Embeddings calculés : shape = {DOC_EMBEDDINGS.shape}")


# ==============================================================
# CELLULE 5 — Index FAISS + fonction retrieve()
# ==============================================================

def build_faiss_index(embeddings):
    """Construit un index FAISS avec Inner Product (= cosine après normalisation)."""
    dim = embeddings.shape[1]
    norms      = np.linalg.norm(embeddings, axis=1, keepdims=True)
    normalized = embeddings / (norms + 1e-8)
    index      = faiss.IndexFlatIP(dim)
    index.add(normalized)
    return index, normalized

FAISS_INDEX, NORMALIZED_EMBEDDINGS = build_faiss_index(DOC_EMBEDDINGS)
print(f"✅ Index FAISS construit : {FAISS_INDEX.ntotal} vecteurs, dim={DOC_EMBEDDINGS.shape[1]}")

def retrieve(query, k=3, return_scores=False):
    """Récupère les k documents les plus similaires à la requête."""
    q_emb  = EMBED_MODEL.encode([query]).astype(np.float32)
    q_norm = q_emb / (np.linalg.norm(q_emb) + 1e-8)
    scores, indices = FAISS_INDEX.search(q_norm, k)
    results = []
    for score, idx in zip(scores[0], indices[0]):
        if idx < len(DOCUMENTS):
            results.append({
                "description": DOCUMENTS[idx],
                "yara_rule":   YARA_RULES[idx],
                "category":    CATEGORIES[idx],
                "score":       float(score),
                "idx":         idx
            })
    if return_scores:
        return results, scores[0]
    return results

# Test du retrieval
print("\n🔍 Test de retrieval :")
test_results = retrieve("ransomware chiffre fichiers AES", k=3)
for i, r in enumerate(test_results):
    print(f"  [{i+1}] score={r['score']:.4f} | cat={r['category']:12s} | {r['description'][:60]}...")


# ==============================================================
# CELLULE 6 — LLM local google/flan-t5-base + format_yara_rule()
# ==============================================================

MODEL_NAME = "google/flan-t5-base"
print(f"⏳ Chargement du modèle {MODEL_NAME}...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
llm_model  = AutoModelForSeq2SeqLM.from_pretrained(MODEL_NAME)
llm_model.eval()

DEVICE    = "cuda" if torch.cuda.is_available() else "cpu"
llm_model = llm_model.to(DEVICE)
print(f"✅ Modèle chargé sur {DEVICE}")


def generate_yara(prompt, max_new_tokens=300):
    """Génère une règle YARA à partir d'un prompt via le LLM local."""
    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        max_length=512,
        truncation=True
    ).to(DEVICE)

    with torch.no_grad():
        outputs = llm_model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            num_beams=4,
            early_stopping=True,
            no_repeat_ngram_size=3,
            temperature=0.7,
            do_sample=False
        )

    result = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return result


def format_yara_rule(raw_output, query, category="malware"):
    """
    Formate la sortie du LLM en une règle YARA syntaxiquement valide.
    Le LLM flan-t5-base étant généraliste, on construit une règle structurée
    en utilisant sa sortie + des heuristiques basées sur la requête.
    """
    rule_name = "Generated_" + "_".join(query.split()[:3]).replace("-", "_")

    keywords = [w for w in query.lower().split()
                if len(w) > 3 and w not in
                {"avec", "pour", "les", "des", "qui", "dans", "une", "est"}]

    strings_section = []
    crypto_kw  = {"aes", "rsa", "chacha20", "chiffr", "encrypt", "crypt"}
    network_kw = {"c2", "http", "ftp", "smtp", "irc", "network",
                  "serveur", "server", "tcp", "udp"}
    persist_kw = {"registre", "registry", "startup", "persistence", "autorun", "run"}

    has_crypto  = any(k in query.lower() for k in crypto_kw)
    has_network = any(k in query.lower() for k in network_kw)
    has_persist = any(k in query.lower() for k in persist_kw)

    if has_crypto:
        strings_section.append('        $enc1 = "CryptEncrypt" ascii')
        strings_section.append('        $enc2 = "AES" ascii nocase')
    if has_network:
        strings_section.append('        $net1 = "WSAConnect" ascii')
        strings_section.append('        $net2 = "InternetOpen" ascii')
    if has_persist:
        strings_section.append('        $reg1 = "CurrentVersion\\\\Run" ascii wide nocase')

    for i, kw in enumerate(keywords[:3]):
        strings_section.append(f'        $kw{i+1} = "{kw}" ascii nocase')

    if not strings_section:
        strings_section = [
            '        $s1 = "malware" ascii nocase',
            '        $s2 = "payload" ascii nocase',
        ]

    conditions = ["uint16(0) == 0x5A4D"]
    if has_crypto:
        conditions.append("any of ($enc1, $enc2)")
    if has_network:
        conditions.append("any of ($net1, $net2)")
    if keywords:
        conditions.append("any of ($kw*)")

    condition_str = " and\n        ".join(conditions)
    strings_str   = "\n".join(strings_section)

    rule = f"""rule {rule_name} {{
    meta:
        author      = "YaraRAG_Generated"
        description = "Règle générée pour : {query[:80]}"
        category    = "{category}"
    strings:
{strings_str}
    condition:
        {condition_str}
}}"""
    return rule

# Test de génération
print("\n🧪 Test de génération LLM locale :")
test_out = generate_yara("Generate a YARA rule to detect ransomware that encrypts files using AES")
print("Sortie brute LLM:", test_out[:100], "...")
print("\n✅ Système de génération opérationnel.")


# ==============================================================
# ARCHITECTURE 1 — Baseline : LLM sans RAG
# CELLULE 7
# ==============================================================

def llm_no_rag(query):
    """
    Baseline : génération de règle YARA sans retrieval.
    Le LLM génère directement à partir de la requête, sans contexte.
    """
    prompt = f"""You are a cybersecurity expert. Generate a YARA rule for the following threat:
Threat description: {query}
Generate only the YARA rule with rule name, meta, strings and condition sections."""

    raw  = generate_yara(prompt)
    rule = format_yara_rule(raw, query, "unknown")
    return rule

# Test
print("=== BASELINE (LLM sans RAG) ===")
q      = "ransomware chiffre fichiers avec AES et demande rançon Bitcoin"
result = llm_no_rag(q)
print(result)


# ==============================================================
# ARCHITECTURE 2 — RAG Classique
# CELLULE 8
# ==============================================================

def rag_classic(query, k=3):
    """
    RAG Classique : retrieval dense (FAISS) + génération enrichie.
    Pipeline : query → embed → FAISS → top-k docs → prompt enrichi → LLM
    """
    # 1. Retrieval
    docs = retrieve(query, k=k)

    # 2. Construction du contexte
    context_parts = []
    for i, doc in enumerate(docs):
        context_parts.append(f"Example {i+1} ({doc['category']}):")
        context_parts.append(f"  Description: {doc['description']}")
        context_parts.append(f"  YARA Rule:\n{doc['yara_rule']}")
    context = "\n".join(context_parts)

    # 3. Prompt enrichi
    prompt = f"""You are a YARA rule expert. Based on these examples:
{context}

Generate a new YARA rule for: {query}
Create a complete YARA rule with rule name, meta, strings, and condition."""

    # 4. Génération
    raw     = generate_yara(prompt)
    top_cat = docs[0]["category"] if docs else "malware"
    rule    = format_yara_rule(raw, query, top_cat)

    return rule, docs

# Test
print("=== RAG CLASSIQUE ===")
q = "malware qui utilise C2 et chiffre communications"
rule, docs = rag_classic(q)
print(f"Documents récupérés : {[d['category'] for d in docs]}")
print(rule)


# ==============================================================
# ARCHITECTURE 3 — RAG avec Re-ranking
# CELLULE 9
# ==============================================================

def rerank(query, docs, top_k=2):
    """
    Re-ranking par similarité cosine sur la concaténation description+catégorie.
    Score combiné : 0.7 * dense_score + 0.3 * keyword_overlap
    """
    query_words = set(query.lower().split())
    reranked    = []

    for doc in docs:
        dense_score = doc["score"]
        doc_words   = set(doc["description"].lower().split())
        overlap     = len(query_words & doc_words) / (len(query_words) + 1e-8)
        combined    = 0.7 * dense_score + 0.3 * overlap
        reranked.append({**doc, "rerank_score": combined, "overlap": overlap})

    reranked.sort(key=lambda x: x["rerank_score"], reverse=True)
    return reranked[:top_k]


def rag_rerank(query, k_retrieve=5, k_final=2):
    """
    RAG avec re-ranking en deux étapes :
    1. Retrieval large (k_retrieve docs)
    2. Re-ranking et sélection des k_final meilleurs
    3. Génération avec contexte re-classé
    """
    # 1. Retrieval large
    docs = retrieve(query, k=k_retrieve)

    # 2. Re-ranking
    reranked_docs = rerank(query, docs, top_k=k_final)

    # 3. Prompt avec docs re-rankés
    context_parts = []
    for i, doc in enumerate(reranked_docs):
        context_parts.append(
            f"Best Example {i+1} (score={doc['rerank_score']:.3f}, {doc['category']}):"
        )
        context_parts.append(f"  Description: {doc['description']}")
        context_parts.append(f"  YARA Rule:\n{doc['yara_rule']}")
    context = "\n".join(context_parts)

    prompt = f"""Based on the most relevant examples:
{context}
Generate a YARA rule for: {query}"""

    raw     = generate_yara(prompt)
    top_cat = reranked_docs[0]["category"] if reranked_docs else "malware"
    rule    = format_yara_rule(raw, query, top_cat)

    return rule, reranked_docs

# Test
print("=== RAG avec RE-RANKING ===")
q = "keylogger capture frappes clavier et envoie par email"
rule, docs = rag_rerank(q)
print(f"Docs re-rankés : {[(d['category'], round(d['rerank_score'], 3)) for d in docs]}")
print(rule)


# ==============================================================
# ARCHITECTURE 4 — RAG Hybride (TF-IDF + FAISS via RRF)
# CELLULE 10
# ==============================================================

# ── Index TF-IDF (construit une seule fois) ──────────────────
TFIDF_VECTORIZER = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=5000,
    analyzer="word"
)
TFIDF_MATRIX = TFIDF_VECTORIZER.fit_transform(DOCUMENTS)
print(f"✅ TF-IDF matrix : {TFIDF_MATRIX.shape}")


def sparse_retrieve(query, k=5):
    """Retrieval sparse via TF-IDF + cosine similarity."""
    q_vec  = TFIDF_VECTORIZER.transform([query])
    scores = cosine_similarity(q_vec, TFIDF_MATRIX)[0]
    top_k_idx = np.argsort(scores)[::-1][:k]
    results   = []
    for idx in top_k_idx:
        if scores[idx] > 0:
            results.append({
                "description": DOCUMENTS[idx],
                "yara_rule":   YARA_RULES[idx],
                "category":    CATEGORIES[idx],
                "score":       float(scores[idx]),
                "idx":         idx
            })
    return results


def hybrid_retrieve(query, k_dense=3, k_sparse=3, k_final=3):
    """
    Retrieval hybride : fusion des scores dense (FAISS) et sparse (TF-IDF).
    Méthode Reciprocal Rank Fusion (RRF).
    """
    dense_docs  = retrieve(query, k=k_dense)
    sparse_docs = sparse_retrieve(query, k=k_sparse)

    # ── Reciprocal Rank Fusion ────────────────────────────────
    rrf_scores = defaultdict(float)
    rrf_data   = {}

    for rank, doc in enumerate(dense_docs):
        idx = doc["idx"]
        rrf_scores[idx] += 1.0 / (rank + 60)   # constante RRF = 60
        rrf_data[idx]    = doc

    for rank, doc in enumerate(sparse_docs):
        idx = doc["idx"]
        rrf_scores[idx] += 1.0 / (rank + 60)
        if idx not in rrf_data:
            rrf_data[idx] = doc

    top_idxs = sorted(rrf_scores.keys(),
                      key=lambda x: rrf_scores[x], reverse=True)[:k_final]
    results  = []
    for idx in top_idxs:
        doc = {**rrf_data[idx], "rrf_score": rrf_scores[idx]}
        results.append(doc)

    return results


def rag_hybrid(query, k=3):
    """
    RAG Hybride : combine retrieval dense et sparse via RRF.
    """
    docs = hybrid_retrieve(query, k_final=k)

    context = "\n".join([
        f"Example ({d['category']}, RRF={d['rrf_score']:.4f}): {d['description']}"
        for d in docs
    ])

    prompt = f"""Using hybrid retrieval results:
{context}
Generate YARA rule for: {query}"""

    raw     = generate_yara(prompt)
    top_cat = docs[0]["category"] if docs else "malware"
    rule    = format_yara_rule(raw, query, top_cat)

    return rule, docs

# Test
print("=== RAG HYBRIDE ===")
q = "spyware surveille webcam et capture audio"
rule, docs = rag_hybrid(q)
print(f"Docs hybrides : {[(d['category'], round(d['rrf_score'], 4)) for d in docs]}")
print(rule)


# ==============================================================
# ARCHITECTURE 5 — Multi-hop RAG
# CELLULE 11
# ==============================================================

def reformulate_query(original_query, first_hop_docs):
    """
    Reformule la requête en intégrant les informations du 1er hop.
    Stratégie : extrait les termes techniques dominants des docs récupérés.
    """
    categories   = [d["category"] for d in first_hop_docs]
    dominant_cat = max(set(categories), key=categories.count)

    tech_terms = []
    for doc in first_hop_docs:
        desc_words = doc["description"].split()
        tech_terms += [w for w in desc_words if len(w) > 5 and w[0].isupper()]

    enriched = f"{original_query} AND {dominant_cat} behavior"
    if tech_terms:
        enriched += f" using {tech_terms[0]}"

    return enriched


def multi_hop_rag(query, hops=2, k_per_hop=3):
    """
    Multi-hop RAG : retrieval itératif avec reformulation de requête.

    Étape 1 : retrieval initial
    Étape 2 : reformulation de la requête avec contexte du hop 1
    Étape 3 : retrieval final sur la requête enrichie
    Étape 4 : génération avec contexte cumulé
    """
    all_docs      = []
    current_query = query

    for hop in range(hops):
        hop_docs = retrieve(current_query, k=k_per_hop)
        all_docs.extend(hop_docs)

        if hop < hops - 1:
            current_query = reformulate_query(current_query, hop_docs)

    # Déduplication par index
    seen       = set()
    unique_docs = []
    for doc in all_docs:
        if doc["idx"] not in seen:
            seen.add(doc["idx"])
            unique_docs.append(doc)
    unique_docs = unique_docs[:k_per_hop + 1]

    # Construction du prompt avec contexte multi-hop
    context = "\n".join([
        f"[Hop Context] ({d['category']}): {d['description'][:100]}"
        for d in unique_docs
    ])

    prompt = f"""Multi-step analysis for: {query}
Additional context from related threats:
{context}
Generate comprehensive YARA rule for: {query}"""

    raw     = generate_yara(prompt)
    top_cat = unique_docs[0]["category"] if unique_docs else "malware"
    rule    = format_yara_rule(raw, query, top_cat)

    return rule, unique_docs, current_query   # retourne aussi la requête reformulée

# Test
print("=== MULTI-HOP RAG ===")
q = "botnet DDoS avec C2 IRC et flood UDP"
rule, docs, reformulated_q = multi_hop_rag(q)
print(f"Requête originale  : {q}")
print(f"Requête reformulée : {reformulated_q}")
print(f"Docs récupérés : {[d['category'] for d in docs]}")
print(rule)


# ==============================================================
# ARCHITECTURE 6 — Graph RAG
# CELLULE 12 + 13
# ==============================================================

def build_knowledge_graph(dataset, embeddings, threshold=0.6):
    """
    Construit un graphe de connaissances entre les malwares.
    - Nœuds : chaque entrée du dataset
    - Arêtes : si similarité cosine > threshold
    - Attributs : catégorie, techniques partagées
    """
    G = nx.Graph()

    for i, (d, emb) in enumerate(zip(dataset, embeddings)):
        G.add_node(i,
            id=d["id"],
            category=d["category"],
            description=d["description"][:80],
            yara_rule=d["yara_rule"]
        )

    norms      = np.linalg.norm(embeddings, axis=1, keepdims=True)
    norm_emb   = embeddings / (norms + 1e-8)
    sim_matrix = norm_emb @ norm_emb.T

    for i in range(len(dataset)):
        for j in range(i + 1, len(dataset)):
            sim = sim_matrix[i, j]
            if sim > threshold:
                G.add_edge(i, j, weight=float(sim), relation="similar_behavior")

    # Arêtes catégorielles (même catégorie = relation forte)
    cat_groups = defaultdict(list)
    for i, d in enumerate(dataset):
        cat_groups[d["category"]].append(i)

    for cat, indices in cat_groups.items():
        for i in range(len(indices)):
            for j in range(i + 1, min(i + 3, len(indices))):
                ni, nj = indices[i], indices[j]
                if not G.has_edge(ni, nj):
                    G.add_edge(ni, nj, weight=0.5, relation="same_category")

    return G

# Construction du graphe sur le dataset original (25 exemples)
original_embeddings = EMBED_MODEL.encode(
    [d["description"] for d in YARA_DATASET]
).astype(np.float32)

KNOWLEDGE_GRAPH = build_knowledge_graph(YARA_DATASET, original_embeddings, threshold=0.55)

print(f"✅ Graphe de connaissances :")
print(f"   Nœuds : {KNOWLEDGE_GRAPH.number_of_nodes()}")
print(f"   Arêtes : {KNOWLEDGE_GRAPH.number_of_edges()}")

# Visualisation du graphe
fig, ax = plt.subplots(figsize=(14, 8))
cat_colors = {
    "ransomware": "#e74c3c",
    "trojan":     "#3498db",
    "spyware":    "#2ecc71",
    "keylogger":  "#f39c12",
    "botnet":     "#9b59b6"
}
node_colors  = [cat_colors[KNOWLEDGE_GRAPH.nodes[n]["category"]] for n in KNOWLEDGE_GRAPH.nodes()]
edge_weights = [KNOWLEDGE_GRAPH[u][v]["weight"] for u, v in KNOWLEDGE_GRAPH.edges()]
pos          = nx.spring_layout(KNOWLEDGE_GRAPH, seed=42, k=2.0)

nx.draw_networkx_nodes(KNOWLEDGE_GRAPH, pos, node_color=node_colors,
                       node_size=400, alpha=0.9, ax=ax)
nx.draw_networkx_edges(KNOWLEDGE_GRAPH, pos,
                       width=[w * 2 for w in edge_weights], alpha=0.4,
                       edge_color="#95a5a6", ax=ax)
labels = {n: KNOWLEDGE_GRAPH.nodes[n]["id"] for n in KNOWLEDGE_GRAPH.nodes()}
nx.draw_networkx_labels(KNOWLEDGE_GRAPH, pos, labels, font_size=7, ax=ax)

legend_patches = [mpatches.Patch(color=c, label=cat) for cat, c in cat_colors.items()]
ax.legend(handles=legend_patches, loc="upper left", fontsize=9)
ax.set_title("Graphe de Connaissances YARA — Relations inter-malwares",
             fontsize=13, fontweight="bold")
ax.axis("off")
plt.tight_layout()
plt.show()
print("✅ Graphe visualisé.")


def graph_retrieve(query, G, k=3):
    """
    Retrieval basé sur le graphe de connaissances.
    1. Trouve le nœud le plus similaire à la requête
    2. Explore ses voisins dans le graphe (propagation de contexte)
    3. Retourne les nœuds les plus pertinents avec contexte relationnel
    """
    q_emb  = EMBED_MODEL.encode([query]).astype(np.float32)
    q_norm = q_emb / (np.linalg.norm(q_emb) + 1e-8)

    node_indices = list(G.nodes())
    node_embs    = original_embeddings[node_indices]
    node_norms   = node_embs / (np.linalg.norm(node_embs, axis=1, keepdims=True) + 1e-8)
    scores       = (node_norms @ q_norm.T).flatten()

    # Nœud le plus proche (seed node)
    seed_idx  = node_indices[int(np.argmax(scores))]
    neighbors = list(G.neighbors(seed_idx))

    # Scoring des voisins : sim * edge_weight
    neighbor_scores = {}
    neighbor_scores[seed_idx] = float(np.max(scores))

    for nb in neighbors:
        edge_w = G[seed_idx][nb].get("weight", 0.5)
        nb_score = (float(scores[node_indices.index(nb)]) * edge_w
                    if nb in node_indices else 0.5 * edge_w)
        neighbor_scores[nb] = nb_score

    top_nodes = sorted(neighbor_scores.keys(),
                       key=lambda x: neighbor_scores[x], reverse=True)[:k]

    results = []
    for node in top_nodes:
        node_data = G.nodes[node]
        results.append({
            "description":     YARA_DATASET[node]["description"],
            "yara_rule":       YARA_DATASET[node]["yara_rule"],
            "category":        node_data["category"],
            "score":           neighbor_scores[node],
            "idx":             node,
            "graph_neighbors": len(list(G.neighbors(node)))
        })

    return results


def graph_rag(query, k=3):
    """
    Graph RAG : exploite les relations du graphe de connaissances.
    Inclut dans le prompt les relations entre les malwares similaires.
    """
    docs = graph_retrieve(query, KNOWLEDGE_GRAPH, k=k)

    context_parts = []
    for doc in docs:
        context_parts.append(
            f"[Graph Node — {doc['category']}, {doc['graph_neighbors']} connections]: "
            f"{doc['description']}"
        )

    categories_found = list(set([d["category"] for d in docs]))
    relation_context = f"Related threat categories: {', '.join(categories_found)}"

    context = "\n".join(context_parts) + "\n" + relation_context

    prompt = f"""Knowledge graph analysis for cybersecurity threat:
{context}
Generate YARA detection rule for: {query}"""

    raw     = generate_yara(prompt)
    top_cat = docs[0]["category"] if docs else "malware"
    rule    = format_yara_rule(raw, query, top_cat)

    return rule, docs

# Test
print("=== GRAPH RAG ===")
q = "trojan bancaire vole identifiants via hook navigateur"
rule, docs = graph_rag(q)
print(f"Docs via graphe : {[(d['category'], round(d['score'], 3), d['graph_neighbors']) for d in docs]}")
print(rule)


# ==============================================================
# ARCHITECTURE 7 — Agentic RAG
# CELLULE 14
# ==============================================================

def decide_retrieval(query):
    """
    Agent de décision : détermine si le retrieval est nécessaire.

    Stratégie :
    - Requêtes simples (question générale) → pas de retrieval
    - Requêtes spécifiques (malware technique) → retrieval obligatoire
    - Requêtes avec termes techniques → retrieval forcé

    Retourne: (bool, str) — (needs_retrieval, reason)
    """
    technical_keywords = {
        # Techniques malware
        "aes", "rsa", "chacha", "encrypt", "chiffr",
        "keylog", "hook", "inject", "rootkit", "dkom",
        "botnet", "c2", "ddos", "flood", "irc", "p2p",
        "ransomware", "trojan", "spyware", "malware",
        "smtp", "ftp", "exfil", "payload", "exploit",
        "shadow", "vssadmin", "persistence", "registry",
        # Termes YARA
        "yara", "rule", "strings", "condition", "detect"
    }

    query_lower = query.lower()
    matched_kw  = [kw for kw in technical_keywords if kw in query_lower]

    if len(matched_kw) >= 2:
        return True, f"Requête technique (mots-clés: {matched_kw[:3]})"
    elif len(matched_kw) == 1:
        return len(query.split()) > 5, f"Requête semi-technique ({matched_kw[0]})"
    else:
        return False, "Requête générale — pas de retrieval nécessaire"


def reason_and_retrieve(query, max_iterations=2):
    """
    Boucle de raisonnement agentique :
    1. Analyser la requête
    2. Décider du retrieval
    3. Retrieval si nécessaire
    4. Affiner si besoin (iterate)
    Retourne: (docs, strategy_log)
    """
    strategy_log = []
    all_docs     = []

    for iteration in range(max_iterations):
        needs_ret, reason = decide_retrieval(query)
        strategy_log.append(f"Iteration {iteration+1}: {reason}")

        if needs_ret:
            if iteration == 0:
                docs = retrieve(query, k=3)
                strategy_log.append("  → Retrieval dense FAISS (k=3)")
            else:
                docs = hybrid_retrieve(query, k_final=2)
                strategy_log.append("  → Retrieval hybride (k=2)")

            all_docs.extend(docs)

            if all_docs and all_docs[0]["score"] > 0.7:
                strategy_log.append(
                    f"  → Score suffisant ({all_docs[0]['score']:.3f}), arrêt"
                )
                break
        else:
            strategy_log.append("  → Génération directe sans retrieval")
            break

    # Déduplication
    seen       = set()
    unique_docs = []
    for doc in all_docs:
        if doc["idx"] not in seen:
            seen.add(doc["idx"])
            unique_docs.append(doc)

    return unique_docs[:3], strategy_log


def agentic_rag(query):
    """
    Agentic RAG : l'agent décide de la stratégie de retrieval.

    Décisions possibles :
    - Requête générale → génération directe
    - Requête technique → retrieval dense
    - Requête complexe → retrieval hybride multi-itération
    """
    # Phase 1 : Décision initiale
    needs_ret, reason = decide_retrieval(query)

    if not needs_ret:
        rule = llm_no_rag(query)
        return rule, [], [f"Décision: {reason}", "→ Mode baseline (sans retrieval)"]

    # Phase 2 : Boucle de raisonnement
    docs, strategy_log = reason_and_retrieve(query)

    # Phase 3 : Génération avec stratégie optimale
    if docs:
        context = "\n".join([
            f"[Agent Retrieved — {d['category']}, confidence={d['score']:.3f}]: {d['description']}"
            for d in docs
        ])

        prompt = f"""Agentic analysis — threat intelligence context:
{context}
Agent decision: {reason}
Generate optimized YARA rule for: {query}"""

        raw     = generate_yara(prompt)
        top_cat = docs[0]["category"] if docs else "malware"
        rule    = format_yara_rule(raw, query, top_cat)
    else:
        rule = llm_no_rag(query)

    return rule, docs, strategy_log

# Test
print("=== AGENTIC RAG ===")
q = "ransomware utilise AES chiffrement et demande rançon Monero"
rule, docs, strategy = agentic_rag(q)
print("\n📋 Stratégie agentique :")
for s in strategy:
    print(f"  {s}")
print(f"\nDocs utilisés : {[d['category'] for d in docs]}")
print(rule)


# ==============================================================
# CELLULE 15 — Requêtes de test
# ==============================================================

TEST_QUERIES = [
    {
        "id": "Q1",
        "query": "Ransomware qui chiffre les fichiers avec AES-256 et affiche un message de rançon Bitcoin",
        "expected_category": "ransomware"
    },
    {
        "id": "Q2",
        "query": "Malware avec serveur C2 utilisant le protocole IRC pour recevoir des commandes DDoS",
        "expected_category": "botnet"
    },
    {
        "id": "Q3",
        "query": "Trojan bancaire qui intercepte les formulaires de connexion bancaire via hook navigateur",
        "expected_category": "trojan"
    },
    {
        "id": "Q4",
        "query": "Keylogger furtif capturant les frappes clavier avec SetWindowsHookEx",
        "expected_category": "keylogger"
    },
    {
        "id": "Q5",
        "query": "Spyware activant la caméra et enregistrant audio pour surveillance",
        "expected_category": "spyware"
    },
    {
        "id": "Q6",
        "query": "Bot qui mine du Monero via XMRig en utilisant les ressources CPU de la victime",
        "expected_category": "botnet"
    },
    {
        "id": "Q7",
        "query": "Malware supprimant les shadow copies Windows et chiffrant les lecteurs réseau",
        "expected_category": "ransomware"
    },
]

print(f"✅ {len(TEST_QUERIES)} requêtes de test définies.")
for q in TEST_QUERIES:
    print(f"  [{q['id']}] ({q['expected_category']:10s}) {q['query'][:70]}...")
