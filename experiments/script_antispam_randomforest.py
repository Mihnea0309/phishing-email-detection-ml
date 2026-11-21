import os
import email
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import re
import time
import requests
import base64
import json
import shap
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
from scipy.sparse import hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, ConfusionMatrixDisplay
from sklearn.model_selection import GridSearchCV
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

dataset_dir = r"C:\Users\mihne\Desktop\facultate\proiect licenta\Dataset"

dataset_folders = {
    'easy_ham': 0,
    "easy_ham_2": 0,
    "hard_ham": 0,
    "spam" : 1,
    "spam_2" : 1,
    #"spam_github": 1,
}

vt_api_key = "1c6cbea2f85c60665c1e84f7e4db022c355908e161d6f63c19f5807690779daf"
abuse_api_key = "b9e2dc0e0d65df15d6ed39e224049e32446c824d83bce6b98b6ddbb4351e441ff507fd6da70cd1bb"

CACHE_FILE = "../src/threat_intel_cache.json"

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            data = json.load(f)
            # Ne asiguram ca structura veche primeste si suport pentru fisiere
            if "files" not in data:
                data["files"] = {}
            return data
    return {"urls": {}, "domains": {}, "ips": {}, "files": {}}

def save_cache(cache_data):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache_data, f, indent=4)

# Incarcam cache-ul la pornirea scriptului
threat_cache = load_cache()

# ==========================================
# SISTEM DE BLACKLIST PERSONALIZAT
# ==========================================
BLACKLIST_FILE = "../src/blacklist.json"


def load_blacklist():
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r') as f:
            return json.load(f)
    # Dacă fișierul nu există, îl creăm cu câteva exemple demonstrative
    default_blacklist = {
        "emails": ["attacker@malicious-domain.com", "invoice@scam-paypal.net"],
        "domains": ["phishingsite.org", "verify-security-login.xyz", "badattacker.com"]
    }
    with open(BLACKLIST_FILE, 'w') as f:
        json.dump(default_blacklist, f, indent=4)
    return default_blacklist


# Încărcăm blacklist-ul la pornirea scriptului
blacklist_data = load_blacklist()


def check_blacklist(sender_string):
    """Verifică dacă e-mailul sau domeniul expeditorului se află în blacklist"""
    sender_string = sender_string.lower()

    # 1. Extragem doar adresa curată de e-mail (ex: din 'Nume <test@domeniu.com>' extragem 'test@domeniu.com')
    email_match = re.search(r'[\w.-]+@[\w.-]+', sender_string)
    clean_email = email_match.group(0) if email_match else ""

    # 2. Extragem domeniul
    domain_match = re.search(r'@([\w.-]+)', sender_string)
    clean_domain = domain_match.group(1).replace('>', '').replace('<', '').strip() if domain_match else ""

    if clean_email in blacklist_data["emails"]:
        return True, f"Adresa de e-mail [{clean_email}] se află în Blacklist-ul personalizat."
    if clean_domain in blacklist_data["domains"]:
        return True, f"Domeniul [{clean_domain}] se află în Blacklist-ul personalizat."

    return False, ""


# ==========================================
# SISTEM DE GEO-FENCING (BLOCARE LIMBI ASIATICE)
# ==========================================
def check_suspicious_language(text, threshold=0.05):
    """
    Scanează textul pentru caractere din afara alfabetului latin (ex: Asiatice).
    Dacă ponderea lor depășește pragul (implicit 5%), returnează True.
    """
    if not text:
        return False, ""

    # 1. Eliminăm spațiile albe pentru a calcula procentul strict din caracterele vizibile
    clean_text = re.sub(r'\s+', '', text)
    if len(clean_text) < 10:  # Ignorăm textele prea scurte pentru a evita alarme false
        return False, ""

    # 2. Expresie regulată bazată pe blocuri Unicode:
    # \u4e00-\u9fff : CJK (Ideograme Chinezești)
    # \u3040-\u309f : Hiragana (Japonia)
    # \u30a0-\u30ff : Katakana (Japonia)
    # \uac00-\ud7af : Hangul (Coreea)
    # (Opțional, poți adăuga \u0400-\u04ff pentru alfabetul Chirilic / Rusesc)

    asian_chars = re.findall(r'[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]', clean_text)

    # 3. Calculăm procentul
    ratio = len(asian_chars) / len(clean_text)

    if ratio > threshold:
        return True, f"S-a detectat un procent anormal de caractere asiatice ({ratio:.1%}). Pragul maxim permis este {threshold:.1%}."

    return False, ""

def check_url(url):
    if not vt_api_key: return 0

    # 1. Verificare in Cache
    if url in threat_cache["urls"]:
        print(f"[CACHE HIT] URL deja scanat anterior: {url}")
        return threat_cache["urls"][url]

    # 2. Daca nu e in cache, facem request la API
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": vt_api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            score = stats['malicious'] + stats['suspicious']
            print(f"[API HIT] URL scanat la VT: {url} (Scor malicios: {score})")

            # 3. Salvare in Cache pentru viitor
            threat_cache["urls"][url] = score
            save_cache(threat_cache)

            return score
        else:
            print(f"Eroare VT URL: {response.status_code} - {response.text[:50]}")

    except Exception as e:
        print(f"Eroare: {e}")
    return 0


def check_domain(domain):
    if not vt_api_key: return 0

    if domain in threat_cache["domains"]:
        print(f"[CACHE HIT] Domeniu deja scanat anterior: {domain}")
        return threat_cache["domains"][domain]

    try:
        headers = {"x-apikey": vt_api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=10)

        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            score = stats['malicious'] + stats['suspicious']
            print(f"[API HIT] Domeniu scanat la VT ({domain}). Scor: {score}")

            threat_cache["domains"][domain] = score
            save_cache(threat_cache)

            return score
        else:
            print(f"Eroare VT Domeniu: {response.status_code} - {response.text[:50]}")

    except Exception as e:
        print(f"Eroare: {e}")
    return 0


def check_ip_abuse(ip):
    if not abuse_api_key: return 0

    if ip in threat_cache["ips"]:
        print(f"[CACHE HIT] IP deja scanat anterior: {ip}")
        return threat_cache["ips"][ip]

    try:
        headers = {"Key": abuse_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            score = response.json()['data']['abuseConfidenceScore']
            print(f"[API HIT] IP scanat la AbuseIPDB: {ip}. Scor: {score}")

            threat_cache["ips"][ip] = score
            save_cache(threat_cache)

            return score
        else:
            print(f"Eroare AbuseIPDB: {response.status_code} - {response.text[:50]}")

    except Exception as e:
        print(f"Eroare: {e}")
    return 0

def check_file_hash(file_hash):
    if not vt_api_key: return 0

    if "files" not in threat_cache:
        threat_cache["files"] = {}

    # 1. Verificare in Cache
    if file_hash in threat_cache["files"]:
        print(f"[CACHE HIT] Hash atasament deja scanat anterior: {file_hash}")
        return threat_cache["files"][file_hash]

    # 2. Interogare API VirusTotal pentru fisiere
    try:
        headers = {"x-apikey": vt_api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=10)

        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            score = stats['malicious'] + stats['suspicious']
            print(f"[API HIT] Hash atasament scanat la VT. Scor malicios: {score}")

            threat_cache["files"][file_hash] = score
            save_cache(threat_cache)
            return score
        elif response.status_code == 404:
            # Daca VT returneaza 404, inseamna ca fisierul nu a mai fost vazut/raportat ca periculos niciodata (e curat)
            print(f"[API HIT] Hash atasament: {file_hash} -> Nu a fost gasit pe VT (Verdict: Curat/Necunoscut).")
            threat_cache["files"][file_hash] = 0
            save_cache(threat_cache)
            return 0
        else:
            print(f"Eroare VT Files: {response.status_code} - {response.text[:50]}")

    except Exception as e:
        print(f"Eroare la verificarea hash-ului: {e}")
    return 0


def extract_features(filepath):
    try:
        with open(filepath, 'r', encoding='latin-1') as f:
            content = f.read()

        msg = email.message_from_string(content)
        header_features = {}
        attachment_hashes = []  # Aici vom stoca dictionare cu {'filename': ..., 'hash': ...}

        received = msg.get_all('Received')
        header_features['count_received'] = len(received) if received else 0

        def get_domain(email_string):
            if not email_string:
                return ""
            match = re.search(r'@([\w.-]+)', email_string)
            return match.group(1) if match else ""

        return_path = msg.get('Return-Path', '')
        sender = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        cc = msg.get('Cc', '')

        domain_return = get_domain(return_path)
        domain_sender = get_domain(sender)
        domain_reply = get_domain(reply_to)

        if domain_return and domain_sender and (domain_return == domain_sender):
            header_features['domain_match'] = 1
        else:
            header_features['domain_match'] = 0

        if reply_to:
            if domain_reply == domain_sender:
                header_features['reply_to_match'] = 1
            else:
                header_features['reply_to_match'] = 0
        else:
            header_features['reply_to_match'] = 1

        if cc and domain_sender in cc.lower():
            header_features['sender_domain_in_cc'] = 1
        else:
            header_features['sender_domain_in_cc'] = 0

        subject = msg.get('Subject', '')
        header_features['subject_length'] = len(subject)
        header_features['subject_caps'] = sum(1 for c in subject if c.isupper())

        auth_results = msg.get_all('Authentication-Results', [])
        received_spf = msg.get_all('Received-SPF', [])
        auth_headers_combined = " ".join([str(h).lower() for h in auth_results + received_spf])

        if re.search(r'spf=(fail|softfail|none)', auth_headers_combined):
            header_features['auth_spf_fail'] = 1
        else:
            header_features['auth_spf_fail'] = 0

        if re.search(r'dkim=(fail|none)', auth_headers_combined):
            header_features['auth_dkim_fail'] = 1
        else:
            header_features['auth_dkim_fail'] = 0

        if re.search(r'dmarc=(fail|none)', auth_headers_combined):
            header_features['auth_dmarc_fail'] = 1
        else:
            header_features['auth_dmarc_fail'] = 0

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                # ---------------------------------------------------------
                # NOU: DETECTARE ȘI PROCESARE FIȘIERE ATAȘATE
                # ---------------------------------------------------------
                content_disposition = part.get('Content-Disposition', '')
                filename = part.get_filename()

                # Daca piesa curenta este marcata ca atasament sau are un nume de fisier
                if 'attachment' in str(content_disposition).lower() or filename:
                    payload = part.get_payload(decode=True)
                    if payload:
                        import hashlib
                        file_hash = hashlib.md5(payload).hexdigest()
                        attachment_hashes.append({
                            'filename': filename if filename else "fisier_necunoscut",
                            'hash': file_hash
                        })
                # ---------------------------------------------------------

                if part.get_content_maintype() == 'text/plain' and not body:
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body = payload.decode('latin-1', errors='ignore')
                        except:
                            pass
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    body = payload.decode('latin-1', errors='ignore')
                except:
                    pass

        text = f"{subject} {body}"
        return text, header_features, attachment_hashes  # Returnam si lista de hash-uri

    except Exception as e:
        print(f"Eroare la fisierul {filepath}: {e}")
        return None, None, []


def plot_confusion_matrix(y_true, y_pred, title, filename):
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(8,6))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Safe Email', 'Phishing/Spam'])
    disp.plot(cmap=plt.cm.Blues, ax=ax, values_format='d')
    plt.title(title, fontsize=14, pad=20)
    plt.xlabel('Eticheta Prezisa', fontsize=12)
    plt.ylabel('Eticheta Reala', fontsize=12)
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.show()

def plot_feature_importance(model, feature_names, filename):
    importances = model.feature_importances_
    indices = np.argsort(importances)[-15:]

    plt.figure(figsize=(10,8))
    plt.title('Top 15 Caracteristici', fontsize=14)
    plt.barh(range(len(indices)), importances[indices], color='teal', align='center')
    plt.yticks(range(len(indices)), [feature_names[i] for i in indices])
    plt.xlabel('Importanta Relativa')
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.show()

print("Se citesc datele din foldere")
texts = []
numerical_data = []
labels = []
file_paths = []

for folder, label in dataset_folders.items():
    folder_path = os.path.join(dataset_dir, folder)

    if not os.path.exists(folder_path):
        print(f"Folderul '{folder}' nu exista. Trec peste")
        continue

    print(f"Incarcare '{folder}' (Label: {label})")

    files = os.listdir(folder_path)
    for file in files:
        file_path = os.path.join(folder_path, file)
        if os.path.isfile(file_path) and not file.startswith('.'):
            text, headers, _ = extract_features(file_path)

            if text:
                texts.append(text)
                labels.append(label)
                numerical_data.append(list(headers.values()))
                file_paths.append(file_path)

print(f"\nTotal mail-uri incarcare cu succes: {len(labels)}")

def clean_and_group_text(text):
    text = text.lower()  # Transformăm totul în litere mici

    # Grupăm cuvintele similare: înlocuim 'href', 'url', 'http', 'www' cu 'link'
    text = re.sub(r'\b(href|url|http|https|www)\b', ' link ', text)

    # Opțional (dar recomandat): Eliminăm tag-urile HTML rămase (precum <div>, <font> etc.)
    # ATENȚIE: Facem asta DUPĂ ce am salvat 'href' transformându-l în 'link'
    text = re.sub(r'<[^>]+>', ' ', text)

    # Păstrăm doar literele (eliminăm numere, semne de punctuație ciudate etc.)
    text = re.sub(r'[^a-z]+', ' ', text)

    return text

print("Curat si normalizez textele (eliminare HTML, grupare cuvinte)...")
cleaned_texts = [clean_and_group_text(t) for t in texts]

# Adăugăm cuvintele noastre inutile peste cele standard din limba engleză
custom_stop_words = list(ENGLISH_STOP_WORDS) + [
    'font', 'size', 'wrote', 'listinfo', 'mailman', 'date', 'br', 'td', 'tr',
    'nbsp', 'face', 'width', 'height', 'align', 'div', 'span', 'color',
    'style', 'bgcolor', 'center', 'html', 'body', 'com' , 'org'
]

print("Vectorizez textul (TF_IDF)")
vectorizer = TfidfVectorizer(stop_words=custom_stop_words, max_features=3000)
# Folosim lista curățată în loc de 'texts'
X_text = vectorizer.fit_transform(cleaned_texts)

X_headers = np.array(numerical_data)

print("combin caracteristicile")
X_final = hstack((X_text, X_headers))
y = np.array(labels)

tfidf_feature_names = vectorizer.get_feature_names_out()
header_feature_names = [
    'count_received', 'domain_match', 'reply_to_match',
    'sender_domain_in_cc', 'subject_length', 'subject_caps',
    'auth_spf_fail', 'auth_dkim_fail', 'auth_dmarc_fail'
]
all_feature_names = np.concatenate([tfidf_feature_names, header_feature_names])

X_train, X_test, y_train, y_test, paths_train, paths_test = train_test_split(X_final, y, file_paths, test_size = 0.2, random_state = 42)

print("\nOptimizare Random Forest")
print("Caut setarile optime")
param_grid = {
    'n_estimators': [100, 200],
    'max_depth': [None, 50, 100],
    'class_weight': ['balanced', 'balanced_subsample'],
}

rf_model = RandomForestClassifier(random_state=42, n_jobs=-1)
grid_search = GridSearchCV(estimator=rf_model, param_grid=param_grid, cv=3, scoring='f1_macro', n_jobs=-1)
grid_search.fit(X_train, y_train)

best_rf_model = grid_search.best_estimator_

print(f"Cei mai buni parametri sunt: {grid_search.best_params_}")

y_pred_rf = best_rf_model.predict(X_test)
print(f"Acuratete Random Forest Optimizat: {accuracy_score(y_test, y_pred_rf):.2%}")
print("Raport detaliat:")
print(classification_report(y_test, y_pred_rf, target_names=['Safe Email', 'Phishing/Spam']))

plot_confusion_matrix(y_test, y_pred_rf, 'Matrice de Confuzie Random Forest',
                      '../src/matricea_de_confuzie_random_forest.png')

print("Graficul de importanta a caracteristicilor:")
plot_feature_importance(best_rf_model, all_feature_names, '../results/importanta_caracteristici_rf.png')

y_probs = best_rf_model.predict_proba(X_test)[:,1]

low_bound = 0.4
high_bound = 0.6

uncertain_indices = np.where((y_probs >= low_bound) & (y_probs <= high_bound))[0]
uncertain_count = len(uncertain_indices)

print(f"\nProcesul Threat Inteligence")
y_pred_refined = y_pred_rf.copy()

for i, idx in enumerate(uncertain_indices):
    current_file = paths_test[idx]
    print(f"\n[{i + 1}/{uncertain_count}] Analiza hibridă pentru: {os.path.basename(current_file)}")

    # Citim fișierul pentru a extrage antetul From
    with open(current_file, 'r', encoding='latin-1') as f:
        msg = email.message_from_string(f.read())

    sender = msg.get('From', '')

    # ---------------------------------------------------------
    # NOU: INTERCEPȚIE PRIN BLACKLIST PERSONALIZAT
    # ---------------------------------------------------------
    is_blocked, reason = check_blacklist(sender)
    if is_blocked:
        print(f"⛔ [BLACKLIST HIT] -> {reason}")
        print("-> ALERTĂ: Blocat instant de regulile locale. Se marchează ca Phishing (1).")
        y_pred_refined[idx] = 1
        continue  # Sărim direct la următorul e-mail, fără a mai apela API-urile externe!
    # ---------------------------------------------------------

    # Dacă nu este în blacklist, procesul continuă normal cu restul verificărilor...
    raw_text, _, attachment_hashes = extract_features(current_file)

    # ---------------------------------------------------------
    # NOU: INTERCEPȚIE LIMBI/CARACTERE NEPERMISE (GEO-FENCING)
    # ---------------------------------------------------------
    is_foreign, lang_reason = check_suspicious_language(raw_text, threshold=0.05)
    if is_foreign:
        print(f"🌏 [GEO-BLOCK HIT] -> {lang_reason}")
        print("-> ALERTĂ: Blocat pe baza setului de caractere nepermis. Se marchează ca Phishing (1).")
        y_pred_refined[idx] = 1
        continue  # Sărim peste API-uri, am decis deja că e periculos!
    # ---------------------------------------------------------

    # --- 1. VERIFICARE URL-URI ---
    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', raw_text)
    found_url_threat = False

    for url in urls[:2]:
        # Verificam daca e deja in cache INAINTE de a apela functia
        is_cached = url in threat_cache["urls"]
        malicious_count = check_url(url)

        if malicious_count > 0:
            print(f"URL gasit: {url} ({malicious_count} raportari)")
            found_url_threat = True
            break

        # Punem pauza DOAR daca am interogat pe bune API-ul
        if not is_cached:
            time.sleep(15)

    # Citim din nou fisierul pentru a extrage headerele corect
    with open(current_file, 'r', encoding='latin-1') as f:
        msg = email.message_from_string(f.read())

    # --- 2. VERIFICARE DOMENIU EXPEDITOR ---
    found_domain_threat = False
    sender = msg.get('From', '')
    domain_match = re.search(r'@([\w.-]+)', sender)

    if domain_match:
        # Curatam domeniul de caractere extra precum '>'
        sender_domain = domain_match.group(1).replace('>', '').replace('<', '')
        domain_threat_count = check_domain(sender_domain)

        if domain_threat_count > 0:
            print(f"Domeniu malicios gasit: {sender_domain} ({domain_threat_count} raportari)")
            found_domain_threat = True
        time.sleep(15)  # Pauza necesara pentru limitarea API-ului VT

    # --- 3. VERIFICARE IP-URI ---
    found_ip_threat = False
    received_headers = msg.get_all('Received')
    ips = []
    if received_headers:
        for rh in received_headers:
            found = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(rh))
            ips.extend(found)

    public_ips = [ip for ip in ips if
                  not ip.startswith('127.') and not ip.startswith('192.168.') and not ip.startswith('10.')]

    if public_ips:
        target_ip = public_ips[-1]
        abuse_score = check_ip_abuse(target_ip)
        if abuse_score > 50:
            print(f"IP suspect: {target_ip} (Scor: {abuse_score})")
            found_ip_threat = True
    else:
        print("Nu s-a gasit IP public pentru verificare.")

    # --- 4. VERIFICARE ATAȘAMENTE (HASH VIRUSTOTAL) ---
    found_attachment_threat = False
    if attachment_hashes:
        print(f"📎 S-au gasit {len(attachment_hashes)} atasamente in e-mail. Se verifica integritatea...")
        for att in attachment_hashes:
            is_cached = att['hash'] in threat_cache.get("files", {})
            malicious_count = check_file_hash(att['hash'])

            if malicious_count > 0:
                print(
                    f"⚠️ ALERTĂ ATASAMENT: Fisierul [{att['filename']}] este MARCAT CA MALWARE pe VirusTotal ({malicious_count} raportari)!")
                found_attachment_threat = True
                break

            if not is_cached:
                time.sleep(15)  # Pauza necesara pentru limitarea API-ului VT

    # --- DECIZIA FINALA PENTRU MAIL-UL INCERT ---
    if found_ip_threat or found_url_threat or found_domain_threat or found_attachment_threat:
        print("-> ALERTĂ: Amenintare confirmata de API-uri externe. Se marcheaza ca Phishing (1).")
        y_pred_refined[idx] = 1
    else:
        print("-> Nicio amenintare gasita extern. Se pastreaza decizia modelului.")

print("Rezultate dupa API uri")
print(f"Noua acuratete: {accuracy_score(y_test, y_pred_refined):.2%}")
print(classification_report(y_test, y_pred_refined, target_names=['Safe Email', 'Phishing/Spam']))
plot_confusion_matrix(y_test, y_pred_refined, 'Matricea de Confuzie AI + API Random Forest',
                      '../results/matricea_de_confuzie_random_forest_API.png')

# ==========================================
# EXPLICABILITATEA MODELULUI (XAI) cu SHAP - TEXT
# ==========================================
print("\nGenerare explicabilitate model (SHAP) - Modul Textual...")

spam_indices = np.where(y_test == 1)[0]

if len(spam_indices) > 0:
    target_idx = spam_indices[0]

    # 1. Extragem datele
    instance_to_explain_2d = X_test[target_idx].toarray()

    # 2. Calculam valorile SHAP
    explainer = shap.TreeExplainer(best_rf_model)
    shap_values_output = explainer.shap_values(instance_to_explain_2d, check_additivity=False)

    if isinstance(shap_values_output, list):
        shap_vals_phishing = shap_values_output[1][0]
    else:
        shap_vals_phishing = shap_values_output[0, :, 1]

    # 3. CREAREA EXPLICATIEI TEXTUALE - PE INTELESUL TUTUROR
    impact_list = list(zip(all_feature_names, shap_vals_phishing))
    impact_list.sort(key=lambda x: x[1], reverse=True)

    print("\n" + "=" * 60)
    print("💡 DECIZIE AI EXPLICATA:")
    print(f"Fisier analizat: {os.path.basename(paths_test[target_idx])}")
    print("Sistemul a marcat acest mesaj ca PERICULOS (Phishing/Spam) din urmatoarele motive:\n")

    # Dictionar care traduce caracteristicile tehnice in limbaj normal
    explicatii_headere = {
        'count_received': "Traseu Suspect: E-mailul a fost rutat printr-un numar neobisnuit de servere, o tactica des folosita pentru a ascunde sursa reala a mesajului.",
        'domain_match': "Falsificarea Identitatii: Adresa vizibila a expeditorului a fost falsificata. In realitate, mesajul provine de la un cu totul alt domeniu.",
        'reply_to_match': "Redirectionare Suspecta: Daca incerci sa raspunzi la acest mesaj, raspunsul tau va fi redirectionat in secret catre alta adresa, diferita de cea a expeditorului.",
        'sender_domain_in_cc': "Distributie Ascunsa: Tiparul in care alte persoane au fost adaugate in copie (CC) este tipic campaniilor de mesaje nesolicitate.",
        'subject_length': "Titlu Atipic: Lungimea subiectului nu respecta formatul unei comunicari de afaceri legitime.",
        'subject_caps': "Limbaj Agresiv (Clickbait): Subiectul foloseste excesiv majuscule, o tactica psihologica pentru a capta atentia sau a crea falsa panica.",
        'auth_spf_fail': "Securitate Picata: Serverul care a trimis mesajul nu are autorizatia legala de a trimite mailuri din partea acelei companii.",
        'auth_dkim_fail': "Semnatura Invalida: Lipseste semnatura digitala care garanteaza ca textul e-mailului nu a fost modificat de hackeri pe traseu.",
        'auth_dmarc_fail': "Protectie Anti-Fraudă Picata: Mesajul a picat testele globale de securitate (DMARC) folosite de banci si corporatii pentru a preveni clonarea identitatii."
    }

    motiv_count = 1
    # Luam top 5 motive
    for feature_name, shap_impact in impact_list[:5]:
        if shap_impact > 0:  # Ne intereseaza doar ce a tras scorul in sus spre Phishing

            # Formatam textul in functie de tipul caracteristicii
            if feature_name in header_feature_names:
                explicatie = explicatii_headere.get(feature_name,
                                                    f"S-a detectat o anomalie tehnica de retea ({feature_name}).")
                print(f" {motiv_count}. [Structura Tehnica] -> {explicatie}")

            elif feature_name == "link":
                print(
                    f" {motiv_count}. [Continut] -> Prezenta unui numar exagerat de link-uri (tactica tipica pentru a atrage victimele catre site-uri false).")

            else:
                print(
                    f" {motiv_count}. [Analiza Text] -> Prezenta cuvantului de manipulare '{feature_name}' (des utilizat pentru a convinge, pacali sau promite castiguri).")

            motiv_count += 1

    print("=" * 60 + "\n")
else:
    print("Nu s-au gasit exemple de spam in setul de test pentru generarea SHAP.")

# ==========================================
# SALVAREA MODELULUI PENTRU INTERFAȚĂ
# ==========================================
print("\nSalvez modelul si vectorizatorul pe disk...")
joblib.dump(best_rf_model, '../src/phishing_rf_model.pkl')
joblib.dump(vectorizer, '../src/tfidf_vectorizer.pkl')
print("Fisierele '.pkl' au fost salvate cu succes! Scriptul de antrenare s-a incheiat.")

# print("\nAnaliza incertitudine (40%-60%)")
# print(f"Mail uri in setul de date: {len(y_test)}")
# print(f"Mail uri cu scor incert: {uncertain_count}")
# print(f"Procent din total test: {(uncertain_count / len(y_test)) * 100:.2f}%")

# nu prea imi plac rezultatele cu url urile astea brute, poate merge varianta cu
# a cauta numa url uri unde mail urile sunt in range ul 40-60 - solutie rezolvata
# pt caracteristici sa le fac eu manual? - next de facut
# poate daca email ul are atasamente reusesc sa iau hash ul atasamentului sa l bag pe VT
# pot sa adaug un blacklist personalizat cu adrese de mail + domenii
# cuvintele cheie care apar in mail uri, acelea din vectori/matrici, sa fie recunoscute in toate limbile
# as putea sa adaug in acel blacklist si o lista de limbi permise, spre ex excluderea oricarei limbi din asia