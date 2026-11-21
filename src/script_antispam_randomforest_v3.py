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
from sklearn.metrics import precision_recall_curve

dataset_dir = r"C:"

dataset_folders = {
    'easy_ham': 0,
    "easy_ham_2": 0,
    "hard_ham": 0,
    "ham_nou": 0,
    "spam" : 1,
    "spam_2" : 1,
    "spam_github": 1,
}

vt_api_key = ""
abuse_api_key = ""

CACHE_FILE = "threat_intel_cache.json"


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            data = json.load(f)
            if "files" not in data:
                data["files"] = {}
            return data
    return {"urls": {}, "domains": {}, "ips": {}, "files": {}}


def save_cache(cache_data):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache_data, f, indent=4)


threat_cache = load_cache()

BLACKLIST_FILE = "blacklist.json"


def load_blacklist():
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r') as f:
            return json.load(f)
    default_blacklist = {
        "emails": ["attacker@malicious-domain.com", "invoice@scam-paypal.net"],
        "domains": ["phishingsite.org", "verify-security-login.xyz", "badattacker.com"]
    }
    with open(BLACKLIST_FILE, 'w') as f:
        json.dump(default_blacklist, f, indent=4)
    return default_blacklist


blacklist_data = load_blacklist()


def check_blacklist(sender_string):
    sender_string = sender_string.lower()
    email_match = re.search(r'[\w.-]+@[\w.-]+', sender_string)
    clean_email = email_match.group(0) if email_match else ""

    domain_match = re.search(r'@([\w.-]+)', sender_string)
    clean_domain = domain_match.group(1).replace('>', '').replace('<', '').strip() if domain_match else ""

    if clean_email in blacklist_data["emails"]:
        return True, f"Adresa de e-mail [{clean_email}] se află în Blacklist-ul personalizat."
    if clean_domain in blacklist_data["domains"]:
        return True, f"Domeniul [{clean_domain}] se află în Blacklist-ul personalizat."

    return False, ""


def check_suspicious_language(text, threshold=0.05):
    if not text: return False, ""
    clean_text = re.sub(r'\s+', '', text)
    if len(clean_text) < 10: return False, ""
    asian_chars = re.findall(r'[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]', clean_text)
    ratio = len(asian_chars) / len(clean_text)

    if ratio > threshold:
        return True, f"S-a detectat un procent anormal de caractere asiatice ({ratio:.1%}). Pragul maxim permis este {threshold:.1%}."
    return False, ""


def check_url(url):
    if not vt_api_key: return 0
    if url in threat_cache["urls"]:
        print(f"[CACHE HIT] URL deja scanat anterior: {url}")
        return threat_cache["urls"][url]
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": vt_api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            score = stats['malicious'] + stats['suspicious']
            print(f"[API HIT] URL scanat la VT: {url} (Scor malicios: {score})")
            threat_cache["urls"][url] = score
            save_cache(threat_cache)
            return score
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
    except Exception as e:
        print(f"Eroare: {e}")
    return 0


def check_file_hash(file_hash):
    if not vt_api_key: return 0
    if "files" not in threat_cache: threat_cache["files"] = {}
    if file_hash in threat_cache["files"]:
        print(f"[CACHE HIT] Hash atasament deja scanat anterior: {file_hash}")
        return threat_cache["files"][file_hash]
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
            print(f"[API HIT] Hash atasament: {file_hash} -> Nu a fost gasit pe VT (Verdict: Curat/Necunoscut).")
            threat_cache["files"][file_hash] = 0
            save_cache(threat_cache)
            return 0
    except Exception as e:
        print(f"Eroare la verificarea hash-ului: {e}")
    return 0


def domains_related(d1, d2):
    if not d1 or not d2:
        return False
    root1 = '.'.join(d1.strip().lower().split('.')[-2:])
    root2 = '.'.join(d2.strip().lower().split('.')[-2:])
    return root1 == root2


def extract_features(filepath):
    try:
        with open(filepath, 'r', encoding='latin-1') as f:
            content = f.read()

        msg = email.message_from_string(content)
        header_features = {}
        attachment_hashes = []

        received = msg.get_all('Received')
        header_features['count_received'] = len(received) if received else 0

        def get_domain(email_string):
            if not email_string: return ""
            match = re.search(r'@([\w.-]+)', email_string)
            return match.group(1) if match else ""

        return_path = msg.get('Return-Path', '')
        sender = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        cc = msg.get('Cc', '')

        domain_return = get_domain(return_path)
        domain_sender = get_domain(sender)
        domain_reply = get_domain(reply_to)

        header_features['domain_match'] = 1 if domains_related(domain_return, domain_sender) else 0

        header_features['reply_to_match'] = 1 if not reply_to or domains_related(domain_reply, domain_sender) else 0

        header_features['sender_domain_in_cc'] = 1 if cc and domain_sender in cc.lower() else 0

        subject = msg.get('Subject', '')
        header_features['subject_length'] = len(subject)
        header_features['subject_caps'] = sum(1 for c in subject if c.isupper())

        auth_results = msg.get_all('Authentication-Results', [])
        received_spf = msg.get_all('Received-SPF', [])
        auth_headers = " ".join(
            [str(h).lower() for h in msg.get_all('Authentication-Results', []) + msg.get_all('Received-SPF', [])])

        header_features['auth_spf_fail'] = 0 if 'spf=pass' in auth_headers else (
            1 if re.search(r'spf=(fail|softfail|none)', auth_headers) else 0)
        header_features['auth_dkim_fail'] = 0 if 'dkim=pass' in auth_headers else (
            1 if re.search(r'dkim=(fail|none)', auth_headers) else 0)
        header_features['auth_dmarc_fail'] = 0 if 'dmarc=pass' in auth_headers else (
            1 if re.search(r'dmarc=(fail|none)', auth_headers) else 0)

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                cdisp = part.get('Content-Disposition', '')
                fname = part.get_filename()
                if 'attachment' in str(cdisp).lower() or fname:
                    payload = part.get_payload(decode=True)
                    if payload:
                        import hashlib
                        attachment_hashes.append({
                            'filename': fname if fname else "fisier_necunoscut",
                            'hash': hashlib.md5(payload).hexdigest()
                        })
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
        return text, header_features, attachment_hashes

    except Exception as e:
        print(f"Eroare la fisierul {filepath}: {e}")
        return None, None, []


def plot_confusion_matrix(y_true, y_pred, title, filename):
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(8, 6))
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
    plt.figure(figsize=(10, 8))
    plt.title('Top 15 Caracteristici', fontsize=14)
    plt.barh(range(len(indices)), importances[indices], color='teal', align='center')
    plt.yticks(range(len(indices)), [feature_names[i] for i in indices])
    plt.xlabel('Importanta Relativa')
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.show()


print("Se citesc datele din foldere")
texts, numerical_data, labels, file_paths = [], [], [], []

for folder, label in dataset_folders.items():
    folder_path = os.path.join(dataset_dir, folder)
    if not os.path.exists(folder_path):
        print(f"Folderul '{folder}' nu exista. Trec peste")
        continue

    print(f"Incarcare '{folder}' (Label: {label})")
    for file in os.listdir(folder_path):
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
    text = text.lower()
    text = re.sub(r'\b(href|url|http|https|www)\b', ' link ', text)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'[^a-z]+', ' ', text)
    return text


print("Curat si normalizez textele (eliminare HTML, grupare cuvinte)...")
cleaned_texts = [clean_and_group_text(t) for t in texts]

custom_stop_words = list(ENGLISH_STOP_WORDS) + [
    'font', 'size', 'wrote', 'listinfo', 'mailman', 'date', 'br', 'td', 'tr',
    'nbsp', 'face', 'width', 'height', 'align', 'div', 'span', 'color',
    'style', 'bgcolor', 'center', 'html', 'body', 'com', 'org'
]

print("Vectorizez textul (TF-IDF)")
vectorizer = TfidfVectorizer(
    stop_words=custom_stop_words,
    max_features=5000,
    min_df=3,
    max_df=0.85,
    ngram_range=(1, 2),
    sublinear_tf=True
)
X_text = vectorizer.fit_transform(cleaned_texts)
X_headers = np.array(numerical_data)

print("Combin caracteristicile...")
X_final = hstack((X_text, X_headers))
y = np.array(labels)

tfidf_feature_names = vectorizer.get_feature_names_out()
header_feature_names = [
    'count_received', 'domain_match', 'reply_to_match',
    'sender_domain_in_cc', 'subject_length', 'subject_caps',
    'auth_spf_fail', 'auth_dkim_fail', 'auth_dmarc_fail'
]
all_feature_names = np.concatenate([tfidf_feature_names, header_feature_names])

X_train, X_test, y_train, y_test, paths_train, paths_test = train_test_split(
    X_final, y, file_paths, test_size=0.2, random_state=42
)

print("\nOptimizare Random Forest...")
param_grid = {
    'n_estimators': [100, 200],
    'max_depth': [None, 50, 100],
    'class_weight': [{0: 1, 1: 1}, {0: 2, 1: 1}, {0: 3, 1: 1}],
}

rf_model = RandomForestClassifier(random_state=42, n_jobs=-1)
grid_search = GridSearchCV(estimator=rf_model, param_grid=param_grid, cv=3, scoring='f1_macro', n_jobs=-1)
grid_search.fit(X_train, y_train)

best_rf_model = grid_search.best_estimator_

print(f"Cei mai buni parametri sunt: {grid_search.best_params_}")

y_pred_rf = best_rf_model.predict(X_test)
y_probs = best_rf_model.predict_proba(X_test)[:, 1]

print(f"\nAcuratete Random Forest (threshold default 0.50): {accuracy_score(y_test, y_pred_rf):.2%}")
print("Raport detaliat (threshold 0.50):")
print(classification_report(y_test, y_pred_rf, target_names=['Safe Email', 'Phishing/Spam']))

print("\n" + "=" * 60)
print("CALIBRARE THRESHOLD OPTIM")
print("=" * 60)

precisions, recalls, thresholds = precision_recall_curve(y_test, y_probs)

best_threshold = 0.50
best_f1_macro = 0.0

print(f"\n{'Threshold':<12} {'F1-Macro':<12} {'Prec-Ham':<12} {'Recall-Ham':<12} {'Prec-Spam':<12} {'Recall-Spam'}")
print("-" * 72)

for thresh in np.arange(0.40, 0.76, 0.05):
    y_pred_thresh = (y_probs >= thresh).astype(int)

    report = classification_report(y_test, y_pred_thresh, target_names=['Ham', 'Spam'], output_dict=True,
                                   zero_division=0)

    f1_macro  = report['macro avg']['f1-score']
    prec_ham  = report['Ham']['precision']
    rec_ham   = report['Ham']['recall']
    prec_spam = report['Spam']['precision']
    rec_spam  = report['Spam']['recall']

    print(f"{thresh:<12.2f} {f1_macro:<12.4f} {prec_ham:<12.4f} {rec_ham:<12.4f} {prec_spam:<12.4f} {rec_spam:.4f}")

    if f1_macro > best_f1_macro and prec_ham >= 0.95:
        best_f1_macro = f1_macro
        best_threshold = thresh

print(f"\n>>> Threshold optim selectat automat: {best_threshold:.2f} (F1-Macro: {best_f1_macro:.4f})")
print("    (Criteriu: cel mai bun F1-Macro cu Precizie Ham >= 95%)\n")

y_pred_optimized = (y_probs >= best_threshold).astype(int)

print(f"Acuratete Random Forest (threshold optim {best_threshold:.2f}): {accuracy_score(y_test, y_pred_optimized):.2%}")
print(f"Raport detaliat (threshold {best_threshold:.2f}):")
print(classification_report(y_test, y_pred_optimized, target_names=['Safe Email', 'Phishing/Spam']))

joblib.dump(best_threshold, 'optimal_threshold.pkl')
print(f"Threshold optim salvat in 'optimal_threshold.pkl'")

plot_confusion_matrix(y_test, y_pred_rf,
                      'Matrice de Confuzie - Threshold Default (0.50)',
                      'matricea_de_confuzie_default.png')

plot_confusion_matrix(y_test, y_pred_optimized,
                      f'Matrice de Confuzie - Threshold Optim ({best_threshold:.2f})',
                      'matricea_de_confuzie_optimizat.png')

plot_feature_importance(best_rf_model, all_feature_names, '../results/importanta_caracteristici_rf.png')

uncertain_low  = max(0.30, best_threshold - 0.15)
uncertain_high = min(0.80, best_threshold + 0.15)

print(f"\nZona incerta pentru Threat Intelligence: [{uncertain_low:.2f} - {uncertain_high:.2f}]")
uncertain_indices = np.where((y_probs >= uncertain_low) & (y_probs <= uncertain_high))[0]
y_pred_refined = y_pred_optimized.copy()

print(f"Procesul Threat Intelligence pentru {len(uncertain_indices)} emailuri incerte...")

for i, idx in enumerate(uncertain_indices):
    current_file = paths_test[idx]

    with open(current_file, 'r', encoding='latin-1') as f:
        msg = email.message_from_string(f.read())
    sender = msg.get('From', '')

    is_blocked, reason = check_blacklist(sender)
    if is_blocked:
        y_pred_refined[idx] = 1
        continue

    raw_text, _, attachment_hashes = extract_features(current_file)

    is_foreign, lang_reason = check_suspicious_language(raw_text, threshold=0.05)
    if is_foreign:
        y_pred_refined[idx] = 1
        continue

    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', raw_text)
    found_threat = False

    for url in urls[:2]:
        is_cached = url in threat_cache["urls"]
        if check_url(url) > 0:
            found_threat = True
            break
        if not is_cached: time.sleep(15)

    if not found_threat:
        domain_match = re.search(r'@([\w.-]+)', sender)
        if domain_match:
            sender_domain = domain_match.group(1).replace('>', '').replace('<', '')
            if check_domain(sender_domain) > 0: found_threat = True
            time.sleep(1)

    if not found_threat:
        ips = []
        for rh in msg.get_all('Received', []):
            ips.extend(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(rh)))
        public_ips = [ip for ip in ips if not ip.startswith(('127.', '192.168.', '10.'))]
        if public_ips:
            if check_ip_abuse(public_ips[-1]) > 50: found_threat = True

    if not found_threat and attachment_hashes:
        for att in attachment_hashes:
            is_cached = att['hash'] in threat_cache.get("files", {})
            if check_file_hash(att['hash']) > 0:
                found_threat = True
                break
            if not is_cached: time.sleep(15)

    if found_threat:
        y_pred_refined[idx] = 1

print("\nGenerare explicabilitate model (SHAP) - Modul Textual...")

spam_indices = np.where(y_test == 1)[0]

if len(spam_indices) > 0:
    target_idx = spam_indices[0]

    instance_to_explain_2d = X_test[target_idx].toarray()
    instance_dense = instance_to_explain_2d[0]

    explainer = shap.TreeExplainer(best_rf_model)
    shap_values_output = explainer.shap_values(instance_to_explain_2d, check_additivity=False)

    if isinstance(shap_values_output, list):
        shap_vals_phishing = shap_values_output[1][0]
    else:
        shap_vals_phishing = shap_values_output[0, :, 1]

    impact_list = []
    for i in range(len(all_feature_names)):
        impact_list.append((all_feature_names[i], shap_vals_phishing[i], instance_dense[i]))

    impact_list.sort(key=lambda x: x[1], reverse=True)

    print("\n" + "=" * 60)
    print("DECIZIE AI EXPLICATA:")
    print(f"Fisier analizat: {os.path.basename(paths_test[target_idx])}")
    print("Sistemul a marcat acest mesaj ca PERICULOS (Phishing/Spam) din urmatoarele motive:\n")

    explicatii_headere = {
        'count_received': "Traseu Suspect: Rutare prin numar neobisnuit de servere.",
        'domain_match': "Falsificarea Identitatii: Adresa expeditorului falsificata.",
        'reply_to_match': "Redirectionare Suspecta: Mesajul de raspuns merge catre alta adresa.",
        'sender_domain_in_cc': "Distributie Ascunsa: Tipar de campanie nesolicitata (CC).",
        'subject_length': "Titlu Atipic: Format suspect pentru comunicare.",
        'subject_caps': "Limbaj Agresiv (Clickbait): Utilizare excesiva de majuscule.",
        'auth_spf_fail': "Securitate Picata (SPF): Server neautorizat.",
        'auth_dkim_fail': "Semnatura Invalida (DKIM): Lipseste certificarea continutului.",
        'auth_dmarc_fail': "Protectie Anti-Fraudă Picata (DMARC)."
    }

    motiv_count = 1
    for feature_name, shap_impact, feature_value in impact_list:
        if motiv_count > 5:
            break

        if shap_impact > 0.01:
            if feature_name in header_feature_names:
                este_anomalie = False

                if feature_name in ['domain_match', 'reply_to_match'] and feature_value == 0:
                    este_anomalie = True
                elif feature_name in ['auth_spf_fail', 'auth_dkim_fail', 'auth_dmarc_fail',
                                      'sender_domain_in_cc'] and feature_value == 1:
                    este_anomalie = True
                elif feature_name == 'count_received' and (feature_value == 0 or feature_value > 5):
                    este_anomalie = True
                elif feature_name == 'subject_caps' and feature_value > 5:
                    este_anomalie = True
                elif feature_name == 'subject_length' and feature_value > 100:
                    este_anomalie = True

                if este_anomalie:
                    explicatie = explicatii_headere.get(feature_name, f"Anomalie tehnica ({feature_name}).")
                    print(f" {motiv_count}. [Structura Tehnica] -> {explicatie}")
                    motiv_count += 1

            elif feature_name == "link":
                if feature_value > 0:
                    print(f" {motiv_count}. [Continut] -> Prezenta unui numar exagerat de link-uri.")
                    motiv_count += 1
            else:
                if feature_value > 0:
                    print(f" {motiv_count}. [Analiza Text] -> Prezenta cuvantului suspect: '{feature_name}'")
                    motiv_count += 1

    if motiv_count == 1:
        print(" [!] Scorul de risc a fost calculat pe baza traseului ascuns de retea si a formatului, neputand izola cuvinte malitioase specifice.")

    print("=" * 60 + "\n")
else:
    print("Nu s-au gasit exemple de spam in setul de test pentru generarea SHAP.")


print("\nSalvez modelul si vectorizatorul pe disk...")
joblib.dump(best_rf_model, 'phishing_rf_model.pkl')
joblib.dump(vectorizer, 'tfidf_vectorizer.pkl')

print("Fisierele '.pkl' au fost salvate cu succes!")
print(f"  -> phishing_rf_model.pkl")
print(f"  -> tfidf_vectorizer.pkl")
print(f"  -> optimal_threshold.pkl  (threshold: {best_threshold:.2f})")
print("\nScriptul de antrenare s-a incheiat.")
