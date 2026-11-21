import streamlit as st
import joblib
import email
import re
import numpy as np
import os
import shap
import json
import requests
import base64
import time
from scipy.sparse import hstack

st.set_page_config(page_title="Sistem Anti-Phishing", page_icon="🛡️", layout="wide")

base_dir = os.path.dirname(os.path.abspath(__file__))

vt_api_key = ""
abuse_api_key = ""


@st.cache_resource
def load_models():
    rf = joblib.load(os.path.join(base_dir, 'phishing_rf_model.pkl'))
    vect = joblib.load(os.path.join(base_dir, 'tfidf_vectorizer.pkl'))
    optimal_threshold = joblib.load(os.path.join(base_dir, 'optimal_threshold.pkl'))
    return rf, vect, optimal_threshold


try:
    rf_model, vectorizer, optimal_threshold = load_models()
except Exception as e:
    st.error(f"Eroare la încărcarea modelelor .pkl: {e}\nAsigură-te că sunt în folderul 'src'!")
    st.stop()

blacklist_path = os.path.join(base_dir, 'blacklist.json')


def load_blacklist():
    if os.path.exists(blacklist_path):
        with open(blacklist_path, 'r') as f:
            return json.load(f)
    data = {"emails": ["attacker@malicious-domain.com"], "domains": ["phishingsite.org"]}
    with open(blacklist_path, 'w') as f: json.dump(data, f, indent=4)
    return data


whitelist_path = os.path.join(base_dir, 'whitelist.json')


def load_whitelist():
    if os.path.exists(whitelist_path):
        with open(whitelist_path, 'r') as f: return json.load(f)
    data = {"emails": ["noreply@steampowered.com"], "domains": ["emag.ro", "github.com"]}
    with open(whitelist_path, 'w') as f: json.dump(data, f, indent=4)
    return data


def save_whitelist(data):
    with open(whitelist_path, 'w') as f: json.dump(data, f, indent=4)


whitelist_data = load_whitelist()


def save_blacklist(data):
    with open(blacklist_path, 'w') as f: json.dump(data, f, indent=4)


blacklist_data = load_blacklist()

threat_cache_path = os.path.join(base_dir, 'threat_intel_cache.json')


def load_threat_cache():
    if os.path.exists(threat_cache_path):
        with open(threat_cache_path, 'r') as f: return json.load(f)
    return {"urls": {}, "domains": {}, "ips": {}, "files": {}}


def save_threat_cache(cache_data):
    with open(threat_cache_path, 'w') as f: json.dump(cache_data, f, indent=4)


threat_cache = load_threat_cache()

EXPLICATII_SISTEM = {
    'count_received': "Traseu Suspect: Rutare prin numar neobisnuit de servere.",
    'domain_match': "Falsificarea Identitatii: Adresa expeditorului falsificata.",
    'reply_to_match': "Redirectionare Suspecta: Mesajul de răspuns merge către alta adresa.",
    'sender_domain_in_cc': "Distributie Ascunsa: Tipar de campanie nesolicitata (CC).",
    'subject_length': "Titlu Atipic: Format suspect pentru comunicare de afaceri.",
    'subject_caps': "Limbaj Agresiv: Utilizare excesiva de majuscule (Clickbait).",
    'auth_spf_fail': "Securitate Picata (SPF): Server neautorizat.",
    'auth_dkim_fail': "Semnatura Invalida (DKIM): Lipseste certificarea continutului.",
    'auth_dmarc_fail': "Protectie Anti-Fraudă Picata (DMARC): Posibila clonare.",
    'link': "Structura: Prezenta unui numar exagerat de link-uri malitioase."
}


def check_suspicious_language(text_to_scan, threshold=0.05):
    if not text_to_scan: return False, ""
    clean_text = re.sub(r'\s+', '', text_to_scan)
    if len(clean_text) < 10: return False, ""
    asian_chars = re.findall(r'[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]', clean_text)
    ratio = len(asian_chars) / len(clean_text)
    if ratio > threshold:
        return True, f"Detectat {ratio:.1%} caractere nepermise (Asiatice)."
    return False, ""


def check_url(url):
    if url in threat_cache["urls"]: return threat_cache["urls"][url]
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": vt_api_key},
                                timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            score = stats['malicious'] + stats['suspicious']
            threat_cache["urls"][url] = score
            save_threat_cache(threat_cache)
            return score
    except:
        pass
    return 0


def check_domain(domain):
    if domain in threat_cache["domains"]: return threat_cache["domains"][domain]
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": vt_api_key},
                                timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            score = stats['malicious'] + stats['suspicious']
            threat_cache["domains"][domain] = score
            save_threat_cache(threat_cache)
            return score
    except:
        pass
    return 0


def check_ip_abuse(ip):
    if ip in threat_cache["ips"]: return threat_cache["ips"][ip]
    try:
        response = requests.get("https://api.abuseipdb.com/api/v2/check",
                                headers={"Key": abuse_api_key, "Accept": "application/json"},
                                params={"ipAddress": ip, "maxAgeInDays": "90"}, timeout=10)
        if response.status_code == 200:
            score = response.json()['data']['abuseConfidenceScore']
            threat_cache["ips"][ip] = score
            save_threat_cache(threat_cache)
            return score
    except:
        pass
    return 0


def check_file_hash(file_hash):
    if file_hash in threat_cache.get("files", {}): return threat_cache["files"][file_hash]
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}",
                                headers={"x-apikey": vt_api_key}, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            score = stats['malicious'] + stats['suspicious']
            threat_cache.setdefault("files", {})[file_hash] = score
            save_threat_cache(threat_cache)
            return score
        elif response.status_code == 404:
            threat_cache.setdefault("files", {})[file_hash] = 0
            save_threat_cache(threat_cache)
            return 0
    except:
        pass
    return 0


def extract_features(content):
    try:
        msg = email.message_from_string(content)
        header_features = {}
        attachment_hashes = []

        received = msg.get_all('Received')
        header_features['count_received'] = len(received) if received else 0

        def get_domain(s):
            if not s: return ""
            m = re.search(r'@([\w.-]+)', s)
            return m.group(1) if m else ""

        domain_return = get_domain(msg.get('Return-Path', ''))
        domain_sender = get_domain(msg.get('From', ''))
        domain_reply = get_domain(msg.get('Reply-To', ''))

        header_features['domain_match'] = 1 if domain_return and domain_sender and (
                domain_return == domain_sender) else 0
        header_features['reply_to_match'] = 1 if not msg.get('Reply-To', '') or domain_reply == domain_sender else 0

        cc = msg.get('Cc', '')
        header_features['sender_domain_in_cc'] = 1 if cc and domain_sender in cc.lower() else 0

        subject = msg.get('Subject', '')
        header_features['subject_length'] = len(subject)
        header_features['subject_caps'] = sum(1 for c in subject if c.isupper())

        auth_headers = " ".join(
            [str(h).lower() for h in msg.get_all('Authentication-Results', []) + msg.get_all('Received-SPF', [])])

        # NOU: Prioritizăm rezultatul pozitiv ('pass'). Ignorăm 'none' dacă există măcar un 'pass' valid în lanț.
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
                        attachment_hashes.append(
                            {'filename': fname if fname else "unknown", 'hash': hashlib.md5(payload).hexdigest()})
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
        return text, header_features, attachment_hashes, msg

    except Exception as e:
        return None, None, [], None


st.sidebar.header("Panou de Administrare")
st.sidebar.info("Modelul AI & API-urile sunt active.")
st.sidebar.subheader("Filtru Whitelist/Blacklist Local")

with st.sidebar.expander("Adaugă Expeditor Sigur"):
    tip_adaugare_w = st.selectbox("Tip Element Sigur", ["E-mail Expeditor", "Domeniu Web"])
    valoare_noua_w = st.text_input("Introduceți adresa/domeniul (Sigur):").strip().lower()
    if st.button("Adaugă în Whitelist", use_container_width=True):
        if valoare_noua_w:
            key = "emails" if tip_adaugare_w == "E-mail Expeditor" else "domains"
            if valoare_noua_w not in whitelist_data[key]:
                whitelist_data[key].append(valoare_noua_w)
                save_whitelist(whitelist_data)
                st.success("Expeditor marcat ca sigur!")
                st.rerun()

with st.sidebar.expander("Adaugă Expeditor Blocat"):
    tip_adaugare = st.selectbox("Tip Element", ["E-mail Expeditor", "Domeniu Web"])
    valoare_noua = st.text_input("Introduceți adresa/domeniul:").strip().lower()
    if st.button("Adaugă în Blacklist", use_container_width=True):
        if valoare_noua:
            key = "emails" if tip_adaugare == "E-mail Expeditor" else "domains"
            if valoare_noua not in blacklist_data[key]:
                blacklist_data[key].append(valoare_noua)
                save_blacklist(blacklist_data)
                st.success("Adăugat!")
                st.rerun()

with st.sidebar.expander("Vizualizează / Șterge"):
    st.markdown("**BLACKLIST (Blocate)**")
    if blacklist_data["emails"]:
        email_de_sters = st.selectbox(
            "E-mailuri Blocate",
            options=blacklist_data["emails"],
            index=None,
            placeholder="Alege e-mail..."
        )
        if email_de_sters and st.button("Elimină E-mail (Blacklist)"):
            blacklist_data["emails"].remove(email_de_sters)
            save_blacklist(blacklist_data)
            st.rerun()

    if blacklist_data["domains"]:
        dom_de_sters = st.selectbox(
            "Domenii Blocate",
            options=blacklist_data["domains"],
            index=None,
            placeholder="Alege domeniu..."
        )
        if dom_de_sters and st.button("Elimină Domeniu (Blacklist)"):
            blacklist_data["domains"].remove(dom_de_sters)
            save_blacklist(blacklist_data)
            st.rerun()

    st.markdown("---")
    st.markdown("**WHITELIST (Sigure)**")

    if whitelist_data["emails"]:
        w_email_de_sters = st.selectbox(
            "E-mailuri Sigure",
            options=whitelist_data["emails"],
            index=None,
            placeholder="Alege e-mail sigur..."
        )
        if w_email_de_sters and st.button("Elimină E-mail (Whitelist)"):
            whitelist_data["emails"].remove(w_email_de_sters)
            save_whitelist(whitelist_data)
            st.rerun()

    if whitelist_data["domains"]:
        w_dom_de_sters = st.selectbox(
            "Domenii Sigure",
            options=whitelist_data["domains"],
            index=None,
            placeholder="Alege domeniu sigur..."
        )
        if w_dom_de_sters and st.button("Elimină Domeniu (Whitelist)"):
            whitelist_data["domains"].remove(w_dom_de_sters)
            save_whitelist(whitelist_data)
            st.rerun()

st.title("🛡Sistem de Detecție Phishing")
st.divider()

uploaded_file = st.file_uploader("Încarcă un e-mail suspect (format .eml)", type=['eml', 'txt'])

if uploaded_file is not None:
    file_content = uploaded_file.getvalue().decode('latin-1', errors='ignore')

    msg_raw = email.message_from_string(file_content)
    sender_raw = msg_raw.get('From', '') if msg_raw.get('From') else ""

    email_match = re.search(r'[\w.-]+@[\w.-]+', sender_raw.lower())
    domain_match = re.search(r'@([\w.-]+)', sender_raw.lower())
    clean_email = email_match.group(0) if email_match else ""
    clean_domain = domain_match.group(1).replace('>', '').replace('<', '').strip() if domain_match else ""

    is_blocked = False
    blacklist_reason = ""

    if clean_email in blacklist_data["emails"]:
        is_blocked = True
        blacklist_reason = f"Adresa de e-mail [{clean_email}] se află în Blacklist-ul personalizat."
    elif clean_domain in blacklist_data["domains"]:
        is_blocked = True
        blacklist_reason = f"Domeniul [{clean_domain}] se află în Blacklist-ul personalizat."

    if is_blocked:
        st.divider()
        st.subheader("Rezultatul Analizei de Securitate")

        col1, col2 = st.columns(2)
        with col1:
            st.error("**BLOCAT INSTANT DE FILTRUL LOCAL**")
            st.metric(label="Nivel de Risc (Politică de Securitate)", value="100.0%")
        with col2:
            st.info(
                f"**Motivul blocării:**\n\n{blacklist_reason}\n\nMesajul a fost respins la nivel de gateway înainte de procesarea prin rețelele neuronale sau algoritmii Machine Learning.")
            st.markdown(f"**Expeditor detectat:** `{sender_raw.strip()}`")
        st.stop()

    text, headers, attachments, _ = extract_features(file_content)

    if text is not None:
        is_whitelisted = False
        whitelist_reason = ""

        if clean_email in whitelist_data["emails"]:
            is_whitelisted = True
            whitelist_reason = f"Adresa [{clean_email}] se află în Whitelist."
        elif clean_domain in whitelist_data["domains"]:
            is_whitelisted = True
            whitelist_reason = f"Domeniul [{clean_domain}] se află în Whitelist."

        if is_whitelisted:
            if headers.get('auth_spf_fail') == 1 or headers.get('auth_dkim_fail') == 1:
                st.warning(
                    "Expeditorul este în Whitelist, dar a PICAT testele de securitate (SPF/DKIM)! Posibilă tentativă de Spoofing (Falsificare). Se continuă analiza de risc!")
            else:
                st.divider()
                st.subheader("Rezultatul Analizei de Securitate")
                col1, col2 = st.columns(2)
                with col1:
                    st.success("**VERDICT: E-MAIL SIGUR (WHITELISTED)**")
                    st.metric(label="Scorul oferit de către sistem", value="100.0%")
                with col2:
                    st.info(
                        f"**Motivul aprobării:**\n\n{whitelist_reason}\n\nMesajul a trecut testele criptografice (SPF/DKIM) și a fost aprobat direct de politica de securitate locală.")
                st.stop()

    if text is not None:
        is_foreign, lang_reason = check_suspicious_language(text)
        if is_foreign:
            st.error("**BLOCAT DE GEO-FENCING (CARACTERE NEPERMISE)**")
            st.info(f"Motiv: {lang_reason}")
            st.metric(label="Nivel de Risc", value="100.0%")
            st.stop()

        st.write("Se procesează mail-ul atașat")
        text_lower = text.lower()
        text_clean = re.sub(r'\b(href|url|http|https|www)\b', ' link ', text_lower)
        text_clean = re.sub(r'<[^>]+>', ' ', text_clean)
        text_clean = re.sub(r'[^a-z]+', ' ', text_clean)

        X_text = vectorizer.transform([text_clean])
        X_headers = np.array([list(headers.values())])
        X_final = hstack((X_text, X_headers))

        probability = rf_model.predict_proba(X_final)[0][1]
        prediction = 1 if probability >= optimal_threshold else 0

        api_alerts = []

        if 0.3 <= probability <= 0.9:
            with st.status("AI-ul este nesigur. Se inițiază investigația externă (Threat Intel)",
                           expanded=True) as status:
                st.write("Se extrag amprentele digitale...")

                trust_bonus = 0.0
                risk_bonus = 0.0

                # ── Verificare Domeniu ──────────────────────────────────────────
                if clean_domain:
                    st.write(f"Scanam domeniul: `{clean_domain}`")
                    domain_score = check_domain(clean_domain)
                    if domain_score > 0:
                        api_alerts.append(f"Domeniu malițios: {clean_domain}")
                        risk_bonus += 0.40
                    else:
                        trust_bonus += 0.25
                    time.sleep(2)

                urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
                malicious_urls = 0
                for u in urls[:3]:
                    st.write(f"Scanam link-ul: `{u}`")
                    if check_url(u) > 0:
                        api_alerts.append(f"URL malițios: {u}")
                        malicious_urls += 1
                        risk_bonus += 0.35
                    else:
                        trust_bonus += 0.15
                    time.sleep(2)

                ips = []
                for rh in msg_raw.get_all('Received', []):
                    ips.extend(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(rh)))
                public_ips = [ip for ip in ips if not ip.startswith(('127.', '192.168.', '10.'))]
                if public_ips:
                    target_ip = public_ips[-1]
                    st.write(f"Scanam IP-ul: `{target_ip}`")
                    abuse_score = check_ip_abuse(target_ip)
                    if abuse_score > 50:
                        api_alerts.append(f"IP abuziv (Botnet): {target_ip} (scor: {abuse_score})")
                        risk_bonus += 0.40
                    elif abuse_score > 20:
                        risk_bonus += 0.20
                    else:
                        trust_bonus += 0.25
                    time.sleep(2)

                for att in attachments:
                    st.write(f"Scanam fisierul: `{att['filename']}`")
                    if check_file_hash(att['hash']) > 0:
                        api_alerts.append(f"Malware detectat în: {att['filename']}")
                        risk_bonus += 0.50
                    else:
                        trust_bonus += 0.25
                    time.sleep(2)

                crypto_ok = (headers.get('auth_spf_fail') == 0 and
                             headers.get('auth_dkim_fail') == 0 and
                             headers.get('auth_dmarc_fail') == 0)

                if crypto_ok:
                    trust_bonus += 0.35
                else:
                    if headers.get('auth_spf_fail') == 1: risk_bonus += 0.10
                    if headers.get('auth_dkim_fail') == 1: risk_bonus += 0.10
                    if headers.get('auth_dmarc_fail') == 1: risk_bonus += 0.10

                if api_alerts:
                    status.update(label="ALERTĂ: Amenințări confirmate de API-uri!", state="error", expanded=True)
                    prediction = 1
                    probability = min(0.99, probability + risk_bonus)
                else:
                    adjusted_probability = probability - trust_bonus + risk_bonus
                    adjusted_probability = max(0.01, min(0.98, adjusted_probability))

                    probability = adjusted_probability
                    prediction = 1 if probability >= 0.50 else 0

                    if prediction == 0:
                        status.update(
                            label=f"De-escaladare Reușită: scor coborât la {probability:.0%} ",
                            state="complete", expanded=False
                        )
                    else:
                        status.update(
                            label=f"API-urile sunt curate, dar scorul rămâne ridicat ({probability:.0%}). "
                                  f"Protocoale criptografice: {'OK' if crypto_ok else 'Suspecte'}.",
                            state="complete", expanded=False
                        )
        if probability >= 0.4:
            st.divider()
            with st.spinner("Generare explicații AI"):
                try:
                    all_features = np.concatenate([vectorizer.get_feature_names_out(), list(headers.keys())])
                    shap_vals = shap.TreeExplainer(rf_model).shap_values(X_final.toarray(), check_additivity=False)
                    shap_vals_phishing = shap_vals[1][0] if isinstance(shap_vals, list) else shap_vals[0, :, 1]

                    X_dense = X_final.toarray()[0]

                    impact_list = []
                    for i in range(len(all_features)):
                        impact_list.append((all_features[i], shap_vals_phishing[i], X_dense[i]))


                    # NOU: Funcție de sortare care dă prioritate absolută protocoalelor picate
                    def sort_priority(item):
                        f, imp, val = item
                        is_failed_protocol = 1 if (
                                f in ['auth_spf_fail', 'auth_dkim_fail', 'auth_dmarc_fail'] and val == 1) else 0
                        return (is_failed_protocol, imp)


                    # Sortăm folosind noua funcție
                    impact_list.sort(key=sort_priority, reverse=True)

                    st.subheader("Decizia AI Explicată:")
                    exp_text = "Motive principale pentru ridicarea scorului de risc:\n\n"

                    cnt = 1
                    for f, imp, val in impact_list:
                        # Am crescut limita la 4, pentru ca dacă pică 3 protocoale, să mai afișeze și un cuvânt suspect
                        if cnt > 4:
                            break

                        is_failed_protocol = (f in ['auth_spf_fail', 'auth_dkim_fail', 'auth_dmarc_fail'] and val == 1)

                        # Afișăm dacă e un protocol picat SAU dacă are impact SHAP relevant (> 0.01)
                        if is_failed_protocol or imp > 0.01:
                            if f in headers.keys():
                                este_anomalie = False

                                if is_failed_protocol:
                                    este_anomalie = True
                                elif f in ['domain_match', 'reply_to_match'] and val == 0:
                                    este_anomalie = True
                                elif f == 'sender_domain_in_cc' and val == 1:
                                    este_anomalie = True
                                elif f == 'count_received' and (val == 0 or val > 5):
                                    este_anomalie = True
                                elif f == 'subject_caps' and val > 15:
                                    este_anomalie = True
                                elif f == 'subject_length' and val > 100:
                                    este_anomalie = True

                                if este_anomalie:
                                    # NOU: Etichetă diferită pentru a scoate în evidență problemele de criptografie
                                    if is_failed_protocol:
                                        exp_text += f"{cnt}. **[Securitate Critică]** -> {EXPLICATII_SISTEM.get(f, f)}\n\n"
                                    else:
                                        exp_text += f"{cnt}. **[Antet]** -> {EXPLICATII_SISTEM.get(f, f)}\n\n"
                                    cnt += 1

                            elif f == "link":
                                if val > 0:
                                    exp_text += f"{cnt}. **[Conținut]** -> {EXPLICATII_SISTEM.get('link')}\n\n"
                                    cnt += 1
                            else:
                                # Pentru cuvinte, ne asigurăm că impactul SHAP este valid
                                if val > 0 and imp > 0.01:
                                    exp_text += f"{cnt}. **[Text]** -> Limbaj suspect: '{f}'\n\n"
                                    cnt += 1

                    if cnt == 1:
                        exp_text = "Scorul de risc a fost calculat pe baza traseului ascuns de rețea (Headers) și a formatului atipic"

                    st.info(exp_text)
                except Exception as e:
                    st.warning(f"Sistemul de explicabilitate este temporar indisponibil. ({e})")

        st.divider()
        st.subheader("Rezultatul Final al Sistemului")
        col1, col2 = st.columns(2)
        with col1:
            if prediction == 1:
                st.error("**VERDICT: PHISHING / MALWARE**")
                st.metric(label="Scorul oferit de către sistem", value=f"{probability:.1%}")
                if api_alerts:
                    for alert in api_alerts: st.warning(alert)
            else:
                st.success("**VERDICT: E-MAIL SIGUR**")
                st.metric(label="Scorul oferit de către sistem", value=f"{probability:.1%}")

        with col2:
            st.markdown("**Detalii Extrase:**")
            st.write(f"- **Atașamente:** {len(attachments)}")
            st.write(
                f"- **Protocoale securitate picate:** {'Da' if (headers.get('auth_spf_fail') or headers.get('auth_dkim_fail')) else 'Nu'}")