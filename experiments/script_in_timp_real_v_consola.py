import imaplib
import email
import re
import numpy as np
import os
import joblib
import time
import requests
import base64
import json
from scipy.sparse import hstack
from email.header import decode_header

IMAP_SERVER = "imap.mail.yahoo.com"
IMAP_PORT = 993

EMAIL_USER = ""
EMAIL_PASS = ""

vt_api_key = ""
abuse_api_key = ""

base_dir = os.path.dirname(os.path.abspath(__file__))

print("Se încarcă creierul AI (Modelele .pkl) și modulele de memorie...")
try:
    rf_model = joblib.load(os.path.join(base_dir, 'phishing_rf_model.pkl'))
    vectorizer = joblib.load(os.path.join(base_dir, 'tfidf_vectorizer.pkl'))
    print("Modele încărcate cu succes!")
except Exception as e:
    print(f"Eroare la încărcarea modelelor: {e}")
    exit(1)

threat_cache_path = os.path.join(base_dir, 'threat_intel_cache.json')


def load_threat_cache():
    if os.path.exists(threat_cache_path):
        with open(threat_cache_path, 'r') as f: return json.load(f)
    return {"urls": {}, "domains": {}, "ips": {}, "files": {}}


def save_threat_cache(cache_data):
    with open(threat_cache_path, 'w') as f: json.dump(cache_data, f, indent=4)


threat_cache = load_threat_cache()

blacklist_path = os.path.join(base_dir, 'blacklist.json')


def load_blacklist():
    if os.path.exists(blacklist_path):
        with open(blacklist_path, 'r') as f: return json.load(f)
    return {"emails": [], "domains": []}


blacklist_data = load_blacklist()


# ==========================================
# FUNCȚII UTIlITARE ȘI API (GEO-FENCING + THREAT INTEL)
# ==========================================
def decode_mime_words(s):
    if not s: return "(Fără Subiect)"
    decoded_words = []
    for word, encoding in decode_header(s):
        if isinstance(word, bytes):
            try:
                decoded_words.append(word.decode(encoding or 'utf8'))
            except:
                decoded_words.append(word.decode('latin-1', errors='ignore'))
        else:
            decoded_words.append(word)
    return u''.join(decoded_words)


def check_suspicious_language(text_to_scan, threshold=0.05):
    """Geo-Fencing: Verifica daca textul contine un exces de caractere asiatice"""
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
    """NOU: API VirusTotal pentru Hash-ul atasamentelor"""
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


def extract_features_from_raw(raw_html_or_text):
    try:
        msg = email.message_from_string(raw_html_or_text)
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
        header_features['auth_spf_fail'] = 1 if re.search(r'spf=(fail|softfail|none)', auth_headers) else 0
        header_features['auth_dkim_fail'] = 1 if re.search(r'dkim=(fail|none)', auth_headers) else 0
        header_features['auth_dmarc_fail'] = 1 if re.search(r'dmarc=(fail|none)', auth_headers) else 0

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


# ==========================================
# LOGICA DE MONITORIZARE LIVE (BUCLA IMAP)
# ==========================================
def start_realtime_filter():
    last_checked_uid = 0

    while True:
        try:
            print(f"\nSe inițiază conexiunea IMAP la {IMAP_SERVER}...")
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
            mail.login(EMAIL_USER, EMAIL_PASS)

            mail.select("INBOX")

            if last_checked_uid == 0:
                status, response = mail.uid('search', None, 'ALL')
                if status == 'OK' and response[0]:
                    all_uids = response[0].split()
                    last_checked_uid = int(all_uids[-1])
                print("Autentificare reușită! Filtru Hibrid TOTAL (Blacklist + ML + GeoFence + Threat Intel).")
                print("Se monitorizează folderul INBOX exclusiv pentru e-mailuri noi care intră ACUM...\n" + "-" * 60)
            else:
                print("Conexiune restabilită cu succes! Se continuă monitorizarea...")

            while True:
                mail.select("INBOX")
                status, response = mail.uid('search', None, 'ALL')

                if status == 'OK' and response[0]:
                    current_uids = response[0].split()

                    if current_uids:
                        latest_uid = int(current_uids[-1])

                        if latest_uid > last_checked_uid:
                            # Reincarcam Blacklist-ul in caz ca ai adaugat ceva nou din Dashboard-ul Web intre timp!
                            global blacklist_data
                            blacklist_data = load_blacklist()

                            new_uids = [uid for uid in current_uids if int(uid) > last_checked_uid]
                            print(
                                f"[SISTEM] S-au primit {len(new_uids)} mesaje proaspete! Se pornește analizatorul...")

                            for uid_bytes in new_uids:
                                uid = uid_bytes.decode() if isinstance(uid_bytes, bytes) else str(uid_bytes)
                                status, data = mail.uid('fetch', uid, '(RFC822)')
                                if status != 'OK': continue

                                raw_email = data[0][1].decode('latin-1', errors='ignore')
                                text, headers, attachments, msg_obj = extract_features_from_raw(raw_email)

                                if text is None: continue

                                sender = decode_mime_words(msg_obj.get('From', 'Necunoscut'))
                                subject = decode_mime_words(msg_obj.get('Subject', ''))

                                print("\n" + "=" * 50)
                                print(f"SCRIPTO-SCANNER LIVE INTERCEPT")
                                print(f"Expeditor: {sender}")
                                print(f"Subiect: {subject}")

                                # --- PASUL 1: VERIFICARE BLACKLIST LOCAL ---
                                email_match = re.search(r'[\w.-]+@[\w.-]+', sender.lower())
                                domain_match = re.search(r'@([\w.-]+)', sender.lower())
                                clean_email = email_match.group(0) if email_match else ""
                                clean_domain = domain_match.group(1).replace('>', '').replace('<',
                                                                                              '').strip() if domain_match else ""

                                if clean_email in blacklist_data["emails"] or clean_domain in blacklist_data["domains"]:
                                    print(f"VERDICT FINAL: [BLOCAT INSTANT DE BLACKLIST-UL LOCAL]")
                                    print("=" * 50 + "\n")
                                    continue  # Trecem la urmatorul mail direct

                                # --- PASUL 2: VERIFICARE GEO-FENCING ---
                                is_foreign, lang_reason = check_suspicious_language(text)
                                if is_foreign:
                                    print(f"VERDICT FINAL: [🌏 BLOCAT DE GEO-FENCING]")
                                    print(f"Motiv: {lang_reason}")
                                    print("=" * 50 + "\n")
                                    continue  # Trecem la urmatorul mail direct

                                # --- PASUL 3: MACHINE LEARNING ---
                                text_lower = text.lower()
                                text_clean = re.sub(r'\b(href|url|http|https|www)\b', ' link ', text_lower)
                                text_clean = re.sub(r'<[^>]+>', ' ', text_clean)
                                text_clean = re.sub(r'[^a-z]+', ' ', text_clean)

                                X_text = vectorizer.transform([text_clean])
                                X_headers = np.array([list(headers.values())])
                                X_final = hstack((X_text, X_headers))

                                prediction = rf_model.predict(X_final)[0]
                                probability = rf_model.predict_proba(X_final)[0][1]

                                api_alerts = []

                                # --- PASUL 4: THREAT INTELLIGENCE (API-URI) ---
                                if 0.4 <= probability <= 0.6:
                                    print(
                                        f"[AI] Scor incert ({probability:.1%}). Se inițiază investigația externă (API)...")

                                    if clean_domain:
                                        print(f"Scanare domeniu: {clean_domain}...")
                                        if check_domain(clean_domain) > 0: api_alerts.append(
                                            f"Domeniu malițios: {clean_domain}")
                                        time.sleep(2)

                                    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
                                    for u in urls[:2]:
                                        print(f"Scanare URL: {u}...")
                                        if check_url(u) > 0: api_alerts.append(f"URL malițios: {u}")
                                        time.sleep(2)

                                    ips = []
                                    for rh in msg_obj.get_all('Received', []):
                                        ips.extend(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(rh)))
                                    public_ips = [ip for ip in ips if not ip.startswith(('127.', '192.168.', '10.'))]
                                    if public_ips:
                                        target_ip = public_ips[-1]
                                        print(f"Scanare IP: {target_ip}...")
                                        if check_ip_abuse(target_ip) > 50: api_alerts.append(
                                            f"IP abuziv (Botnet): {target_ip}")
                                        time.sleep(2)

                                    # NOU: Scanare Atasamente in fundal
                                    for att in attachments:
                                        print(f"Scanare fișier: {att['filename']}...")
                                        if check_file_hash(att['hash']) > 0: api_alerts.append(
                                            f"Malware detectat în: {att['filename']}")
                                        time.sleep(2)

                                    if api_alerts:
                                        prediction = 1
                                        probability = 0.99

                                # --- AFIȘARE FINALĂ ---
                                print(f"Scor Probabilitate Phishing: {probability:.2%}")

                                if api_alerts:
                                    print("\nALERTE API CONFIRMATE:")
                                    for alert in api_alerts:
                                        print(f"   - {alert}")

                                if prediction == 1:
                                    print(f"\nVERDICT FINAL: [PHISHING / SPAM DETECTAT]")
                                    print(f"ACȚIUNE: E-mailul a fost marcat ca periculos.")
                                else:
                                    print(f"\nVERDICT FINAL: [MESAJ SIGUR]")
                                    print(f"ACȚIUNE: Permis în Inbox-ul utilizatorului.")
                                print("=" * 50 + "\n")

                            last_checked_uid = latest_uid

                time.sleep(5)

        except KeyboardInterrupt:
            print("\nOprire manuală a filtrului de securitate. La revedere!")
            try:
                mail.logout()
            except:
                pass
            break
        except Exception as e:
            print(f"\nS-a pierdut conexiunea cu serverul ({e}). Se reinițializează în 5 secunde...")
            time.sleep(5)

if __name__ == "__main__":
    start_realtime_filter()