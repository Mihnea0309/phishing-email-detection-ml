import customtkinter as ctk
import threading
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
import shap
from scipy.sparse import hstack
from email.header import decode_header

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

vt_api_key = ""
abuse_api_key = ""

base_dir = os.path.dirname(os.path.abspath(__file__))

threat_cache_path = os.path.join(base_dir, 'threat_intel_cache.json')
blacklist_path = os.path.join(base_dir, 'blacklist.json')
whitelist_path = os.path.join(base_dir, 'whitelist.json')

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


class SocMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Sistem de detecție în timp real")
        self.geometry("900x700")

        self.is_running = False
        self.monitor_thread = None
        self.mail_connection = None

        self.rf_model = None
        self.vectorizer = None
        self.optimal_threshold = 0.50
        self.threat_cache = self.load_threat_cache()
        self.blacklist_data = self.load_blacklist()
        self.whitelist_data = self.load_whitelist()

        self.setup_ui()
        self.load_ai_models()

    def setup_ui(self):
        self.top_frame = ctk.CTkFrame(self)
        self.top_frame.pack(pady=20, padx=20, fill="x")

        self.title_label = ctk.CTkLabel(self.top_frame, text="Setări Conexiune IMAP (Gateway)",
                                        font=ctk.CTkFont(size=16, weight="bold"))
        self.title_label.grid(row=0, column=0, columnspan=4, pady=10, padx=10, sticky="w")

        self.email_label = ctk.CTkLabel(self.top_frame, text="E-mail:")
        self.email_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.email_entry = ctk.CTkEntry(self.top_frame, width=250, placeholder_text="exemplu@yahoo.com")
        self.email_entry.grid(row=1, column=1, padx=10, pady=5)
        self.email_entry.insert(0, "")

        self.pass_label = ctk.CTkLabel(self.top_frame, text="App Password:")
        self.pass_label.grid(row=1, column=2, padx=10, pady=5, sticky="e")
        self.pass_entry = ctk.CTkEntry(self.top_frame, width=250, show="*", placeholder_text="Parolă 16 caractere")
        self.pass_entry.grid(row=1, column=3, padx=10, pady=5)
        self.pass_entry.insert(0, "")

        self.start_btn = ctk.CTkButton(self.top_frame, text="▶ START MONITORIZARE", fg_color="green",
                                       hover_color="darkgreen", command=self.toggle_monitor)
        self.start_btn.grid(row=2, column=0, columnspan=4, pady=15)

        self.console_label = ctk.CTkLabel(self, text="Terminal Interceptări Live:",
                                          font=ctk.CTkFont(size=14, weight="bold"))
        self.console_label.pack(padx=20, anchor="w")

        self.console = ctk.CTkTextbox(self, width=860, height=450, font=ctk.CTkFont(family="Consolas", size=13))
        self.console.pack(padx=20, pady=10, fill="both", expand=True)
        self.console.configure(state="disabled")

    def log(self, message):
        self.console.configure(state="normal")
        self.console.insert("end", message + "\n")
        self.console.see("end")
        self.console.configure(state="disabled")

    def load_ai_models(self):
        self.log("Se încarcă modulul de AI")
        try:
            self.rf_model = joblib.load(os.path.join(base_dir, 'phishing_rf_model.pkl'))
            self.vectorizer = joblib.load(os.path.join(base_dir, 'tfidf_vectorizer.pkl'))
            self.optimal_threshold = joblib.load(os.path.join(base_dir, 'optimal_threshold.pkl'))
            self.log("Modul încărcat cu succes")
        except Exception as e:
            self.log(f"Eroare la încărcarea modelelor: {e}")

    def load_threat_cache(self):
        if os.path.exists(threat_cache_path):
            with open(threat_cache_path, 'r') as f: return json.load(f)
        return {"urls": {}, "domains": {}, "ips": {}, "files": {}}

    def save_threat_cache(self):
        with open(threat_cache_path, 'w') as f: json.dump(self.threat_cache, f, indent=4)

    def load_blacklist(self):
        if os.path.exists(blacklist_path):
            with open(blacklist_path, 'r') as f: return json.load(f)
        return {"emails": [], "domains": []}

    def load_whitelist(self):
        if os.path.exists(whitelist_path):
            with open(whitelist_path, 'r') as f: return json.load(f)
        return {"emails": [], "domains": []}

    def check_url(self, url):
        if url in self.threat_cache["urls"]: return self.threat_cache["urls"][url]
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                                    headers={"x-apikey": vt_api_key}, timeout=10)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                score = stats['malicious'] + stats['suspicious']
                self.threat_cache["urls"][url] = score
                self.save_threat_cache()
                return score
        except:
            pass
        return 0

    def check_domain(self, domain):
        if domain in self.threat_cache["domains"]: return self.threat_cache["domains"][domain]
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                                    headers={"x-apikey": vt_api_key}, timeout=10)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                score = stats['malicious'] + stats['suspicious']
                self.threat_cache["domains"][domain] = score
                self.save_threat_cache()
                return score
        except:
            pass
        return 0

    def check_ip_abuse(self, ip):
        if ip in self.threat_cache["ips"]: return self.threat_cache["ips"][ip]
        try:
            response = requests.get("https://api.abuseipdb.com/api/v2/check",
                                    headers={"Key": abuse_api_key, "Accept": "application/json"},
                                    params={"ipAddress": ip, "maxAgeInDays": "90"}, timeout=10)
            if response.status_code == 200:
                score = response.json()['data']['abuseConfidenceScore']
                self.threat_cache["ips"][ip] = score
                self.save_threat_cache()
                return score
        except:
            pass
        return 0

    def check_file_hash(self, file_hash):
        if file_hash in self.threat_cache.get("files", {}): return self.threat_cache["files"][file_hash]
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}",
                                    headers={"x-apikey": vt_api_key}, timeout=10)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                score = stats['malicious'] + stats['suspicious']
                self.threat_cache.setdefault("files", {})[file_hash] = score
                self.save_threat_cache()
                return score
            elif response.status_code == 404:
                self.threat_cache.setdefault("files", {})[file_hash] = 0
                self.save_threat_cache()
                return 0
        except:
            pass
        return 0

    def toggle_monitor(self):
        if not self.is_running:
            email_val = self.email_entry.get().strip()
            pass_val = self.pass_entry.get().strip()
            if not email_val or not pass_val:
                self.log("Introdu emailul și parola")
                return
            self.is_running = True
            self.start_btn.configure(text="STOP MONITORIZARE", fg_color="red", hover_color="darkred")
            self.email_entry.configure(state="disabled")
            self.pass_entry.configure(state="disabled")
            self.monitor_thread = threading.Thread(target=self.realtime_filter_loop, args=(email_val, pass_val),
                                                   daemon=True)
            self.monitor_thread.start()
        else:
            self.is_running = False
            self.start_btn.configure(text="START MONITORIZARE", fg_color="green", hover_color="darkgreen")
            self.email_entry.configure(state="normal")
            self.pass_entry.configure(state="normal")
            self.log("\nSemnal de oprire trimis. Se deconectează în câteva secunde...")

    def realtime_filter_loop(self, user_email, user_pass):
        IMAP_SERVER = "imap.mail.yahoo.com"
        IMAP_PORT = 993
        last_checked_uid = 0

        while self.is_running:
            try:
                self.log(f"\nSe inițiază conexiunea IMAP la {IMAP_SERVER}...")
                self.mail_connection = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
                self.mail_connection.login(user_email, user_pass)
                self.mail_connection.select("INBOX")

                if last_checked_uid == 0:
                    status, response = self.mail_connection.uid('search', None, 'ALL')
                    if status == 'OK' and response[0]:
                        last_checked_uid = int(response[0].split()[-1])
                    self.log("Autentificare reușită - sistemul este activ")
                    self.log("Se monitorizează mail-urile\n" + "-" * 60)
                else:
                    self.log("Conexiune restabilită cu succes! Se continuă monitorizarea")

                while self.is_running:
                    self.mail_connection.select("INBOX")
                    status, response = self.mail_connection.uid('search', None, 'ALL')

                    if status == 'OK' and response[0]:
                        current_uids = response[0].split()
                        if current_uids:
                            latest_uid = int(current_uids[-1])
                            if latest_uid > last_checked_uid:
                                self.blacklist_data = self.load_blacklist()
                                self.whitelist_data = self.load_whitelist()

                                new_uids = [uid for uid in current_uids if int(uid) > last_checked_uid]
                                self.log(f"\n[SISTEM] S-a primit {len(new_uids)} mesaj - se pornește clasificatorul")

                                for uid_bytes in new_uids:
                                    uid = uid_bytes.decode() if isinstance(uid_bytes, bytes) else str(uid_bytes)
                                    status, data = self.mail_connection.uid('fetch', uid, '(RFC822)')
                                    if status != 'OK': continue

                                    raw_email = data[0][1].decode('latin-1', errors='ignore')
                                    text, headers, attachments, msg_obj = self.extract_features_from_raw(raw_email)

                                    if text is None: continue

                                    sender = self.decode_mime_words(msg_obj.get('From', 'Necunoscut'))
                                    subject = self.decode_mime_words(msg_obj.get('Subject', ''))

                                    email_match = re.search(r'[\w.-]+@[\w.-]+', sender.lower())
                                    domain_match = re.search(r'@([\w.-]+)', sender.lower())
                                    clean_email = email_match.group(0) if email_match else ""
                                    clean_domain = domain_match.group(1).replace('>', '').replace('<',
                                                                                                  '').strip() if domain_match else ""

                                    self.log("\n" + "=" * 50)
                                    self.log(f"Analiza sistemului")
                                    self.log(f"Expeditor: {sender}")
                                    self.log(f"Subiect: {subject}")

                                    is_whitelisted = clean_email in self.whitelist_data["emails"] or clean_domain in \
                                                     self.whitelist_data["domains"]
                                    if is_whitelisted:
                                        if headers.get('auth_spf_fail') == 1 or headers.get('auth_dkim_fail') == 1:
                                            self.log(
                                                "[SPOOFING WARNING] Expeditor în Whitelist, dar a picat testele criptografice")
                                        else:
                                            self.log(f"VERDICT FINAL: [E-MAIL DE ÎNCREDERE (WHITELISTED)]")
                                            self.log("=" * 50 + "\n")
                                            continue

                                    if clean_email in self.blacklist_data["emails"] or clean_domain in \
                                            self.blacklist_data["domains"]:
                                        self.log(f"VERDICT FINAL: [BLOCAT INSTANT DE BLACKLIST-UL LOCAL]")
                                        self.log("=" * 50 + "\n")
                                        continue

                                    is_foreign, lang_reason = self.check_suspicious_language(text)
                                    if is_foreign:
                                        self.log(f"VERDICT FINAL: [BLOCAT DE GEO-FENCING]")
                                        self.log(f"Motiv: {lang_reason}")
                                        self.log("=" * 50 + "\n")
                                        continue

                                    text_lower = text.lower()
                                    text_clean = re.sub(r'\b(href|url|http|https|www)\b', ' link ', text_lower)
                                    text_clean = re.sub(r'<[^>]+>', ' ', text_clean)
                                    text_clean = re.sub(r'[^a-z]+', ' ', text_clean)

                                    X_text = self.vectorizer.transform([text_clean])
                                    X_headers = np.array([list(headers.values())])
                                    X_final = hstack((X_text, X_headers))

                                    probability = self.rf_model.predict_proba(X_final)[0][1]
                                    prediction = 1 if probability >= self.optimal_threshold else 0
                                    api_alerts = []

                                    if 0.3 <= probability <= 0.9:
                                        self.log(
                                            f"    [AI] Scor incert ({probability:.1%}). Se inițiază investigația externă")

                                        if clean_domain:
                                            self.log(f"    Scanare domeniu: {clean_domain}...")
                                            if self.check_domain(clean_domain) > 0: api_alerts.append(
                                                f"Domeniu malițios: {clean_domain}")
                                            time.sleep(2)

                                        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
                                        for u in urls[:2]:
                                            self.log(f"    Scanare URL: {u}...")
                                            if self.check_url(u) > 0: api_alerts.append(f"URL malițios: {u}")
                                            time.sleep(2)

                                        ips = []
                                        for rh in msg_obj.get_all('Received', []):
                                            ips.extend(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(rh)))
                                        public_ips = [ip for ip in ips if
                                                      not ip.startswith(('127.', '192.168.', '10.'))]
                                        if public_ips:
                                            target_ip = public_ips[-1]
                                            self.log(f"    Scanare IP: {target_ip}...")
                                            if self.check_ip_abuse(target_ip) > 50: api_alerts.append(
                                                f"IP abuziv: {target_ip}")
                                            time.sleep(2)

                                        for att in attachments:
                                            self.log(f"    Scanare fișier atașat: {att['filename']}")
                                            if self.check_file_hash(att['hash']) > 0: api_alerts.append(
                                                f"Malware detectat: {att['filename']}")
                                            time.sleep(2)

                                        if api_alerts:
                                            prediction = 1
                                            probability = 0.99
                                        else:
                                            if headers.get('auth_spf_fail') == 0 and headers.get(
                                                    'auth_dkim_fail') == 0 and headers.get('auth_dmarc_fail') == 0:
                                                self.log(
                                                    "    De-escaladare: API-uri curate și protocoale valide (SPF/DKIM/DMARC).")
                                                prediction = 0
                                                probability = 0.10

                                    self.log(f"Scor Probabilitate Phishing: {probability:.2%}")
                                    if api_alerts:
                                        self.log("\nALERTE API CONFIRMATE:")
                                        for alert in api_alerts: self.log(f"   - {alert}")

                                    if probability >= 0.4:
                                        self.log("\n[ANALIZĂ AI] Se generează motivele deciziei...")
                                        try:
                                            all_features = np.concatenate(
                                                [self.vectorizer.get_feature_names_out(), list(headers.keys())])
                                            shap_vals = shap.TreeExplainer(self.rf_model).shap_values(X_final.toarray(),
                                                                                                      check_additivity=False)
                                            shap_vals_phishing = shap_vals[1][0] if isinstance(shap_vals,
                                                                                               list) else shap_vals[0,
                                                                                                          :, 1]
                                            X_dense = X_final.toarray()[0]

                                            impact_list = []
                                            for i in range(len(all_features)):
                                                impact_list.append((all_features[i], shap_vals_phishing[i], X_dense[i]))

                                            def sort_priority(item):
                                                f, imp, val = item
                                                is_failed_protocol = 1 if (f in ['auth_spf_fail', 'auth_dkim_fail',
                                                                                 'auth_dmarc_fail'] and val == 1) else 0
                                                return (is_failed_protocol, imp)

                                            impact_list.sort(key=sort_priority, reverse=True)

                                            cnt = 1
                                            for f, imp, val in impact_list:
                                                if cnt > 4: break

                                                is_failed_protocol = (f in ['auth_spf_fail', 'auth_dkim_fail',
                                                                            'auth_dmarc_fail'] and val == 1)

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
                                                            prefix = "[Securitate Critică]" if is_failed_protocol else "[Antet]"
                                                            self.log(
                                                                f"   {cnt}. {prefix} -> {EXPLICATII_SISTEM.get(f, f)}")
                                                            cnt += 1
                                                    elif f == "link":
                                                        if val > 0:
                                                            self.log(
                                                                f"   {cnt}. [Conținut] -> {EXPLICATII_SISTEM.get('link')}")
                                                            cnt += 1
                                                    else:
                                                        if val > 0 and imp > 0.01:
                                                            self.log(f"   {cnt}. [Text] -> Limbaj suspect: '{f}'")
                                                            cnt += 1

                                            if cnt == 1:
                                                self.log(
                                                    "   -> Scorul a fost calculat pe baza traseului ascuns și a formatului atipic.")

                                        except Exception as e:
                                            self.log(
                                                f"   [Eroare Modul SHAP]: Explicația indisponibilă momentan. Detalii: {e}")
                                    # ========================================================

                                    if prediction == 1:
                                        self.log(f"\nVERDICT FINAL: [PHISHING / SPAM DETECTAT]")
                                    else:
                                        self.log(f"\nVERDICT FINAL: [MESAJ SIGUR]")
                                    self.log("=" * 50 + "\n")

                                last_checked_uid = latest_uid

                    for _ in range(5):
                        if not self.is_running: break
                        time.sleep(1)

            except Exception as e:
                if self.is_running:
                    self.log(f"\nS-a pierdut conexiunea cu serverul ({e}). Se reinițializează...")
                    time.sleep(5)
                else:
                    break

        try:
            if self.mail_connection: self.mail_connection.logout()
        except:
            pass
        self.log("Deconectare reușită. Monitorizare oprită.")

    def decode_mime_words(self, s):
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

    def check_suspicious_language(self, text_to_scan, threshold=0.05):
        if not text_to_scan: return False, ""
        clean_text = re.sub(r'\s+', '', text_to_scan)
        if len(clean_text) < 10: return False, ""
        asian_chars = re.findall(r'[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]', clean_text)
        ratio = len(asian_chars) / len(clean_text)
        if ratio > threshold: return True, f"Detectat {ratio:.1%} caractere nepermise (Asiatice)."
        return False, ""

    def extract_features_from_raw(self, raw_html_or_text):
        try:
            msg = email.message_from_string(raw_html_or_text)
            header_features = {}
            attachments = []
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
                            attachments.append(
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

            return f"{subject} {body}", header_features, attachments, msg
        except:
            return None, None, [], None


if __name__ == "__main__":
    app = SocMonitorApp()
    app.mainloop()