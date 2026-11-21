import os
import email
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.preprocessing import MinMaxScaler
from scipy.sparse import hstack
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, ConfusionMatrixDisplay
from sklearn.model_selection import GridSearchCV

dataset_dir = r"C:\Users\mihne\Desktop\facultate\proiect licenta\Dataset"

dataset_folders = {
    'easy_ham': 0,
    "easy_ham_2": 0,
    "hard_ham": 0,
    "spam" : 1,
    "spam_2" : 1,
}

def extract_features(filepath):
    try:
        with open(filepath, 'r', encoding='latin-1') as f:
            content = f.read()

        msg = email.message_from_string(content)
        header_features = {}

        received = msg.get_all('Received')
        header_features['count_received'] = len(received) if received else 0

        # return_path = msg.get('Return-Path', '').strip('<> ')
        # sender = msg.get('From', '')
        #
        # if return_path and return_path in sender:
        #     header_features['sender_return_path_match'] = 1
        # else:
        #     header_features['sender_return_path_match'] = 0

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

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body = payload.decode('latin-1', errors='ignore')
                        except:
                            pass
                    break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    body = payload.decode('latin-1', errors='ignore')
                except:
                    pass

        text = f"{subject} {body}"

        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
        header_features['url_count'] = len(urls)

        if urls:
            combined_urls = "".join(urls).lower()
            header_features['avg_url_length'] = len(combined_urls) / len(urls)
            header_features['max_dots'] = max([u.count('.') for u in urls])
            header_features['has_ip_url'] = 1 if re.search(r'\d{1,3}\.\d{1,3}', combined_urls) else 0
            header_features['suspicious_chars'] = sum(1 for c in combined_urls if c in ['@', '-', '_', '='])
        else:
            header_features['avg_url_length'] = 0
            header_features['has_ip_url'] = 0
            header_features['suspicious_chars'] = 0
            header_features['max_dots'] = 0

        return text, header_features

    # except Exception as e:
    #     return None, None
    except Exception as e:
        print(f"Eroare la fisierul {filepath}: {e}")
        return None, None


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


print("Se citesc datele din foldere")
texts = []
numerical_data = []
labels = []

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
            text, headers = extract_features(file_path)

            if text:
                texts.append(text)
                labels.append(label)
                numerical_data.append(list(headers.values()))

print(f"\nTotal mail-uri incarcare cu succes: {len(labels)}")
print(f"Distributie: {pd.Series(labels).value_counts().to_dict()}")

print("\nVectorizez textul (CountVectorizer)")
vectorizer = CountVectorizer(stop_words='english', max_features=3000)
X_text = vectorizer.fit_transform(texts)

print("Scalez caracteristicile numerice (MinMaxScaler)")
scaler = MinMaxScaler()
X_headers_scaled = scaler.fit_transform(np.array(numerical_data))

print("Combin caracteristicile din text cu cele din headere")
X_final = hstack([X_text, X_headers_scaled])
y = np.array(labels)

X_train, X_test, y_train, y_test = train_test_split(X_final, y, test_size = 0.2, random_state=42)
print("Regresia Logistica INCEPE ACUM")

param_grid = {
    'C': [0.1, 1.0, 10.0, 100.0],
    'class_weight': [None, 'balanced'],
    'solver': ['liblinear', 'lbfgs']
}

model = LogisticRegression(max_iter=2000, random_state=42)

print("Setari optime:")
grid_search = GridSearchCV(estimator=model, param_grid=param_grid, cv=5, scoring='f1_macro', n_jobs=-1)
grid_search.fit(X_train, y_train)

best_log_model = grid_search.best_estimator_

print(f"\nCei mai buni parametri gasiti automat: {grid_search.best_params_}")

y_pred_log = best_log_model.predict(X_test)
print(f"Acuratete Regresie Logistica: {accuracy_score(y_test, y_pred_log):.2%}")
print("\nRaport Detaliat:")
print(classification_report(y_test, y_pred_log, target_names=['Safe Email', 'Phishing/Spam']))
plot_confusion_matrix(y_test, y_pred_log, 'Matrice Confuzie - Regresie Logistica',
                      '../src/matricea_de_confuzie_regresie_logistica.png')





