import os
import email
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
#import matplotlib.subplots as plt
import re
#from scipy.linalg.cython_lapack import dposv
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, ConfusionMatrixDisplay
from scipy.sparse import hstack

dataset_dir = r"C:\Users\mihne\Desktop\facultate\proiect licenta\Dataset"

dataset_folders = {
    'easy_ham': 0,
    'easy_ham_2': 0,
    'hard_ham': 0,
    'spam': 1,
    'spam_2': 1
}

def extract_features(filepath):

    try:
        with open(filepath, 'r', encoding='latin-1') as f:
            content = f.read()

        msg = email.message_from_string(content)
        header_features = {}

        # received = msg.get_all('Received')
        # header_features['count_received'] = len(received)
        #
        # return_path = msg.get('Return-Path', '').strip('<> ')
        # sender = msg.get('From', '')
        #
        # if(return_path and return_path in sender):
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
                if part.get_content_type() == 'text/plain':
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

        return text, header_features

    except Exception as e:
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


print("Citirea datelor din foldere")

texts = []
numerical_data = []
labels = []

for folder,label in dataset_folders.items():
    folder_path = os.path.join(dataset_dir, folder)
    if not os.path.exists(folder_path):
        print(f"Folder '{folder}' non existent")
        continue

    print(f"Folder '{folder}' existent (Label: {label})")

    files = os.listdir(folder_path)
    for file in files:
        file_path = os.path.join(folder_path, file)
        if os.path.isfile(file_path) and not file.startswith('.'):
            text, headers = extract_features(file_path)
            if text:
                texts.append(text)
                labels.append(label)
                numerical_data.append(list(headers.values()))


print(f"\n Total mail uri incarcate: {len(labels)}")

print("\n Vectorizez textul")
vectorizer = TfidfVectorizer(stop_words='english', max_features=3000)
X_text = vectorizer.fit_transform(texts)

print("Scalez caracteristicile numerice")
scaler = MinMaxScaler()
X_headers_scaled = scaler.fit_transform(np.array(numerical_data))

print("Combin caracteristicile din text cu cele din headere")
X_final = hstack([X_text, X_headers_scaled])
y = np.array(labels)

print("\n Impart datele si antrenez modelul Naive Bayes")
X_train, X_test, y_train, y_test = train_test_split(X_final, y, test_size=0.2, random_state=42)

print("\nOptimizare Naive Bayes")
param_grid = {
    'alpha': [0.01, 0.1, 0.5, 1.0, 2.0],
    'fit_prior': [True, False],
}

model = MultinomialNB()
grid_search = GridSearchCV(estimator=model, param_grid=param_grid, cv=5, scoring='f1_macro', n_jobs=-1)
grid_search.fit(X_train, y_train)

best_nb_model = grid_search.best_estimator_

print(f"Parametrii cei mai buni: {grid_search.best_params_}")
y_pred = best_nb_model.predict(X_test)

print(f" Acuratetea: {accuracy_score(y_test, y_pred):.2%}")
print("\nRaport Detaliat:")
print(classification_report(y_test, y_pred, target_names=['Safe Email', 'Phishing/Spam']))
plot_confusion_matrix(y_test, y_pred, 'Matricea de confuzie - Naive Bayes Optimizat',
                      '../src/matricea_de_confuzie_naive_bayes.png')
