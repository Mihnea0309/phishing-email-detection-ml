import pandas as pd
from datetime import datetime

# Load the current CSV
df = pd.read_csv('registrars.csv')

# List of popular registrars
popular_registrars = [
    {
        'iana_id': 1910, 'name': 'Cloudflare, Inc.', 'link': 'https://www.cloudflare.com',
        'email': 'abuse@cloudflare.com', 'form': 'https://abuse.cloudflare.com/',
        'api': '', 'notes': 'Updated manually', 'found': True, 'as_of': datetime.now().strftime('%Y-%m-%d')
    },
    {
        'iana_id': 146, 'name': 'GoDaddy.com, LLC', 'link': 'https://www.godaddy.com',
        'email': 'abuse@godaddy.com', 'form': 'https://supportcenter.godaddy.com/abuse',
        'api': '', 'notes': 'Updated manually', 'found': True, 'as_of': datetime.now().strftime('%Y-%m-%d')
    },
    {
        'iana_id': 1068, 'name': 'Namecheap, Inc.', 'link': 'https://www.namecheap.com',
        'email': 'abuse@namecheap.com', 'form': 'https://support.namecheap.com/index.php?/Tickets/Submit',
        'api': '', 'notes': 'Updated manually', 'found': True, 'as_of': datetime.now().strftime('%Y-%m-%d')
    },
    {
        'iana_id': 69, 'name': 'Tucows Domains Inc.', 'link': 'https://tucowsdomains.com',
        'email': 'domainabuse@tucows.com', 'form': 'https://tucowsdomains.com/report-abuse/',
        'api': '', 'notes': 'Updated manually', 'found': True, 'as_of': datetime.now().strftime('%Y-%m-%d')
    },
    {
        'iana_id': 81, 'name': 'IONOS SE', 'link': 'https://www.ionos.com',
        'email': 'abuse@ionos.com', 'form': 'https://www.ionos.com/help/contact',
        'api': '', 'notes': 'Updated manually', 'found': True, 'as_of': datetime.now().strftime('%Y-%m-%d')
    },
    {
        'iana_id': 135, 'name': 'OVH sas', 'link': 'https://www.ovh.com',
        'email': 'abuse@ovh.net', 'form': 'https://www.ovh.com/abuse/',
        'api': '', 'notes': 'Updated manually', 'found': True, 'as_of': datetime.now().strftime('%Y-%m-%d')
    },
    {
        'iana_id': 1860, 'name': 'Porkbun LLC', 'link': 'https://porkbun.com',
        'email': 'abuse@porkbun.com', 'form': 'https://porkbun.com/abuse',
        'api': '', 'notes': 'Updated manually', 'found': True, 'as_of': datetime.now().strftime('%Y-%m-%d')
    },
    {
        'iana_id': 468, 'name': 'Amazon Registrar, Inc.', 'link': 'https://aws.amazon.com/route53/',
        'email': 'trustandsafety@support.aws.com', 'form': 'https://support.aws.amazon.com/#/contacts/report-abuse',
        'api': '', 'notes': 'Updated manually', 'found': True, 'as_of': datetime.now().strftime('%Y-%m-%d')
    }
]

updated_count = 0
added_count = 0

for reg in popular_registrars:
    # Cautam daca exista IANA ID-ul in CSV
    mask = df['iana_id'] == reg['iana_id']

    if mask.any():
        # Daca exista, facem UPDATE la email, form si link
        df.loc[mask, 'email'] = reg['email']
        df.loc[mask, 'form'] = reg['form']
        df.loc[mask, 'link'] = reg['link']
        df.loc[mask, 'notes'] = reg['notes']
        updated_count += 1
    else:
        # Daca totusi nu exista, il adaugam ca rand nou
        new_row = pd.DataFrame([reg])
        df = pd.concat([df, new_row], ignore_index=True)
        added_count += 1

# Sortam dupa IANA ID si salvam noul fisier
df = df.sort_values(by='iana_id').reset_index(drop=True)
df.to_csv('registrars_updated.csv', index=False)

print(f"Am actualizat {updated_count} registranți existenți.")
print(f"Am adăugat {added_count} registranți noi.")
print("Fișierul 'registrars_updated.csv' a fost generat cu succes!")