import tarfile
import os

# 1. Identificăm automat calea către folderul Downloads
downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")

# Numele fișierului cum l-ai spus tu
base_filename = "enron_mail_20150507"

# Verificăm variantele posibile de nume (cu sau fără extensie)
possible_paths = [
    os.path.join(downloads_folder, base_filename + ".tar.gz"),  # Cel mai probabil
    os.path.join(downloads_folder, base_filename),  # Dacă extensia e ascunsă sau ștearsă
    os.path.join(downloads_folder, base_filename + ".tgz")  # O altă variantă posibilă
]

found_path = None
for path in possible_paths:
    if os.path.exists(path):
        found_path = path
        break

if not found_path:
    print(f"❌ EROARE: Nu am găsit fișierul '{base_filename}' în folderul: {downloads_folder}")
    print("Te rog verifică dacă numele fișierului este exact acesta.")
else:
    print(f"✅ Am găsit arhiva la: {found_path}")
    print("⏳ Încerc să citesc conținutul (poate dura câteva secunde)...")

    try:
        # Încercăm să deschidem arhiva (mode='r:*' detectează automat compresia gz, bz2 etc.)
        with tarfile.open(found_path, "r:*") as tar:
            print("✅ Arhiva s-a deschis corect! Citim primele 3 emailuri...")

            count = 0
            for member in tar:
                # Căutăm doar fișiere (nu foldere)
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        content = f.read()
                        print(f"\n--- Email găsit: {member.name} ---")
                        print(f"Mărime: {member.size} bytes")

                        try:
                            # Încercăm decodarea textului
                            text_preview = content.decode('latin-1')
                            print(f"PREVIEW:\n{text_preview[:200]}...")
                        except:
                            print("[Conținut binar sau nedecodabil]")

                        count += 1
                        if count >= 3:
                            break

            if count == 0:
                print("⚠️ Arhiva pare validă, dar nu am găsit fișiere în ea (poate conține doar foldere goale?).")
            else:
                print("\n✅ CONCLUZIE: Fișierul tău este BUN. Problema anterioară era la dezarhivarea manuală.")

    except tarfile.ReadError:
        print("❌ EROARE CRITICĂ: Fișierul există, dar este corupt sau nu este o arhivă validă.")
        print("Soluție: Trebuie să ștergi fișierul și să îl descarci din nou.")
    except Exception as e:
        print(f"❌ A apărut o altă eroare: {e}")