# Clasa CatalogNote
# Atribut studenti - dictionar care tine lista de studenti si notele lor
# Citim din CSV cu csv.DictReader
# metoda medie -> Calculeaza media notelor
# metoda note_peste(prag) -> notele peste pragul setat
# metoda __len__ returneaza numarul de studenti
# metoda __iter__

import csv

class CatalogNote:
    def __init__(self, studenti):
        self.studenti = studenti

    @classmethod
    def from_csv(cls, path):
        lista = []
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                lista.append({
                    "nume":row["nume"],
                    "nota":int(row["nota"])
                })
        return cls(lista)

    def __set__(self, instance, value):
        self.instance = instance
        self.value = value

    def medie(self):
        if not self.studenti:
            return 0
        total = 0
        for s in self.studenti:
            total += s['nota']
        return total / len(self.studenti)

    def note_peste(self, prag):
        rezultat = []
        for s in self.studenti:
            if s["nota"] > prag:
                rezultat.append(s["nume"])
        return rezultat

    def __len__(self):
        return len(self.studenti)

    def __iter__(self):
        for s in self.studenti:
            yield s

    # Scriere in CSV
    # Metoda to_csv creeaza un CSV identic cu cel primit ca input.
    # In parametrul "path" ii dam denumirea noului fisier ce va fi creeat.
    # Parametrul "fieldnames" din cadrul functiei DictWriter seteaza denumirile coloanelor.
    # Cu functia writeheader imi adauga denumirile coloanelor ce au fost setate anterior.
    # Cu functia writerows imi adauga continutul liniilor din studenti,
    # care este o lista de dictionare cu cheile "nume" si "nota"

    def to_csv(self, path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["nume", "nota"])
            writer.writeheader()
            writer.writerows(self.studenti)

catalog = CatalogNote.from_csv("nume.csv")
print(f"Numar studenti: {len(catalog)}")
for s in catalog.studenti:
    print(f"Nume: {s['nume']}, Nota: {s['nota']}")

print("Media studentilor:", catalog.medie())

print("Studentii cu nota peste 7:")
for s in catalog.note_peste(7):
    print("-", s)

catalog.to_csv("catalog_complet.csv")
print("Datele au fost adaugate in CSV cu succes!")