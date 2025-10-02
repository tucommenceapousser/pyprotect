# example.py
# ======= FICHIER ORIGINAL POUR DEMO =======
# Héberge ce fichier (tel quel) sur une URL brute (ex: GitHub raw, raw.githack, gist, or a simple web server).
# Ne pas y ajouter le bloc protecteur — il s'agit de la version *originale* que le protecteur téléchargera et comparera.

"""Petit script de démonstration.
Fonctions :
 - greet(name): retourne une salutation
 - compute_factorial(n): calcule la factorielle (exemple de logique)
 - main(): exécute un petit flux de démonstration

Ce fichier est volontairement simple pour tester le mécanisme d'intégrité.
"""

import sys


def greet(name: str) -> str:
    """Retourne une salutation formatée."""
    return f"Bonjour, {name}! Bienvenue dans la démo."


def compute_factorial(n: int) -> int:
    """Calcule la factorielle de n (entier >= 0).
    Utilisation d'une boucle pour rester simple et lisible.
    """
    if n < 0:
        raise ValueError("n doit être >= 0")
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result


def main():
    # Petit scénario de démonstration
    name = "trhacknon"
    try:
        n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    except Exception:
        n = 5

    print(greet(name))
    print(f"Factorielle de {n} = {compute_factorial(n)}")


if __name__ == "__main__":
    main()
