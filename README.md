# pyprotect
Protect your files by trhacknon
inject_protector.py

Usage:
  ```bash
  python protectme.py <fichier_local.py> <url_fichier_distant>
  ```

  ```bash
  python protectme.py --remove <fichier_local.py>
  ```

Le protecteur compare le code local* (hors bloc protecteur) avec le code distant.
*Le fichier distant doit contenir le code original sans bloc protecteur.

## Example

```bash
python protectme.py example.py
```
