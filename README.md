# pyprotect

Protect your files by trhacknon
protectme.py

![trhacknon](https://i.top4top.io/p_3562rl2pp0.jpg)


# Usage:

## 1) rendre le script exécutable (optionnel)

```bash
chmod +x protectme.py
```

## 2) (re)générer clés si besoin

```bash
python3 protectme.py --generate-keys priv.pem pub.pem
```

## 3) assurer que example.py n'a pas déjà un bloc ou le retirer

```bash
python3 protectme.py --remove example.py || true
```


## 4) signer & append

```bash
python3 protectme.py --sign-inject priv.pem pub.pem example.py
```

## 5) tester

```bash
python3 example.py
```

![trhacknon](https://d.top4top.io/p_3562cc2790.jpg)
