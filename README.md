# APS E-Voting WP4

Simulatore stand-alone del protocollo crittografico di voto elettronico
descritto nel Project Work di Algoritmi e Protocolli per la Sicurezza.

## Documentazione principale

- docs/ProjectWorkAPS.pdf: WP1, WP2 e WP3 del gruppo
- docs/tracciaProgetto.pdf: traccia ufficiale del progetto

## Ambiente di sviluppo

- Python
- cryptography
- pytest
- Git

Il codice applicativo si trova in src/evoting.
I test si trovano nella cartella tests.

## Demo locale

La dimostrazione grafica locale usa solo `tkinter` e `tkinter.ttk` della
libreria standard:

```powershell
python -m evoting.gui.app
```

Per ambienti senza display e test automatici e' disponibile il controllo
headless:

```powershell
python -m evoting.gui.app --check
```
