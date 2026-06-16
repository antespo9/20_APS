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

## Verifica e riproduzione

Eseguire la suite di test completa:

```powershell
python -m pytest
```

Eseguire la demo testuale end-to-end:

```powershell
python -m evoting.demo
```

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

## Benchmark prestazionali

I benchmark WP4 misurano operazioni gia' implementate senza modificare il
protocollo. Il profilo `smoke` e' pensato per controlli rapidi e test
automatici; il profilo `full` usa piu' ripetizioni e scale maggiori per la
raccolta dei risultati.

```powershell
python -m evoting.benchmarks.runner --profile smoke
python -m evoting.benchmarks.runner --profile full
```

Per indicare esplicitamente la directory predefinita:

```powershell
python -m evoting.benchmarks.runner --profile smoke --output runtime/benchmarks
```

Il runner stampa una tabella testuale e salva JSON e CSV sotto
`runtime/benchmarks/` per impostazione predefinita. I risultati contengono solo
nomi tecnici delle operazioni, tempi aggregati, conteggi, scale di input e
dimensioni dei messaggi.
