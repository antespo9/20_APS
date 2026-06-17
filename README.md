# APS E-Voting WP4

Simulatore stand-alone del protocollo crittografico di voto elettronico
descritto nel Project Work di Algoritmi e Protocolli per la Sicurezza.

## Ambiente di sviluppo

- Python
- cryptography
- pytest
- Git

Il codice applicativo si trova in src/evoting.
I test si trovano nella cartella tests.

## Avvio rapido

Aprire un terminale nella cartella principale del progetto, cioè quella che contiene:

```text
README.md
pyproject.toml
src/
tests/
```

### Windows PowerShell

Creare e attivare un ambiente virtuale:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Se PowerShell impedisce l'attivazione:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Installare il progetto e le dipendenze di sviluppo:

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Esecuzione dei test

Eseguire l'intera suite:

```powershell
python -m pytest
```

Risultato atteso:

```text
282 passed
```

Eseguire soltanto una categoria:

```powershell
python -m pytest tests/unit
python -m pytest tests/integration
python -m pytest tests/security
python -m pytest tests/benchmark
```

Verificare inoltre che tutti i file Python siano compilabili:

```powershell
python -m compileall -q src tests
```

Se il comando termina senza output, il controllo è riuscito.

## Esecuzione del prototipo

Demo testuale completa:

```powershell
python -m evoting.demo
```

Il flusso deve terminare con:

```text
Esito finale: OK
```

Controllo della GUI senza apertura della finestra:

```powershell
python -m evoting.gui.app --check
```

Risultato atteso:

```text
GUI check OK
```

Avvio della GUI:

```powershell
python -m evoting.gui.app
```

Benchmark rapido:

```powershell
python -m evoting.benchmarks.runner --profile smoke
```


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
