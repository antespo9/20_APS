# Piano di implementazione WP4

L'implementazione deve procedere una milestone alla volta. Ogni milestone deve partire da repository pulita o da modifiche chiaramente attribuibili alla milestone corrente, deve modificare solo i file indicati e deve concludersi con test applicabili superati. Non si passa alla milestone successiva se quella corrente non e' completa.

## Milestone 0 - Documentazione di base WP4

Obiettivo: definire requisiti, architettura, piano, tracciabilita' e decisioni implementative prima del codice.

File da creare o modificare:

- `docs/requirements.md`
- `docs/architecture.md`
- `docs/implementation-plan.md`
- `docs/traceability.md`
- `docs/decisions.md`

Dipendenze: PDF di progetto, traccia ufficiale, `README.md`, `pyproject.toml`.

Criteri di completamento:

- i cinque documenti sono coerenti tra loro;
- i requisiti WP4 sono coperti;
- non sono modificati codice, test, configurazione, PDF o file locali esclusi dal versionamento;
- i test esistenti passano.

Test richiesti:

- test esistenti della repository.

Comandi di verifica:

```powershell
python -m pytest
git status --short
```

Benchmark associati: nessuno, perche' la milestone non introduce codice misurabile.

## Milestone 1 - Modelli dati e serializzazione canonica

Obiettivo: introdurre esclusivamente i modelli dati del protocollo, la serializzazione canonica unica e i test unitari e di alterazione correlati.

File da creare o modificare:

- `src/evoting/models.py`
- `src/evoting/serialization.py`
- `src/evoting/errors.py`
- `tests/unit/test_models.py`
- `tests/unit/test_serialization.py`
- `tests/security/test_serialization_tampering.py`

Dipendenze: Milestone 0.

Criteri di completamento:

- tutti i messaggi principali hanno un modello tipizzato;
- la serializzazione canonica rispetta `SR-001` e `SR-002`;
- lo stesso valore produce sempre gli stessi byte canonici;
- cambiamenti di campo, ordine logico, valori binari, timestamp o `null` producono digest diversi quando previsto;
- non sono presenti serializzazioni alternative per dati firmati o sottoposti ad hash.

Test richiesti:

- round trip dei modelli ammessi;
- ordinamento deterministico dei campi;
- codifica Base64 standard con padding;
- gestione esplicita di interi, timestamp e `null`;
- rifiuto di tipi non previsti;
- test di alterazione su messaggi firmabili e hashabili.

Comandi di verifica:

```powershell
python -m pytest
```

Benchmark associati:

- nessun benchmark obbligatorio;
- opzionale: dimensione in byte dei messaggi canonici principali come base per `BR-002`.

## Milestone 2 - Primitive crittografiche di base

Obiettivo: implementare wrapper coerenti per hash, firme, cifratura del voto, Scrypt e AES-GCM.

File da creare o modificare:

- `src/evoting/crypto/hashes.py`
- `src/evoting/crypto/signatures.py`
- `src/evoting/crypto/encryption.py`
- `src/evoting/crypto/password.py`
- `src/evoting/crypto/aead.py`
- `tests/unit/test_hashes.py`
- `tests/unit/test_signatures.py`
- `tests/unit/test_encryption.py`
- `tests/unit/test_password.py`
- `tests/unit/test_aead.py`
- `tests/security/test_crypto_tampering.py`

Dipendenze: Milestone 1.

Criteri di completamento:

- SHA-256 e' usato per digest, pseudonimi, identificativi e hash chain;
- RSA-OAEP usa SHA-256 per OAEP e MGF1;
- RSA-PSS usa SHA-256, MGF1 SHA-256 e salt massimo consentito;
- Scrypt usa salt distinti e parametri persistibili;
- AES-256-GCM usa nonce casuale da 12 byte e AAD contestuale;
- errori crittografici interni sono convertiti in errori applicativi generici.

Test richiesti:

- firme valide accettate e firme alterate rifiutate;
- cifrature dello stesso voto diverse per casualita' fresca;
- decifratura di ciphertext alterati rifiutata;
- verifier password corretto e password errata rifiutata;
- tag AEAD o AAD alterati rifiutati.

Comandi di verifica:

```powershell
python -m pytest
```

Benchmark associati:

- cifratura voto;
- firma pacchetto;
- verifica firma;
- dimensione ciphertext e firma.

## Milestone 3 - Shamir Secret Sharing e protezione di `blobTA`

Obiettivo: implementare la custodia distribuita di `Kwrap` e la protezione della chiave privata di decifratura TA.

File da creare o modificare:

- `src/evoting/crypto/shamir.py`
- `src/evoting/actors/commissioners.py`
- `src/evoting/actors/tallying_authority.py`
- `tests/unit/test_shamir.py`
- `tests/security/test_shamir_negative.py`
- `tests/integration/test_ta_blob_protection.py`

Dipendenze: Milestone 2.

Criteri di completamento:

- Shamir usa `P = 2^521 - 1`;
- `Kwrap` e' interpretata come intero big-endian;
- quote duplicate, nulle, malformate o fuori campo sono rifiutate;
- almeno `t` quote valide ricostruiscono `Kwrap`;
- meno di `t` quote non consentono di aprire `blobTA`;
- una quota alterata produce fallimento AEAD su `blobTA`.

Test richiesti:

- ricostruzione positiva con soglia;
- fallimento sotto soglia;
- rifiuto input non validi;
- apertura `blobTA` solo con `Kwrap` corretta.

Comandi di verifica:

```powershell
python -m pytest
```

Benchmark associati:

- generazione quote Shamir;
- ricostruzione `Kwrap`;
- apertura `blobTA`.

## Milestone 4 - Registration Authority e stato pseudonimo elettore

Obiettivo: implementare autenticazione simulata, emissione autorizzazione unica e persistenza cifrata dello stato elettore.

File da creare o modificare:

- `src/evoting/actors/registration_authority.py`
- `src/evoting/actors/voter.py`
- `src/evoting/persistence/stores.py`
- `src/evoting/persistence/voter_state.py`
- `tests/unit/test_registration_authority.py`
- `tests/integration/test_voter_state_persistence.py`
- `tests/security/test_authorization_tampering.py`

Dipendenze: Milestone 2.

Criteri di completamento:

- credenziali corrette emettono una sola autorizzazione;
- credenziali errate, elettori non aventi diritto e seconde richieste sono rifiutati;
- lo stato elettore e' cifrato e recuperabile;
- stato perso o corrotto non consente nuova autorizzazione o sostituzione;
- nessun archivio collega identita', pseudonimo e voto.

Test richiesti:

- autenticazione positiva e negativa;
- emissione unica;
- autorizzazione alterata rifiutata;
- persistenza e recupero;
- contenitore cifrato alterato rifiutato.

Comandi di verifica:

```powershell
python -m pytest
```

Benchmark associati:

- emissione autorizzazione RA;
- derivazione Scrypt per verifier;
- apertura stato cifrato elettore.

## Milestone 5 - Bulletin Board

Obiettivo: implementare validazione pacchetti, registro append-only, hash chain, ricevute e chiusura.

File da creare o modificare:

- `src/evoting/actors/bulletin_board.py`
- `tests/unit/test_bulletin_board_rules.py`
- `tests/security/test_bulletin_board_tampering.py`
- `tests/integration/test_vote_replacement.py`

Dipendenze: Milestone 4.

Criteri di completamento:

- pacchetti validi sono accettati e producono ricevute firmate;
- replay, versioni errate, firme errate, autorizzazioni errate, cambio chiave pseudonima, superamento `Vmax` e voto dopo `CLOSE` sono rifiutati;
- hash chain rileva alterazioni, cancellazioni e riordinamenti;
- `CLOSE` produce `h_close` e firma BB.

Test richiesti:

- regole di accettazione e rifiuto;
- verifica ricevuta;
- alterazioni hash chain;
- sostituzioni valide e invalide.

Comandi di verifica:

```powershell
python -m pytest
```

Benchmark associati:

- verifica BB;
- aggiornamento hash chain;
- verifica ricevuta;
- dimensione pacchetto e ricevuta.

## Milestone 6 - Scrutinio e verifica pubblica

Obiettivo: implementare selezione schede finali, scrutinio, risultato firmato, verifica individuale e verifica pubblica.

File da creare o modificare:

- `src/evoting/actors/tallying_authority.py`
- `src/evoting/actors/verifier.py`
- `tests/integration/test_tally_workflow.py`
- `tests/integration/test_public_verification.py`
- `tests/security/test_tally_negative.py`

Dipendenze: Milestone 5.

Criteri di completamento:

- scrutinio possibile solo dopo `CLOSE`;
- sono decifrate solo le schede finali valide;
- plaintext fuori dominio e ciphertext malformati sono gestiti come anomalie o errori applicativi generici secondo il punto del flusso;
- risultato firmato vincolato a `h_close`;
- verifica pubblica controlla firme, hash chain, versioni, unicita' e coerenza numerica;
- verifica individuale controlla ricevuta e inclusione.

Test richiesti:

- scrutinio positivo;
- avvio prima di `CLOSE` rifiutato;
- conteggio con anomalie;
- firma risultato alterata rifiutata;
- verifica pubblica completa.

Comandi di verifica:

```powershell
python -m pytest
```

Benchmark associati:

- scrutinio;
- verifica pubblica del registro;
- crescita lineare della verifica al crescere degli eventi.

## Milestone 7 - Workflow completo e benchmark

Obiettivo: fornire una dimostrazione end-to-end locale e benchmark separati delle operazioni richieste.

File da creare o modificare:

- `src/evoting/config.py`
- `src/evoting/benchmarks/runner.py`
- `tests/integration/test_complete_election_workflow.py`
- `tests/performance/test_benchmark_smoke.py`

Dipendenze: Milestone 6.

Criteri di completamento:

- scenario dimostrativo con `Vmax = 3`, `t = 3`, `n = 5`;
- workflow completo eseguibile localmente;
- benchmark distinti per le operazioni richieste;
- risultati benchmark generati sotto `runtime/benchmarks/` e non preparati per il versionamento.

Test richiesti:

- workflow completo;
- smoke test benchmark;
- assenza di dati riservati nei risultati benchmark.

Comandi di verifica:

```powershell
python -m pytest
```

Benchmark associati:

- tutti quelli definiti da `BR-001` a `BR-008`.

## Regole operative per ogni milestone

Prima di iniziare una milestone:

1. ispezionare lo stato della repository;
2. confermare i requisiti coinvolti;
3. elencare i file da modificare;
4. evidenziare decisioni sensibili e ambiguita' eventuali.

Prima di chiudere una milestone:

1. eseguire i test applicabili;
2. verificare che siano stati modificati solo i file previsti;
3. verificare che non siano stati creati archivi runtime versionabili;
4. sintetizzare requisiti coperti, test e limiti residui;
5. non creare commit o push senza richiesta esplicita.
