# Requisiti WP4

Questo documento definisce i requisiti del prototipo WP4 per il protocollo di voto elettronico. Il prototipo realizza una simulazione stand-alone e locale del protocollo descritto nel WP2, senza modificare le proprieta' e i compromessi gia' definiti: pseudoanonimato basato sulla separazione dei ruoli, verificabilita' individuale, controllo pubblico del registro, verificabilita' universale del tally solo parziale e fiducia residua nella Tallying Authority.

## Requisiti funzionali

| ID | Requisito |
| --- | --- |
| FR-001 | Il sistema deve simulare localmente gli attori logici Registration Authority, Bulletin Board, Tallying Authority, elettore, commissari elettorali e verificatore pubblico. |
| FR-002 | Il sistema deve gestire una elezione a lista chiusa con codici di lista ammessi e pubblicati nei parametri dell'elezione. |
| FR-003 | Il sistema deve generare e pubblicare i parametri dell'elezione: `election_id`, liste ammesse, periodo di apertura e chiusura, numero totale degli aventi diritto, chiavi pubbliche, parametri `(t, n)` e `Vmax`. |
| FR-004 | Il sistema deve generare coppie di chiavi distinte per RA, BB, TA di cifratura, TA di firma e chiave pseudonima dell'elettore. |
| FR-005 | La RA deve autenticare nominativamente gli elettori usando un archivio riservato degli aventi diritto. |
| FR-006 | La RA deve emettere al massimo una autorizzazione pseudonima per ciascun elettore e per ciascuna elezione. |
| FR-007 | L'elettore deve generare localmente il segreto `t_i`, lo pseudonimo pubblico `p_i = H(t_i)` e la coppia di chiavi pseudonima `(pk_vote_i, sk_vote_i)`. |
| FR-008 | L'autorizzazione RA deve vincolare `election_id`, `p_i` e `pk_vote_i` senza includere l'identita' reale dell'elettore. |
| FR-009 | L'elettore deve cifrare il codice della lista scelta con la chiave pubblica di cifratura della TA. |
| FR-010 | L'elettore deve firmare il pacchetto di voto con la chiave privata pseudonima associata all'autorizzazione. |
| FR-011 | Il Bulletin Board deve ricevere pacchetti di voto contenenti scheda cifrata, pseudonimo, chiave pubblica pseudonima, autorizzazione RA, versione e firma pseudonima. |
| FR-012 | Il Bulletin Board deve validare autorizzazione RA, firma pseudonima, stato dell'elezione, versione e limiti di sostituzione prima di accettare una scheda. |
| FR-013 | Il Bulletin Board deve registrare ogni scheda accettata in un registro append-only con hash chain. |
| FR-014 | Il Bulletin Board deve emettere una ricevuta firmata per ogni scheda accettata. |
| FR-015 | L'elettore deve poter sostituire il voto prima della chiusura usando lo stesso pseudonimo, la stessa autorizzazione e la stessa chiave pseudonima, incrementando la versione in modo consecutivo. |
| FR-016 | Il Bulletin Board deve conservare la storia delle sostituzioni senza cancellare le versioni precedenti. |
| FR-017 | Alla chiusura dell'urna, il Bulletin Board deve registrare un evento `CLOSE`, calcolare `h_close` e firmare lo stato finale del registro. |
| FR-018 | Lo scrutinio deve considerare, per ogni pseudonimo, solo la versione valida piu' alta registrata prima di `CLOSE`. |
| FR-019 | La TA deve avviare lo scrutinio solo dopo `CLOSE` e solo dopo la ricostruzione valida della chiave di protezione tramite almeno `t` quote Shamir. |
| FR-020 | La TA deve decifrare solo le schede finali, classificare come anomale quelle fuori dominio e calcolare i totali per lista. |
| FR-021 | La TA deve pubblicare un risultato firmato vincolato a `election_id`, `h_close`, totali per lista e numero di schede anomale. |
| FR-022 | L'elettore deve poter verificare l'inclusione della propria scheda tramite `t_i`, `p_i`, ricevuta firmata, `RID` e hash chain. |
| FR-023 | Il verificatore pubblico deve poter controllare firme RA, firme pseudonime, hash chain, evento `CLOSE`, firma TA, unicita' della scheda finale per pseudonimo e coerenza numerica del risultato. |
| FR-024 | Il sistema deve supportare parametri configurabili `Vmax`, `t` e `n`, con scenario dimostrativo iniziale `Vmax = 3`, `t = 3`, `n = 5`. |
| FR-025 | Il prototipo deve restare stand-alone e locale: le comunicazioni tra attori sono chiamate locali tra moduli e non connessioni di rete reali. |
| FR-026 | Il prototipo non deve includere microservizi, blockchain, OAuth, database esterni, applicazioni mobili, frontend web complessi o servizi cloud. |

## Requisiti di sicurezza

| ID | Requisito |
| --- | --- |
| SR-001 | Tutti i valori firmati o sottoposti ad hash devono usare una sola implementazione di serializzazione canonica. |
| SR-002 | La serializzazione canonica deve usare UTF-8, ordinamento deterministico dei campi, nessuno spazio non significativo, Unicode mantenuto direttamente, binari in Base64 standard con padding, timestamp UTC in millisecondi Unix, interi come numeri JSON e `null` solo quando previsto dallo schema. |
| SR-003 | La cifratura del voto deve usare RSA-OAEP con SHA-256 per OAEP e MGF1 e casualita' fresca per ogni cifratura. |
| SR-004 | Le firme digitali devono usare RSA-PSS con SHA-256, MGF1 con SHA-256 e salt length massimo consentito dalla libreria. |
| SR-005 | Hash, pseudonimi, identificativi di scheda e hash chain devono usare SHA-256. |
| SR-006 | Le password non devono essere memorizzate; la RA deve conservare solo verifier derivati con Scrypt, salt casuale distinto di 16 byte per utente e parametri memorizzati insieme al verifier. |
| SR-007 | I parametri iniziali Scrypt devono essere `n = 2^15`, `r = 8`, `p = 1`, configurabili e persistiti con il verifier. |
| SR-008 | La chiave privata di decifratura della TA deve essere serializzata e protetta in `blobTA` con AES-256-CBC, padding PKCS7 e HMAC-SHA256 secondo composizione Encrypt-then-Authenticate. |
| SR-009 | `blobTA` deve usare `Kwrap` come segreto casuale di 32 byte; da `Kwrap` devono essere derivate due sottochiavi distinte di 32 byte, `Kenc` e `Kmac`, tramite HKDF-SHA256 con contesto specifico del protocollo. `Kenc` cifra con AES-256-CBC e IV casuale; `Kmac` autentica una serializzazione canonica contenente almeno contesto, `election_id`, IV e ciphertext. Il MAC deve essere verificato prima della decifratura CBC e dell'unpadding PKCS7. `TaBlob` deve contenere IV, ciphertext e MAC, non nonce e tag GCM. Fernet non deve essere usato per `blobTA`. |
| SR-010 | `Kwrap` deve essere suddivisa con una implementazione didattica dello schema standard di Shamir Secret Sharing sul campo primo `P = 2^521 - 1`. |
| SR-011 | `Kwrap` deve essere interpretata come intero big-endian; ogni quota Shamir deve essere una coppia `(x, y)` con `x` distinto e non nullo. |
| SR-012 | La ricostruzione Shamir deve usare interpolazione di Lagrange in zero e rifiutare quote duplicate, malformate o fuori campo. |
| SR-013 | L'implementazione Shamir deve essere documentata come didattica e non come software crittografico destinato alla produzione. |
| SR-014 | Il Bulletin Board non deve mai memorizzare l'identita' reale degli elettori. |
| SR-015 | La Tallying Authority non deve ricevere la lista delle identita' reali degli elettori. |
| SR-016 | Il sistema non deve creare archivi o log che colleghino identita' reale, pseudonimo e voto in chiaro. |
| SR-017 | Le autorizzazioni RA devono essere non falsificabili senza la chiave privata RA. |
| SR-018 | I pacchetti di voto devono essere non falsificabili senza la chiave privata pseudonima dell'elettore. |
| SR-019 | Il solo possesso di `p_i` e dell'autorizzazione `tau_i` non deve bastare per generare o sostituire un voto valido. |
| SR-020 | Il Bulletin Board deve trattare pacchetti identici gia' ricevuti come replay e non deve conteggiarli due volte. |
| SR-021 | Le sostituzioni devono essere accettate solo prima di `CLOSE`, con stessa `pk_vote_i`, versione consecutiva e versione non superiore a `Vmax`. |
| SR-022 | Il registro del Bulletin Board deve essere append-only e tamper-evident tramite hash chain. |
| SR-023 | Errori di ciphertext malformati, MAC o tag di autenticazione errati e plaintext fuori dominio devono produrre errori applicativi generici, senza esporre dettagli interni delle eccezioni crittografiche. |
| SR-024 | Lo scrutinio non deve pubblicare la corrispondenza tra singoli ciphertext e voti in chiaro. |
| SR-025 | Il risultato deve esplicitare il limite di verificabilita' universale parziale: il pubblico verifica coerenza e firme, ma non una prova crittografica di corretta decifratura di ogni scheda. |
| SR-026 | Il sistema deve usare casualita' crittograficamente sicura per segreti, chiavi, IV, nonce, cifrature probabilistiche e coefficienti Shamir. |

## Requisiti di persistenza

| ID | Requisito |
| --- | --- |
| PR-001 | Lo stato pseudonimo dell'elettore deve sopravvivere alla chiusura e riapertura dell'applicazione. |
| PR-002 | Lo stato persistente dell'elettore deve includere, quando disponibili, `t_i`, `p_i`, coppia pseudonima, autorizzazione, versione corrente e ricevute. |
| PR-003 | Lo stato persistente sensibile dell'elettore non deve essere salvato in chiaro. |
| PR-004 | Lo stato persistente dell'elettore deve essere protetto esclusivamente con AES-256-GCM usando una chiave derivata con Scrypt da una password locale fornita dall'utente nel prototipo; la costruzione AES-256-CBC piu' HMAC-SHA256 e' specifica di `blobTA` e non e' richiesta per la persistenza elettore. |
| PR-005 | Il contenitore cifrato dello stato elettore deve memorizzare salt e parametri KDF e usare AAD con contesto applicativo ed `election_id`. |
| PR-006 | Se lo stato locale e' perso, assente, corrotto o non recuperabile, la RA non deve emettere una nuova autorizzazione per la stessa elezione. |
| PR-007 | Se lo stato locale non e' recuperabile, l'elettore non deve poter creare una sostituzione; resta valida l'ultima scheda gia' accettata dal Bulletin Board. |
| PR-008 | Tutti i dati runtime generati devono rimanere sotto `runtime/` e non devono essere preparati per il versionamento. |

## Requisiti di test

| ID | Requisito |
| --- | --- |
| TR-001 | Ogni funzionalita' implementata deve avere test. |
| TR-002 | Devono esistere test unitari per modelli, serializzazione canonica, primitive crittografiche, Shamir e regole di validazione. |
| TR-003 | Devono esistere test di integrazione per il flusso completo di elezione. |
| TR-004 | Devono esistere test di sicurezza e alterazione per messaggi modificati, firme errate, autorizzazioni contraffatte, hash chain alterata, replay, duplicati e messaggi non autorizzati. |
| TR-005 | Devono esistere test di persistenza e recupero dello stato pseudonimo dell'elettore. |
| TR-006 | Devono esistere test negativi per ciphertext malformati, plaintext fuori dominio, MAC `blobTA` errati, tag AES-GCM errati per lo stato elettore e quote Shamir duplicate, malformate o fuori campo. |
| TR-007 | Devono esistere test per la sostituzione del voto: versione consecutiva accettata, versione non consecutiva rifiutata, superamento di `Vmax` rifiutato, voto dopo `CLOSE` rifiutato. |
| TR-008 | Devono esistere test per lo scrutinio: avvio solo dopo `CLOSE`, ricostruzione con almeno `t` quote, fallimento con meno di `t` quote e calcolo corretto dei totali. |
| TR-009 | Devono esistere test per la verifica individuale della ricevuta e per la verifica pubblica del registro e del risultato. |
| TR-010 | Dopo ogni modifica significativa deve essere eseguito `python -m pytest` nell'ambiente previsto dal progetto. |
| TR-011 | Una milestone non e' completa se i test applicabili falliscono. |

## Requisiti prestazionali e benchmark

| ID | Requisito |
| --- | --- |
| BR-001 | I benchmark devono distinguere le operazioni del protocollo e non aggregare misure concettualmente diverse. |
| BR-002 | Ogni misura deve registrare nome operazione, dimensione input, numero di ripetizioni, tempo minimo, mediana, media, deviazione standard e dimensione del messaggio in byte quando applicabile. |
| BR-003 | Devono essere misurati emissione autorizzazione RA, cifratura del voto, firma del pacchetto, verifica BB, aggiornamento hash chain e verifica ricevuta. |
| BR-004 | Devono essere misurati generazione quote Shamir, ricostruzione di `Kwrap`, apertura di `blobTA` e scrutinio. |
| BR-005 | Devono essere misurati verifica pubblica del registro, dimensione del pacchetto di voto, dimensione della ricevuta e crescita della verifica al crescere degli eventi. |
| BR-006 | La generazione delle chiavi non deve essere combinata con il tempo di invio o sottomissione del voto se non come misura separata. |
| BR-007 | Il costo lato elettore deve restare costante rispetto al numero totale di votanti per le operazioni di voto del singolo elettore. |
| BR-008 | Scrutinio e verifica pubblica completa devono essere misurati come operazioni lineari rispettivamente nel numero di schede finali e nel numero di entry pubblicate. |

## Criteri di accettazione verificabili

| ID | Criterio |
| --- | --- |
| AC-001 | Una esecuzione dimostrativa configura una elezione, autentica elettori fittizi, emette autorizzazioni, registra voti, consente sostituzioni valide, chiude l'urna, scrutinia e produce risultato firmato. |
| AC-002 | La RA rifiuta credenziali errate, elettori non aventi diritto e seconde richieste di autorizzazione per la stessa elezione. |
| AC-003 | Il BB accetta un voto valido durante il periodo di apertura e restituisce una ricevuta firmata verificabile. |
| AC-004 | Il BB rifiuta autorizzazioni alterate, firme pseudonime alterate, versioni non valide, replay, pacchetti dopo `CLOSE` e pacchetti oltre `Vmax`. |
| AC-005 | La sostituzione valida lascia nel registro le versioni precedenti e rende conteggiabile solo la versione piu' alta prima di `CLOSE`. |
| AC-006 | La verifica pubblica rileva modifica, cancellazione o riordinamento di una entry pubblicata. |
| AC-007 | Lo scrutinio fallisce con meno di `t` quote Shamir valide e riesce con almeno `t` quote distinte valide. |
| AC-008 | Una quota Shamir alterata non apre correttamente `blobTA` e produce un errore applicativo generico. |
| AC-009 | La perdita dello stato locale dell'elettore impedisce nuove sostituzioni ma non annulla l'ultima scheda accettata dal BB. |
| AC-010 | La suite di test applicabile passa con `python -m pytest`. |
| AC-011 | I benchmark producono misure separate per le operazioni richieste e non includono dati riservati. |

## Formato logico dei messaggi principali

Tutti i messaggi firmati o sottoposti ad hash sono serializzati con la serializzazione canonica definita da `SR-001` e `SR-002`. I campi binari sono rappresentati in Base64 standard con padding.

### Parametri elettorali pubblici

```text
ElectionParams = {
  election_id,
  lists: [{code, label}],
  opens_at_ms,
  closes_at_ms,
  eligible_count,
  pk_ta_enc,
  pk_ta_sig,
  pk_ra,
  pk_bb,
  threshold: {t, n},
  vmax,
  params_hash
}
```

### Richiesta di autorizzazione pseudonima

```text
MAUTH = {
  election_id,
  p_i,
  pk_vote_i
}

tau_i = Sign_RA(MAUTH)
```

### Messaggio firmato dall'elettore

```text
MBALLOT_i = {
  election_id,
  p_i,
  c,
  pk_vote_i,
  v_i
}

sigma_i = Sign_sk_vote_i(MBALLOT_i)
```

### Pacchetto di voto verso il Bulletin Board

```text
VotePackage = {
  c,
  p_i,
  pk_vote_i,
  tau_i,
  v_i,
  sigma_i
}
```

### Entry pubblica del Bulletin Board

```text
RID_i = H({
  election_id,
  c,
  p_i,
  pk_vote_i,
  v_i,
  sigma_i
})

Entry = {
  type: "BALLOT",
  election_id,
  c,
  p_i,
  pk_vote_i,
  tau_i,
  v_i,
  sigma_i,
  rid,
  timestamp_ms
}

h_k = H({
  previous_hash: h_{k-1},
  index: k,
  entry_hash: H(Entry)
})
```

### Ricevuta

```text
Ack = {
  election_id,
  index,
  rid,
  chain_hash,
  signature_bb
}

signature_bb = Sign_BB({
  election_id,
  index,
  rid,
  chain_hash
})
```

### Chiusura e risultato

```text
CloseEntry = {
  type: "CLOSE",
  election_id,
  timestamp_ms
}

SigClose = Sign_BB({
  election_id,
  h_close
})

TallyResult = {
  election_id,
  h_close,
  totals_by_list,
  anomalous_count,
  signature_ta
}

signature_ta = Sign_TA({
  election_id,
  h_close,
  totals_by_list,
  anomalous_count
})
```

## Regole di accettazione e rifiuto del Bulletin Board

### Accettazione

Il Bulletin Board accetta un pacchetto solo se tutte le condizioni seguenti sono vere:

1. `election_id` corrisponde all'elezione configurata.
2. La firma RA `tau_i` e' valida su `{election_id, p_i, pk_vote_i}`.
3. La firma pseudonima `sigma_i` e' valida su `{election_id, p_i, c, pk_vote_i, v_i}` con `pk_vote_i`.
4. L'elezione e' aperta e non e' ancora presente un evento `CLOSE`.
5. Se `p_i` non e' presente nel registro, `v_i` e' esattamente `1`.
6. Se `p_i` e' gia' presente, `pk_vote_i` coincide con quella autorizzata e l'ultima versione accettata per `p_i` e' `v_i - 1`.
7. `v_i` e' minore o uguale a `Vmax`.
8. Il pacchetto non e' identico a un pacchetto gia' ricevuto.
9. La struttura del messaggio e' conforme allo schema atteso e tutti i campi obbligatori sono presenti e ben formati.

### Rifiuto

Il Bulletin Board rifiuta il pacchetto e non aggiorna la hash chain se almeno una delle condizioni seguenti e' vera:

1. autorizzazione RA assente, malformata, scaduta rispetto all'elezione o non verificabile;
2. firma pseudonima assente, malformata o non verificabile;
3. `election_id` errato;
4. elezione non ancora aperta o gia' chiusa;
5. prima versione diversa da `1`;
6. sostituzione non consecutiva;
7. cambio di `pk_vote_i` per uno pseudonimo gia' registrato;
8. versione superiore a `Vmax`;
9. pacchetto identico a uno gia' ricevuto;
10. campi mancanti, tipi errati o valori non ammessi;
11. qualsiasi errore interno di validazione che non consenta di stabilire la validita' del pacchetto.

Il rifiuto deve produrre un errore applicativo controllato. Il BB non deve decifrare il voto durante la raccolta e non deve restituire informazioni che possano aiutare a distinguere dettagli crittografici interni.
