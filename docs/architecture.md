# Architettura WP4

Il prototipo WP4 e' una simulazione locale e stand-alone del protocollo di voto elettronico. Gli attori del protocollo sono separati logicamente tramite moduli, archivi e chiavi distinti, ma comunicano tramite chiamate locali nello stesso processo o nello stesso ambiente di esecuzione. Non sono previste comunicazioni di rete reali, TLS operativo, microservizi, blockchain, OAuth, database esterni, applicazioni mobili, frontend web complessi o servizi cloud.

## Attori logici

| Attore | Responsabilita' principali | Dati riservati | Dati pubblici prodotti |
| --- | --- | --- | --- |
| Registration Authority | Autenticazione nominativa, verifica degli aventi diritto, emissione di una sola autorizzazione pseudonima per elezione. | Identita' reali, verifier password, collegamento identita'-pseudonimo conservato solo nel dominio RA, chiave privata RA. | Autorizzazioni pseudonime firmate. |
| Bulletin Board | Validazione pacchetti, registro append-only, hash chain, ricevute, chiusura del registro. | Chiave privata BB. Non conserva identita' reali. | Entry pubbliche, ricevute, `h_close`, firma di chiusura. |
| Tallying Authority | Generazione chiavi TA, protezione di `sk_TA_dec`, scrutinio dopo chiusura, pubblicazione risultato firmato. | `sk_TA_dec`, `sk_TA_sig`, `blobTA`, `Kwrap` solo temporaneamente durante setup o scrutinio. | Chiavi pubbliche TA, risultato firmato. |
| Elettore | Generazione stato pseudonimo, richiesta autorizzazione, cifratura voto, firma pacchetto, verifica individuale. | Password locale fittizia del prototipo, `t_i`, `sk_vote_i`, stato cifrato, ricevute locali. | `p_i`, `pk_vote_i`, schede cifrate, firme pseudonime. |
| Commissari | Custodia delle quote Shamir e cooperazione allo scrutinio. | Quote Shamir individuali. | Nessun dato pubblico necessario nella versione base, salvo partecipazione alla procedura di scrutinio simulata. |
| Verificatore pubblico | Controllo di firme, hash chain, versioni, unicita' delle schede finali e coerenza numerica. | Nessuno. | Rapporto di verifica locale. |

## Moduli previsti

La struttura applicativa prevista resta sotto `src/evoting`:

```text
src/evoting/
  __init__.py
  models.py
  serialization.py
  errors.py
  config.py
  crypto/
    hashes.py
    signatures.py
    encryption.py
    password.py
    aead.py
    shamir.py
  actors/
    registration_authority.py
    bulletin_board.py
    tallying_authority.py
    voter.py
    commissioners.py
    verifier.py
  persistence/
    stores.py
    voter_state.py
  benchmarks/
    runner.py
```

Responsabilita' dei moduli:

| Modulo | Responsabilita' |
| --- | --- |
| `models.py` | Dataclass o modelli immutabili per parametri, autorizzazioni, pacchetti, entry, ricevute, risultati, quote e stato elettore. |
| `serialization.py` | Unica serializzazione canonica per tutti i valori firmati o sottoposti ad hash. |
| `errors.py` | Eccezioni applicative controllate e messaggi generici per errori crittografici. |
| `config.py` | Parametri configurabili `Vmax`, `t`, `n`, liste, percorsi runtime e profili dimostrativi. |
| `crypto/hashes.py` | SHA-256 per digest, pseudonimi, identificativi e hash chain. |
| `crypto/signatures.py` | RSA-PSS con SHA-256 per firme RA, BB, TA ed elettore pseudonimo. |
| `crypto/encryption.py` | RSA-OAEP con SHA-256 per cifratura e decifratura delle schede. |
| `crypto/password.py` | Scrypt per verifier RA e chiave locale di protezione dello stato elettore. |
| `crypto/aead.py` | AES-256-GCM per `blobTA` e contenitori cifrati locali. |
| `crypto/shamir.py` | Implementazione didattica dello schema standard di Shamir su `P = 2^521 - 1`. |
| `actors/registration_authority.py` | Archivio aventi diritto, autenticazione simulata, emissione e rifiuto autorizzazioni. |
| `actors/bulletin_board.py` | Regole di accettazione e rifiuto, append-only log, hash chain, ricevute e chiusura. |
| `actors/tallying_authority.py` | Setup TA, apertura `blobTA`, selezione schede finali, scrutinio e firma risultato. |
| `actors/voter.py` | Stato pseudonimo, voto, sostituzione e verifica individuale. |
| `actors/commissioners.py` | Distribuzione e raccolta quote Shamir. |
| `actors/verifier.py` | Verifica pubblica del registro e del risultato. |
| `persistence/*` | Archivi locali sotto `runtime/`, separati per attore e protetti dove richiesto. |
| `benchmarks/runner.py` | Misurazioni separate delle operazioni del protocollo. |

## Comunicazioni tra attori

Le comunicazioni sono chiamate locali tra componenti:

1. elettore -> RA: credenziali simulate, `MAUTH = {election_id, p_i, pk_vote_i}`;
2. RA -> elettore: `tau_i = Sign_RA(MAUTH)` oppure rifiuto controllato;
3. elettore -> BB: `VotePackage = {c, p_i, pk_vote_i, tau_i, v_i, sigma_i}`;
4. BB -> elettore: ricevuta firmata `Ack`;
5. BB -> TA: registro pubblico e stato finale firmato;
6. commissari -> TA: almeno `t` quote Shamir valide;
7. TA -> pubblico: risultato firmato;
8. BB/TA -> verificatore pubblico: dati pubblici necessari alla verifica.

L'esclusione di rete reale implica che TLS non sia implementato come canale operativo nel prototipo base. La protezione dei canali resta una proprieta' del protocollo reale, documentata come assunzione o estensione infrastrutturale.

## Archivi persistenti

Tutti gli archivi generati dal prototipo sono collocati sotto `runtime/`:

```text
runtime/
  ra/
    eligible_voters.json
    issued_authorizations.json
    password_verifiers.json
  bb/
    public_log.json
    receipts.json
    close_state.json
  ta/
    public_keys.json
    blob_ta.json
    tally_result.json
  voters/
    <voter_id>/
      state.enc.json
  commissioners/
    shares.json
  benchmarks/
    results.json
```

Gli archivi indicati sono una struttura prevista per l'implementazione; i file runtime non devono essere versionati. Gli archivi RA possono contenere identita' reali fittizie e verifier password, ma non voti. Gli archivi BB sono pubblici e non contengono identita' reali. Gli archivi TA non ricevono l'elenco nominativo degli elettori. Lo stato elettore contiene segreti e deve essere cifrato.

## Dati pubblici e riservati

Dati pubblici:

- parametri elettorali;
- chiavi pubbliche RA, BB e TA;
- entry del Bulletin Board;
- ricevute firmate;
- evento `CLOSE`, `h_close` e firma BB;
- risultato firmato TA;
- parametri pubblici Shamir `(t, n)`.

Dati riservati:

- password e verifier RA;
- elenco nominativo degli aventi diritto;
- collegamento identita' reale e pseudonimo nel dominio RA;
- chiavi private RA, BB, TA ed elettore;
- `t_i`;
- quote Shamir;
- `Kwrap`;
- `sk_TA_dec`;
- stato persistente dell'elettore;
- voti in chiaro prima o durante lo scrutinio.

## Confini di fiducia

| Confine | Assunzione | Rischio residuo |
| --- | --- | --- |
| RA | Autentica correttamente e non trasferisce identita' reali a BB o TA. | Una RA curiosa conosce identita' e pseudonimo; la collusione con TA puo' indebolire lo pseudoanonimato. |
| BB | Pubblica un registro append-only e firma ricevute e chiusura. | La hash chain rileva manomissioni successive, ma non impedisce omissioni prima della pubblicazione. |
| TA | Scrutinia dopo `CLOSE` e firma il risultato coerente con `h_close`. | Il pubblico non verifica crittograficamente ogni decifratura; resta fiducia residua in TA e commissari. |
| Commissari | Meno di `t` quote non ricostruiscono `Kwrap`. | Almeno `t` commissari collusi possono ricostruire `Kwrap`. |
| Elettore | Il dispositivo locale non altera la scelta prima di cifrare e firmare. | Un dispositivo compromesso resta fuori dalle garanzie principali del protocollo. |
| Runtime locale | Gli archivi sensibili sono protetti e separati. | Il prototipo non realizza cancellazione sicura della memoria o mitigazioni infrastrutturali complete. |

## Flusso completo dell'elezione

1. Configurazione: vengono creati `election_id`, liste, finestre temporali, `Vmax`, `(t, n)`, chiavi pubbliche e private, `blobTA`, quote Shamir e `h0`.
2. Autenticazione: l'elettore fittizio si autentica presso la RA; la RA verifica il diritto di voto e l'assenza di autorizzazioni gia' emesse.
3. Autorizzazione: l'elettore genera `t_i`, `p_i`, coppia pseudonima e invia `MAUTH`; la RA firma e restituisce `tau_i`.
4. Persistenza elettore: il client salva in forma cifrata stato pseudonimo, autorizzazione, versione corrente e ricevute.
5. Voto: l'elettore cifra la lista scelta con RSA-OAEP e firma `MBALLOT_i` con `sk_vote_i`.
6. Raccolta BB: il BB verifica autorizzazione, firma, periodo, versione e replay; se il pacchetto e' valido, aggiunge una entry append-only e rilascia ricevuta.
7. Sostituzione: prima di `CLOSE`, l'elettore puo' inviare una nuova versione consecutiva fino a `Vmax`; le versioni precedenti restano pubblicate.
8. Chiusura: il BB aggiunge `CLOSE`, calcola `h_close` e firma lo stato finale.
9. Scrutinio: la TA seleziona le schede finali, ricostruisce temporaneamente `Kwrap` con almeno `t` quote, apre `blobTA`, decifra, classifica anomalie e calcola i totali.
10. Pubblicazione: la TA firma il risultato vincolato a `h_close`.
11. Verifica individuale: l'elettore ricalcola `p_i`, individua la entry, verifica ricevuta e inclusione nella hash chain.
12. Verifica pubblica: chiunque verifica firme, hash chain, versioni, unicita' delle schede finali e coerenza numerica.

## Separazione tra identita' reale e voto

La separazione e' un vincolo architetturale:

- la RA conosce identita' reale, stato di avente diritto e pseudonimo autorizzato, ma non riceve il ciphertext del voto e non decifra schede;
- il BB riceve pseudonimo, chiave pseudonima, autorizzazione, ciphertext e firma, ma non identita' reale;
- la TA riceve il registro pubblico e decifra solo le schede finali dopo `CLOSE`, ma non riceve l'elenco nominativo;
- il verificatore pubblico usa solo dati pubblici e non accede a segreti.

Non devono essere creati archivi, report o log che colleghino simultaneamente identita' reale, pseudonimo e voto in chiaro. In particolare, sono vietati dataset dimostrativi o messaggi diagnostici che associno una persona fittizia al proprio pseudonimo e alla preferenza decifrata.

## Limiti dichiarati

Il prototipo base non include verificabilita' universale crittografica completa del tally, vera decifratura a soglia, blind signature, Merkle tree degli aventi diritto, mirror indipendenti del Bulletin Board, checkpoint distribuiti, autenticazione forte con certificati personali, cancellazione sicura della memoria o mitigazioni complete contro DoS. Questi elementi possono essere discussi come estensioni future, ma non fanno parte del nucleo WP4.
