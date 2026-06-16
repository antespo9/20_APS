# Report benchmark WP4

Questo report sintetizza i risultati del profilo benchmark `full` del prototipo
WP4. Il sistema misurato e' un prototipo didattico stand-alone, eseguito
localmente su una singola macchina, con attori separati logicamente ma non
distribuiti su infrastrutture indipendenti.

## Ambiente sperimentale

I dati dell'ambiente usati per interpretare i risultati sono:

- Python 3.14.5;
- Microsoft Windows 11 Home 64 bit, versione 10.0.26200;
- Intel Core i7-12700H;
- 14 core fisici;
- 20 processori logici;
- circa 16 GB di RAM.

## Metodo

Le misure temporali sono state raccolte dal runner benchmark con
`time.perf_counter_ns()`, convertendo poi i campioni in millisecondi. Il profilo
`full` usa 1 warm-up e 5 ripetizioni per le operazioni temporali. Per ogni
operazione vengono riportati minimo, mediana, media e deviazione standard.

La generazione delle chiavi RSA e' misurata come operazione separata e non e'
aggregata con preparazione, deposito o verifica del voto. Le righe
`vote_package_size` e `receipt_size` sono misure di dimensione: non
rappresentano operazioni temporali e quindi riportano tempi pari a 0.0 ms per
costruzione.

I risultati dipendono da hardware, sistema operativo, carico della macchina,
versione della runtime e profilo di benchmark. Non devono essere generalizzati a
un sistema elettorale reale.

## Artefatti usati

I risultati sono stati letti dagli artefatti locali gia' presenti sotto
`runtime/benchmarks/`:

- `runtime/benchmarks/benchmark-full-20260616T161438Z.json`;
- `runtime/benchmarks/benchmark-full-20260616T161438Z.csv`.

I file JSON e CSV restano nella directory `runtime/` e non sono copiati nella
documentazione.

## Risultati completi

| Operazione | Input | Scala | Rip. | Min ms | Mediana ms | Media ms | Dev. std ms | Dimensione byte |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `rsa_signature_key_generation` | `rsa_bits=2048` | 2048 | 5 | 11.3865 | 37.8399 | 34.8660 | 20.9641 | 0 |
| `rsa_encryption_key_generation` | `rsa_bits=2048` | 2048 | 5 | 24.5867 | 46.8595 | 49.4965 | 20.5727 | 0 |
| `ra_authentication_and_authorization_issue` | `scrypt_n=32768` | 32768 | 5 | 89.8305 | 93.3756 | 93.2970 | 3.4612 | 256 |
| `rsa_oaep_vote_encryption` | `plaintext_bytes=8` | 8 | 5 | 0.0243 | 0.0263 | 0.0286 | 0.0052 | 256 |
| `rsa_pss_package_signature` | `message_bytes=1114` | 1114 | 5 | 0.4739 | 0.4765 | 0.4777 | 0.0041 | 256 |
| `voter_prepare_vote_package_complete` | `single_vote_package` | 1 | 5 | 29.9438 | 30.6746 | 30.6154 | 0.4336 | 1814 |
| `bb_validate_and_accept_vote_package` | `single_vote_package` | 1 | 5 | 1.0526 | 1.0974 | 1.0905 | 0.0292 | 1814 |
| `bb_hash_chain_update_only` | `single_entry_hash_link` | 1 | 5 | 0.0281 | 0.0287 | 0.0291 | 0.0011 | 1966 |
| `bb_receipt_verification` | `single_receipt` | 1 | 5 | 0.0433 | 0.0441 | 0.0456 | 0.0032 | 568 |
| `shamir_split` | `threshold=3,shares=5,secret_bytes=32` | 5 | 5 | 0.0082 | 0.0083 | 0.0087 | 0.0009 | 0 |
| `shamir_reconstruction` | `threshold=3,provided_shares=3` | 3 | 5 | 0.0072 | 0.0073 | 0.0077 | 0.0008 | 0 |
| `blob_ta_create` | `private_key_pem_bytes=1704` | 1704 | 5 | 0.0779 | 0.0786 | 0.0802 | 0.0035 | 162 |
| `blob_ta_open` | `threshold=3,provided_shares=3` | 3 | 5 | 0.0599 | 0.0607 | 0.0634 | 0.0052 | 162 |
| `tally` | `final_ballots=10` | 10 | 5 | 35.2245 | 35.2956 | 35.6702 | 0.6028 | 614 |
| `vote_package_size` | `single_vote_package` | 1 | 1 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1814 |
| `receipt_size` | `single_receipt` | 1 | 1 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 568 |
| `public_verification` | `events=2` | 2 | 5 | 0.2966 | 0.3082 | 0.3271 | 0.0531 | 612 |
| `public_verification` | `events=4` | 4 | 5 | 0.5810 | 0.6007 | 0.5985 | 0.0159 | 612 |
| `public_verification` | `events=11` | 11 | 5 | 1.5735 | 1.6055 | 1.7260 | 0.1914 | 614 |
| `public_verification` | `events=26` | 26 | 5 | 3.9386 | 3.9958 | 4.1199 | 0.2329 | 614 |

`message_size_bytes = 0` per generazione chiavi e Shamir significa che la misura
non e' applicabile come dimensione di un messaggio pubblico. Per Shamir le quote
sono materiale riservato dei commissari, non messaggi pubblici del Bulletin
Board.

## Risultati principali

Le mediane principali del profilo `full` sono:

- generazione chiave RSA per firma: 37.8399 ms;
- generazione chiave RSA per cifratura: 46.8595 ms;
- autenticazione e autorizzazione RA: 93.3756 ms;
- cifratura RSA-OAEP del voto: 0.0263 ms;
- firma RSA-PSS del pacchetto: 0.4765 ms;
- preparazione completa del pacchetto: 30.6746 ms;
- accettazione del Bulletin Board: 1.0974 ms;
- aggiornamento hash chain isolato: 0.0287 ms;
- verifica ricevuta: 0.0441 ms;
- Shamir split: 0.0083 ms;
- ricostruzione Shamir: 0.0073 ms;
- creazione `blobTA`: 0.0786 ms;
- apertura `blobTA`: 0.0607 ms;
- scrutinio di 10 schede finali: 35.2956 ms.

Le dimensioni principali sono 1814 byte per un pacchetto voto canonico e 568
byte per una ricevuta canonica.

## Verifica pubblica

La verifica pubblica e' stata misurata su registri di dimensione crescente:

| Eventi pubblici | Mediana ms |
| ---: | ---: |
| 2 | 0.3082 |
| 4 | 0.6007 |
| 11 | 1.6055 |
| 26 | 3.9958 |

La crescita osservata e' approssimativamente lineare rispetto al numero di
eventi pubblicati, coerentemente con il fatto che il verificatore rilegge e
ricontrolla record, firme, RID, hash chain, versioni, selezione finale e
coerenza numerica.

## Interpretazione prudente

Il costo piu' alto della RA e' dovuto principalmente a Scrypt, usato per la
verifica delle credenziali e configurato nel profilo `full` con `n = 32768`.
La generazione RSA mostra una variabilita' elevata, visibile dalla deviazione
standard, ed e' quindi opportunamente riportata separatamente dalle operazioni
ordinarie di voto.

RID, hash chain, ricevute e Shamir hanno costo molto basso nel contesto locale
misurato. La preparazione completa del pacchetto lato elettore e' invece piu'
costosa della sola cifratura o della sola firma perche' include caricamento
delle chiavi, cifratura RSA-OAEP, caricamento della chiave privata pseudonima e
firma RSA-PSS.

## Limiti sperimentali

Le misure sono state raccolte su una singola macchina, con 5 ripetizioni per le
operazioni temporali del profilo `full`. Non sono stati eseguiti confronti tra
hardware differenti, carichi concorrenti, rete, database esterni o processi
distribuiti. Il prototipo usa chiamate locali tra moduli e non include latenza
di rete, contesa reale tra utenti o persistenza su database.

Questi risultati descrivono il comportamento del prototipo didattico nella
configurazione misurata. Non sono generalizzabili a un sistema elettorale reale
ne' devono essere letti come garanzia prestazionale di un software
production-ready.
