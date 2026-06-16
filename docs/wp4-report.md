# Bozza WP4 - Implementazione e prestazioni

## 1. Introduzione e obiettivi

Il WP4 realizza un prototipo didattico del protocollo di voto elettronico
definito nei WP precedenti. L'obiettivo e' mostrare un flusso completo e
riproducibile: configurazione dell'elezione, registrazione, autorizzazione
pseudonima, deposito del voto cifrato, sostituzione entro `Vmax`, chiusura,
scrutinio, verifica individuale, verifica pubblica e benchmark delle principali
operazioni.

Il prototipo serve a validare in modo sperimentale le scelte progettuali e a
mostrare le prestazioni locali. Non e' destinato all'impiego in elezioni reali e
non e' software production-ready.

## 2. Perimetro stand-alone

L'implementazione e' stand-alone e viene eseguita localmente su un solo
computer. Gli attori sono separati logicamente tramite moduli, chiavi, archivi e
responsabilita', ma comunicano con chiamate locali. Non sono introdotti
microservizi, blockchain, OAuth, database esterni, applicazioni mobili, frontend
web complessi o servizi cloud.

Questo perimetro e' coerente con la traccia WP4, che consente una simulazione
locale del protocollo. Le proprieta' legate a rete, TLS operativo,
disponibilita' infrastrutturale e isolamento tra server restano fuori dal
prototipo.

## 3. Architettura e attori

Il sistema simula sei attori logici:

- Registration Authority: autentica gli aventi diritto fittizi e rilascia una
  sola autorizzazione pseudonima per elezione.
- Bulletin Board: valida pacchetti, mantiene un registro append-only con hash
  chain, emette ricevute e registra `CLOSE`.
- Tallying Authority: custodisce la chiave di decifratura protetta in `blobTA`,
  seleziona le schede finali e firma il risultato.
- Elettore: genera stato pseudonimo, prepara il voto cifrato e firmato,
  conserva ricevute e verifica l'inclusione.
- Commissari elettorali: custodiscono quote Shamir necessarie a ricostruire
  `Kwrap`.
- Verificatore pubblico: controlla registro, firme, versioni e coerenza del
  risultato usando solo dati pubblici.

## 4. Configurazione elezione

Il profilo dimostrativo definisce una elezione a lista chiusa con codici lista
ammessi, `election_id`, periodo di apertura e chiusura, chiavi pubbliche,
numero totale di aventi diritto, soglia Shamir `(t, n)` e limite di
sostituzione `Vmax`.

La configurazione predefinita usa `Vmax = 3`, `t = 3`, `n = 5` e tre elettori
fittizi. I parametri pubblici includono un `params_hash` calcolato con
serializzazione canonica e SHA-256. Lo stesso payload canonico dei parametri
pubblici, con contesto e versione dello schema, viene firmato dalla TA con
`sk_TA_sig`; la firma e' verificabile pubblicamente con `pk_TA_sig` prima di
procedere con il workflow.

## 5. Primitive crittografiche

Le primitive implementate sono:

- RSA-OAEP con SHA-256 e MGF1-SHA-256 per cifrare il codice lista scelto;
- RSA-PSS con SHA-256 e MGF1-SHA-256 per firme RA, BB, TA sui parametri
  pubblici e sul risultato, ed elettore pseudonimo;
- SHA-256 per pseudonimi, digest, RID, `params_hash` e hash chain;
- Scrypt per verifier password RA e derivazione della chiave locale dello stato
  elettore;
- AES-256-GCM per lo stato persistente locale dell'elettore;
- AES-256-CBC con padding PKCS7 e HMAC-SHA256 per `blobTA`;
- HKDF-SHA256 per derivare `Kenc` e `Kmac` da `Kwrap`;
- Shamir Secret Sharing didattico standard per distribuire `Kwrap`.

Tutti i valori firmati o sottoposti ad hash usano la serializzazione canonica
unica del progetto: JSON UTF-8, campi ordinati, nessuno spazio non
significativo, binari in Base64 standard con padding, interi come numeri JSON e
`null` solo dove previsto dai modelli.

## 6. Protezione di `blobTA`

`blobTA` protegge la chiave privata di decifratura della TA. Il segreto casuale
`Kwrap` e' lungo 32 byte e viene distribuito ai commissari con Shamir Secret
Sharing. Quando almeno `t` quote valide sono disponibili, `Kwrap` viene
ricostruito e usato con HKDF-SHA256 per derivare due sottochiavi distinte:
`Kenc` per AES-256-CBC e `Kmac` per HMAC-SHA256.

La costruzione segue Encrypt-then-Authenticate. Il MAC autentica una
rappresentazione canonica che include contesto, `election_id`, IV, ciphertext e
metadati di soglia. L'HMAC viene verificato prima della decifratura CBC e prima
dell'unpadding PKCS7. `blobTA` non usa Fernet e non usa AES-GCM.

## 7. Registrazione e autorizzazione

La RA mantiene un archivio locale riservato di elettori fittizi aventi diritto.
Le password non sono salvate in chiaro: per ogni elettore viene memorizzato un
verifier Scrypt con salt casuale e parametri persistiti.

L'elettore genera localmente il segreto `t_i`, lo pseudonimo `p_i = H(t_i)` e
una coppia di chiavi pseudonima. La richiesta di autorizzazione contiene
`election_id`, `p_i` e `pk_vote_i`. La RA firma questa richiesta con RSA-PSS e
rilascia `tau_i` una sola volta per elettore ed elezione. Una seconda richiesta
per la stessa elezione viene rifiutata.

## 8. Stato pseudonimo e persistenza

Lo stato pseudonimo dell'elettore include `t_i`, `p_i`, chiave pseudonima,
autorizzazione, versione corrente e ricevute. Lo stato viene salvato sotto
`runtime/` in un contenitore cifrato con AES-256-GCM; la chiave e' derivata da
password locale tramite Scrypt e l'AAD include contesto applicativo ed
`election_id`.

Lo stato viene aggiornato solo dopo una ricevuta BB valida e coerente con il
pacchetto depositato. Se lo stato locale viene perso, cancellato o corrotto,
l'elettore non puo' creare una sostituzione e la RA non emette una nuova
autorizzazione; la scheda precedente gia' accettata dal Bulletin Board resta
valida.

## 9. Preparazione e deposito voto

L'elettore sceglie un codice lista tra quelli pubblicati. Il codice viene
cifrato con la chiave pubblica di cifratura della TA usando RSA-OAEP con
SHA-256. Il pacchetto contiene ciphertext, pseudonimo, chiave pubblica
pseudonima, autorizzazione RA, versione e firma pseudonima RSA-PSS.

Il Bulletin Board accetta il pacchetto solo se verifica autorizzazione RA,
firma pseudonima, `election_id`, finestra temporale, versione, `Vmax`, chiave
pseudonima e assenza di replay identici. In caso di accettazione emette una
ricevuta firmata.

## 10. Sostituzione e `Vmax`

Prima di `CLOSE`, l'elettore puo' sostituire il voto usando lo stesso
pseudonimo, la stessa autorizzazione e la stessa chiave pseudonima. La versione
deve essere consecutiva e non superiore a `Vmax`.

Il registro non cancella le versioni precedenti: le conserva come record
pubblici append-only. Ai fini dello scrutinio viene selezionata solo la versione
valida piu' alta per pseudonimo prima di `CLOSE`.

## 11. Bulletin Board, RID e hash chain

Ogni scheda accettata diventa una entry `BALLOT` pubblica. Il `RID` e'
calcolato con SHA-256 su una rappresentazione canonica dei campi rilevanti del
pacchetto. Ogni record del Bulletin Board contiene indice, hash precedente,
hash della entry e hash di catena.

La hash chain rende rilevabili alterazioni, cancellazioni, duplicazioni e
riordinamenti dopo la pubblicazione. Il BB non decifra i voti e non memorizza
identita' reali nel registro pubblico.

## 12. Evento `CLOSE`

Alla chiusura, il Bulletin Board aggiunge una entry `CLOSE`, calcola `h_close`
come ultimo hash della catena e firma lo stato finale. Dopo `CLOSE` non sono
accettati nuovi voti o sostituzioni.

Il valore `h_close` vincola lo stato pubblico che verra' usato dallo scrutinio e
dalla verifica pubblica.

## 13. Scrutinio TA

La TA avvia lo scrutinio solo dopo `CLOSE` e dopo la validazione pubblica del
registro. Sono selezionate solo le schede finali, cioe' la versione valida piu'
alta per ogni pseudonimo. La TA apre `blobTA` solo con almeno `t` quote Shamir
valide, ricostruendo temporaneamente `Kwrap` e quindi la chiave privata di
decifratura.

Le schede finali vengono decifrate con RSA-OAEP. Plaintext non decodificabili,
malformati o fuori dominio sono classificati come anomalie. Il risultato
pubblico contiene totali per lista, numero di schede finali, numero di schede
valide e numero di anomalie; non pubblica la corrispondenza tra singoli
ciphertext e voto in chiaro.

## 14. Verifica individuale

L'elettore puo' verificare la propria ricevuta firmata dal BB e l'inclusione del
record nel registro pubblico. La verifica controlla `election_id`, indice,
`RID`, hash di catena, firma della ricevuta e coerenza con il registro
verificato.

Questa verifica dimostra l'inclusione della scheda cifrata accettata, non il suo
contenuto in chiaro e non la correttezza crittografica della successiva
decifratura.

## 15. Verifica pubblica

Il verificatore pubblico controlla:

- firma TA dei parametri pubblici e coerenza del relativo `params_hash`;
- firme RA sulle autorizzazioni;
- firme pseudonime sui pacchetti;
- RID ricalcolati;
- indici e hash chain;
- versioni consecutive e limite `Vmax`;
- selezione delle ultime versioni valide;
- presenza e firma dell'evento `CLOSE`;
- legame del risultato con `h_close`;
- firma TA sul risultato;
- coerenza numerica tra schede finali, schede valide, anomalie e totali.

La verifica pubblica non prova crittograficamente la corretta decifratura di
ogni ciphertext. Il prototipo non implementa prove verificabili di decifratura
ne' zero-knowledge proof; resta quindi una fiducia residua nella TA e nei
commissari.

## 16. Workflow end-to-end

Il workflow completo configura il profilo demo, registra elettori fittizi,
verifica la firma TA sui parametri pubblici, registra elettori fittizi, rilascia
autorizzazioni, salva e riapre lo stato cifrato degli elettori, deposita voti,
esegue una sostituzione valida, chiude il BB, scrutinia e verifica ricevute,
registro e risultato.

Lo scenario dimostrativo produce tre schede finali, conserva la versione
sostituita nel registro e verifica pubblicamente l'esito finale.

## 17. GUI dimostrativa

La GUI dimostrativa usa Tkinter/ttk della libreria standard. Offre una
interfaccia locale per inizializzare l'elezione, autorizzare elettori fittizi,
depositare e sostituire voti, chiudere l'elezione, eseguire lo scrutinio e
lanciare la verifica pubblica.

La GUI e' una vista dimostrativa sul workflow locale. Il controller espone solo
informazioni pubbliche o abbreviate: RID, pseudonimi e hash sono mostrati come
prefissi, mentre chiavi private, segreti, ciphertext completi e firme complete
non sono mostrati nello snapshot pubblico.

## 18. Strategia di test

La suite include test unitari, di integrazione, di sicurezza e benchmark smoke.
Sono coperti modelli, serializzazione canonica, primitive crittografiche, RA,
BB, TA, Shamir, `blobTA`, persistenza cifrata, sostituzione, perdita dello
stato, verifica individuale, verifica pubblica, GUI e workflow completo.

I test includono casi negativi per parametri pubblici alterati, firma parametri
errata, chiave pubblica TA di firma errata, messaggi alterati, firme errate,
autorizzazioni contraffatte, replay, versioni non valide, `Vmax`, voto dopo
`CLOSE`, hash chain manomessa, ciphertext malformati, plaintext fuori dominio,
MAC `blobTA` errati, tag AES-GCM errati e quote Shamir duplicate o malformate.

La suite di riferimento risulta composta da 282 test superati.

## 19. Benchmark

Sono disponibili benchmark `smoke` e `full`. Il profilo `smoke` serve a
controlli rapidi e test automatici; il profilo `full` raccoglie misure piu'
stabili con 5 ripetizioni per operazione temporale. Il runner misura operazioni
distinte: generazione chiavi, RA, cifratura, firma, preparazione pacchetto,
accettazione BB, hash chain, ricevuta, Shamir, `blobTA`, scrutinio, dimensione
pacchetto, dimensione ricevuta e verifica pubblica su scale crescenti.

Nel profilo `full` del 16 giugno 2026 le mediane principali includono circa
93.3756 ms per autenticazione/autorizzazione RA, 30.6746 ms per preparazione
completa del pacchetto, 1.0974 ms per accettazione BB, 35.2956 ms per scrutinio
di 10 schede finali e una crescita della verifica pubblica da 0.3082 ms su 2
eventi a 3.9958 ms su 26 eventi. Il pacchetto voto misura 1814 byte e la
ricevuta 568 byte.

## 20. Sicurezza, privacy ed errori

Il prototipo riduce la concentrazione informativa separando i ruoli: la RA
conosce identita' e pseudonimo, ma non il voto; il BB vede pseudonimi e
ciphertext, ma non identita' reali; la TA decifra solo schede finali dopo
`CLOSE`, ma non riceve l'elenco nominativo degli elettori.

Gli errori crittografici pubblici sono generici: ciphertext malformati, tag
AES-GCM errati, MAC `blobTA` non validi, padding non valido e input strutturali
errati non espongono dettagli interni della libreria. Gli output dimostrativi,
gli snapshot GUI e i benchmark evitano password, chiavi private, segreti
elettore, `Kwrap`, quote Shamir e collegamenti identita'-pseudonimo-voto in
chiaro.

## 21. Limiti del prototipo

Il sistema resta un prototipo didattico locale. Non implementa infrastruttura
distribuita, canali TLS operativi, isolamento tra server, database esterni,
rate limiting reale, mitigazioni DoS complete, cancellazione sicura della
memoria o gestione production delle credenziali.

La verificabilita' universale del tally e' parziale: il pubblico controlla
registro, firme, versioni, `Vmax`, selezione finale, legame con `h_close`, firma
TA e coerenza numerica, ma non dispone di prove verificabili della corretta
decifratura di ogni scheda. Non e' presente vera threshold decryption: Shamir
protegge `Kwrap`, ma durante lo scrutinio la chiave di decifratura TA viene
ricostruita temporaneamente nell'ambiente TA.

La resistenza alla coercizione e' limitata: la sostituzione riduce il valore di
una ricevuta ottenuta prima della chiusura, ma non impedisce la collaborazione
volontaria dell'elettore con un coercitore. Un dispositivo elettore compromesso
puo' alterare la scelta prima della cifratura o rubare stato locale.

## 22. Istruzioni di riproduzione

I comandi principali sono:

```powershell
python -m pytest
python -m evoting.demo
python -m evoting.gui.app
python -m evoting.gui.app --check
python -m evoting.benchmarks.runner --profile smoke
python -m evoting.benchmarks.runner --profile full
```

I benchmark salvano JSON e CSV sotto `runtime/benchmarks/`. I dati runtime sono
generati localmente e non fanno parte della consegna versionata, salvo eventuali
file esplicitamente tracciati come segnaposto.
