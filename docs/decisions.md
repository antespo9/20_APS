# Decisioni architetturali e implementative

Le decisioni seguenti fissano il perimetro del prototipo WP4 e rendono espliciti i compromessi da rispettare durante l'implementazione. Ogni decisione potra' essere rivista solo se la revisione resta coerente con il protocollo WP2 o se viene approvata come modifica progettuale separata.

## DEC-001 - Prototipo stand-alone e locale

Contesto: il WP4 richiede un prototipo funzionante, non una infrastruttura elettorale reale.

Decisione: RA, BB, TA, elettore, commissari e verificatore sono separati logicamente tramite moduli e archivi distinti, ma comunicano tramite chiamate locali. TLS e comunicazioni di rete reali sono escluse dal prototipo base.

Motivazione: questa scelta rende implementabile il protocollo in un ambiente locale mantenendo la separazione dei ruoli richiesta dal WP2.

Conseguenze: le proprieta' legate ai canali protetti sono documentate come assunzioni del sistema reale e non come funzionalita' di rete del prototipo.

Limiti: non vengono dimostrate configurazioni TLS, disponibilita' di rete o isolamento tra processi distribuiti.

Possibile revisione futura: introdurre canali locali autenticati o servizi separati solo come estensione successiva e motivata.

## DEC-002 - Serializzazione canonica unica

Contesto: firme e hash devono essere stabili e non ambigui.

Decisione: tutti i dati firmati o sottoposti ad hash usano una sola serializzazione canonica JSON: UTF-8, campi ordinati, nessuno spazio non significativo, Unicode mantenuto direttamente, binari in Base64 standard con padding, timestamp come interi UTC in millisecondi Unix, interi come numeri JSON e `null` solo quando previsto dallo schema.

Motivazione: una rappresentazione unica evita discrepanze tra moduli e rende riproducibili firme, digest, identificativi e hash chain.

Conseguenze: nessun modulo puo' serializzare autonomamente strutture firmate o hashate.

Limiti: la serializzazione deve essere rigidamente validata; aggiunte allo schema richiedono aggiornamento dei modelli.

Possibile revisione futura: aggiungere versionamento esplicito degli schemi canonici se il protocollo evolve.

## DEC-003 - Cifratura del voto con RSA-OAEP

Contesto: il voto deve restare segreto durante la raccolta e voti uguali non devono produrre ciphertext riconoscibili.

Decisione: la cifratura del voto usa RSA-OAEP con SHA-256 per OAEP e MGF1 e casualita' fresca per ogni cifratura.

Motivazione: RSA-OAEP e' uno schema standard di cifratura probabilistica coerente con il WP2 e con le dipendenze previste.

Conseguenze: il BB non decifra le schede; la TA decifra solo dopo la chiusura.

Limiti: il prototipo non implementa tecniche avanzate di prova pubblica della corretta decifratura.

Possibile revisione futura: valutare prove di corretta decifratura come estensione non inclusa nel prototipo base.

## DEC-004 - Firme con RSA-PSS

Contesto: autorizzazioni, pacchetti, ricevute e risultati devono essere autentici e integri.

Decisione: le firme usano RSA-PSS con SHA-256, MGF1 con SHA-256 e salt length massimo consentito dalla libreria.

Motivazione: RSA-PSS e' uno schema standard, adatto a evitare firme deterministiche obsolete e coerente con le indicazioni del protocollo.

Conseguenze: RA, BB, TA ed elettori pseudonimi usano coppie di chiavi e contesti distinti.

Limiti: la compromissione di una chiave privata consente falsificazioni per il relativo ruolo.

Possibile revisione futura: introdurre rotazione o revoca delle chiavi in una versione piu' completa.

## DEC-005 - Gestione password con Scrypt

Contesto: l'autenticazione RA e la protezione locale dello stato richiedono derivazione sicura da password.

Decisione: le password usano Scrypt con salt casuale distinto di 16 byte per ogni utente, parametri iniziali `n = 2^15`, `r = 8`, `p = 1`, parametri configurabili e memorizzati insieme al verifier. Nessuna password e' memorizzata.

Motivazione: Scrypt aumenta il costo di attacchi offline rispetto a hash veloci e consente parametri espliciti.

Conseguenze: ogni verifier deve includere salt e parametri usati per la verifica.

Limiti: password deboli, phishing o compromissione del dispositivo restano rischi non eliminati.

Possibile revisione futura: introdurre autenticazione multifattore o certificati personali come estensione.

## DEC-006 - Protezione di `blobTA` con AES-256-CBC e HMAC-SHA256

Contesto: la chiave privata di decifratura della TA non deve restare disponibile in chiaro.

Decisione: `blobTA` protegge `sk_TA_dec` con AES-256-CBC, padding PKCS7 e HMAC-SHA256 secondo composizione Encrypt-then-Authenticate. `Kwrap` resta un segreto casuale di 32 byte distribuito tramite Shamir. Da `Kwrap` sono derivate due sottochiavi distinte di 32 byte, `Kenc` e `Kmac`, tramite HKDF-SHA256 con contesto specifico del protocollo. Il MAC autentica una serializzazione canonica contenente almeno contesto, `election_id`, IV e ciphertext. La verifica HMAC precede sempre decifratura CBC e unpadding PKCS7. `TaBlob` contiene IV, ciphertext e MAC, non nonce e tag GCM. Fernet non viene usato per `blobTA`.

Motivazione: il WP2 specifica per `blobTA` una cifratura simmetrica autenticata basata su AES-CBC e HMAC con chiavi indipendenti. Encrypt-then-Authenticate permette di rifiutare blob alterati prima della decifratura e dell'unpadding.

Conseguenze: una ricostruzione Shamir errata non apre `blobTA` e produce un errore applicativo generico.

Limiti: durante lo scrutinio la chiave completa viene ricostruita temporaneamente nell'ambiente TA.

Possibile revisione futura: sostituire questo approccio con vera decifratura a soglia.

## DEC-007 - Protezione dello stato persistente dell'elettore

Contesto: lo stato pseudonimo deve sopravvivere alla riapertura dell'applicazione ma contiene segreti.

Decisione: lo stato persistente dell'elettore usa AES-256-GCM con chiave derivata tramite Scrypt da una password locale fornita dall'utente nel prototipo; salt e parametri KDF sono memorizzati nel contenitore cifrato; AAD include contesto applicativo ed `election_id`; nessun segreto persistente e' salvato in chiaro. AES-256-GCM resta limitato a questa persistenza locale e non sostituisce la costruzione CBC piu' HMAC prevista per `blobTA`.

Motivazione: il WP2 richiede recupero dello stesso stato pseudonimo per sostituzioni successive senza esporre segreti su disco.

Conseguenze: il recupero corretto consente nuove sostituzioni; stato assente o corrotto le impedisce.

Limiti: la password locale e' fittizia nel prototipo e non rappresenta una gestione credenziali reale.

Possibile revisione futura: integrare un keystore locale o credenziali forti dell'utente.

## DEC-008 - Shamir Secret Sharing didattico standard

Contesto: la custodia di `Kwrap` deve richiedere la cooperazione di almeno `t` commissari.

Decisione: viene implementato a scopo didattico lo schema standard di Shamir sul campo primo `P = 2^521 - 1`; `Kwrap` e' interpretata come intero big-endian; ogni share e' `(x, y)` con `x` distinto e non nullo; la ricostruzione usa interpolazione di Lagrange in zero e rifiuta share duplicate, malformate o fuori campo.

Motivazione: Shamir e' richiesto dal protocollo e permette di proteggere `Kwrap` senza inventare primitive.

Conseguenze: meno di `t` quote non ricostruiscono la chiave; quote alterate sono rilevate all'apertura autenticata di `blobTA`.

Limiti: non e' software crittografico destinato alla produzione e non realizza decifratura a soglia.

Possibile revisione futura: usare una libreria specializzata o uno schema con verificabilita' delle quote.

## DEC-009 - Parametri elettorali configurabili

Contesto: il protocollo prevede limiti di versione e soglie commissariali.

Decisione: `Vmax`, `t` e `n` sono configurabili; lo scenario dimostrativo iniziale usa `Vmax = 3`, `t = 3`, `n = 5`; non devono esistere valori dispersi e hardcoded nei moduli.

Motivazione: la configurabilita' evita incoerenze e rende ripetibili scenari diversi.

Conseguenze: i moduli ricevono parametri da configurazione o da `ElectionParams`.

Limiti: valori incoerenti, come `t > n`, devono essere validati e rifiutati.

Possibile revisione futura: aggiungere profili di configurazione per benchmark e dimostrazioni piu' grandi.

## DEC-010 - Stato locale perso o corrotto

Contesto: la RA rilascia una sola autorizzazione per elettore ed elezione, mentre l'elettore deve conservare lo stato pseudonimo.

Decisione: se lo stato locale e' perso o corrotto, la RA non emette una nuova autorizzazione; l'elettore non puo' creare una sostituzione senza recuperare lo stesso stato pseudonimo; resta valida l'ultima scheda gia' accettata dal Bulletin Board.

Motivazione: emettere una nuova autorizzazione violerebbe unicita' e potrebbe collegare o duplicare voti.

Conseguenze: la persistenza cifrata dello stato elettore e' requisito essenziale del prototipo.

Limiti: l'utente puo' perdere la possibilita' di sostituire il voto.

Possibile revisione futura: progettare una procedura di recupero con garanzie aggiuntive, da analizzare separatamente.

## DEC-011 - Errori crittografici generici

Contesto: errori dettagliati possono trasformarsi in canali informativi.

Decisione: ciphertext malformati, MAC `blobTA` errati, tag AES-GCM errati nella persistenza locale e plaintext fuori dominio producono errori applicativi generici; non devono essere esposti pubblicamente dettagli sulle eccezioni crittografiche interne.

Motivazione: il sistema non deve comportarsi come oracolo durante raccolta, apertura di blob o scrutinio.

Conseguenze: i test devono verificare il rifiuto o la classificazione corretta senza dipendere da messaggi interni della libreria.

Limiti: la diagnosi in sviluppo richiede attenzione per non produrre log sensibili.

Possibile revisione futura: introdurre codici di errore interni separati dai messaggi pubblici, senza dati sensibili.

## DEC-012 - Divieto di collegare identita', pseudonimo e voto

Contesto: il protocollo garantisce pseudoanonimato tramite separazione dei ruoli.

Decisione: nessun archivio, log, report di test o benchmark deve associare identita' reale, pseudonimo e voto in chiaro. Il BB non memorizza identita' reali e la TA non riceve l'elenco nominativo.

Motivazione: la collusione informativa tra domini RA, BB e TA e' il principale rischio per lo pseudoanonimato.

Conseguenze: anche i dati dimostrativi devono essere fittizi e separati per dominio.

Limiti: la RA conosce il collegamento identita'-pseudonimo nella versione base, come dichiarato nel WP2.

Possibile revisione futura: valutare blind signature o altri meccanismi per ridurre la conoscenza della RA.
