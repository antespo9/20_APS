# Matrice di tracciabilita'

Stato iniziale di tutti gli elementi: `Da implementare`.

| Requisito | Fase WP2 | Modulo previsto | Test previsto | Benchmark | Stato |
| --- | --- | --- | --- | --- | --- |
| FR-001 | Tutte le fasi | `actors/*` | `test_complete_election_workflow.py` | Non applicabile | Da implementare |
| FR-002 | Fase 0, Fase 5 | `models.py`, `config.py`, `tallying_authority.py` | `test_tally_workflow.py` | Scrutinio | Da implementare |
| FR-003 | Fase 0 | `models.py`, `config.py` | `test_models.py` | Dimensione parametri | Da implementare |
| FR-004 | Fase 0, sintesi chiavi | `crypto/signatures.py`, `crypto/encryption.py` | `test_signatures.py`, `test_encryption.py` | Generazione chiavi separata | Da implementare |
| FR-005 | Fase 1 | `registration_authority.py`, `password.py` | `test_registration_authority.py` | Emissione autorizzazione RA | Da implementare |
| FR-006 | Fase 1 | `registration_authority.py` | `test_registration_authority.py` | Emissione autorizzazione RA | Da implementare |
| FR-007 | Fase 1 | `voter.py`, `hashes.py` | `test_voter_state_persistence.py` | Non applicabile | Da implementare |
| FR-008 | Fase 1 | `models.py`, `registration_authority.py` | `test_authorization_tampering.py` | Dimensione autorizzazione | Da implementare |
| FR-009 | Fase 2 | `encryption.py`, `voter.py` | `test_encryption.py` | Cifratura voto | Da implementare |
| FR-010 | Fase 2 | `signatures.py`, `voter.py` | `test_signatures.py` | Firma pacchetto | Da implementare |
| FR-011 | Fase 3 | `models.py`, `bulletin_board.py` | `test_bulletin_board_rules.py` | Dimensione pacchetto | Da implementare |
| FR-012 | Fase 3 | `bulletin_board.py` | `test_bulletin_board_rules.py` | Verifica BB | Da implementare |
| FR-013 | Fase 3 | `bulletin_board.py`, `hashes.py` | `test_bulletin_board_tampering.py` | Aggiornamento hash chain | Da implementare |
| FR-014 | Fase 3 | `bulletin_board.py`, `signatures.py` | `test_bulletin_board_rules.py` | Verifica ricevuta, dimensione ricevuta | Da implementare |
| FR-015 | Fase 4 | `voter.py`, `bulletin_board.py` | `test_vote_replacement.py` | Firma e verifica sostituzione | Da implementare |
| FR-016 | Fase 4 | `bulletin_board.py` | `test_vote_replacement.py` | Crescita registro | Da implementare |
| FR-017 | Fase 5 | `bulletin_board.py` | `test_bulletin_board_rules.py` | Aggiornamento hash chain | Da implementare |
| FR-018 | Fase 5 | `tallying_authority.py`, `verifier.py` | `test_tally_workflow.py` | Scrutinio | Da implementare |
| FR-019 | Fase 5 | `tallying_authority.py`, `commissioners.py`, `shamir.py` | `test_tally_negative.py` | Ricostruzione `Kwrap` | Da implementare |
| FR-020 | Fase 5 | `tallying_authority.py`, `encryption.py` | `test_tally_workflow.py` | Scrutinio | Da implementare |
| FR-021 | Fase 5 | `tallying_authority.py`, `signatures.py` | `test_public_verification.py` | Dimensione risultato | Da implementare |
| FR-022 | Fase 6 | `voter.py`, `verifier.py` | `test_public_verification.py` | Verifica ricevuta | Da implementare |
| FR-023 | Fase 6 | `verifier.py` | `test_public_verification.py` | Verifica pubblica registro | Da implementare |
| FR-024 | Fase 0 | `config.py`, `models.py` | `test_models.py` | Profili benchmark | Da implementare |
| FR-025 | Tutte le fasi | `actors/*` | `test_complete_election_workflow.py` | Non applicabile | Da implementare |
| FR-026 | Perimetro WP4 | Revisione architetturale | Verifica repository | Non applicabile | Da implementare |
| SR-001 | Tutte le fasi | `serialization.py` | `test_serialization.py` | Dimensione messaggi canonici | Completato in Milestone 1 |
| SR-002 | Tutte le fasi | `serialization.py` | `test_serialization.py` | Dimensione messaggi canonici | Completato in Milestone 1 |
| SR-003 | Fase 2, Fase 5 | `encryption.py` | `test_encryption.py` | Cifratura voto | Completato in Milestone 2 per la primitiva RSA-OAEP |
| SR-004 | Fase 1, Fase 2, Fase 3, Fase 5 | `signatures.py` | `test_signatures.py` | Firma e verifica | Completato in Milestone 2 per la primitiva RSA-PSS |
| SR-005 | Fase 0, Fase 1, Fase 3 | `hashes.py` | `test_hashes.py` | Hash chain | Primitiva SHA-256 completata in Milestone 2; integrazione protocollo da implementare |
| SR-006 | Fase 1 | `password.py`, `registration_authority.py` | `test_password.py` | Derivazione Scrypt | Verifier Scrypt completato in Milestone 2; integrazione RA da implementare |
| SR-007 | Fase 1 | `password.py`, `config.py` | `test_password.py` | Derivazione Scrypt | Completato in Milestone 2 per parametri Scrypt persistibili |
| SR-008 | Fase 0, Fase 5 | `aead.py`, `tallying_authority.py` | `test_ta_blob_protection.py` | Apertura `blobTA` | Completato in Milestone 3 |
| SR-009 | Fase 0, Fase 5 | `aead.py`, `tallying_authority.py` | `test_aead.py`, `test_ta_blob_protection.py` | Apertura `blobTA` | Completato in Milestone 3 |
| SR-010 | Fase 0, Fase 5 | `shamir.py` | `test_shamir.py` | Generazione quote | Completato in Milestone 3 |
| SR-011 | Fase 0, Fase 5 | `shamir.py` | `test_shamir.py` | Generazione quote | Completato in Milestone 3 |
| SR-012 | Fase 5 | `shamir.py` | `test_shamir_negative.py` | Ricostruzione `Kwrap` | Completato in Milestone 3 |
| SR-013 | Fase 0, Fase 5 | `shamir.py` | Revisione documentazione modulo | Non applicabile | Completato in Milestone 3 |
| SR-014 | Fase 3 | `bulletin_board.py`, `stores.py` | `test_bulletin_board_rules.py` | Non applicabile | Da implementare |
| SR-015 | Fase 5 | `tallying_authority.py`, `stores.py` | `test_tally_workflow.py` | Non applicabile | Da implementare |
| SR-016 | Tutte le fasi | `stores.py`, test fixture | Test di assenza dati collegati | Non applicabile | Da implementare |
| SR-017 | Fase 1, Fase 3 | `registration_authority.py`, `signatures.py` | `test_authorization_tampering.py` | Verifica firma RA | Da implementare |
| SR-018 | Fase 2, Fase 3 | `voter.py`, `signatures.py` | `test_crypto_tampering.py` | Verifica firma pseudonima | Da implementare |
| SR-019 | Fase 2, Fase 4 | `bulletin_board.py` | `test_vote_replacement.py` | Non applicabile | Da implementare |
| SR-020 | Fase 3 | `bulletin_board.py` | `test_bulletin_board_rules.py` | Verifica BB | Da implementare |
| SR-021 | Fase 4 | `bulletin_board.py` | `test_vote_replacement.py` | Verifica BB | Da implementare |
| SR-022 | Fase 3, Fase 5 | `bulletin_board.py`, `hashes.py` | `test_bulletin_board_tampering.py` | Hash chain | Da implementare |
| SR-023 | Fase 5 | `errors.py`, `encryption.py`, `aead.py` | `test_crypto_tampering.py`, `test_tally_negative.py` | Non applicabile | Completato in Milestone 2 per errori RSA-OAEP e AES-GCM; plaintext fuori dominio da implementare |
| SR-024 | Fase 5 | `tallying_authority.py` | `test_tally_workflow.py` | Non applicabile | Da implementare |
| SR-025 | Fase 6 | `verifier.py`, documentazione risultato | `test_public_verification.py` | Verifica pubblica | Da implementare |
| SR-026 | Fase 0, Fase 1, Fase 2 | `crypto/*` | `test_crypto_tampering.py` | Operazioni crittografiche | Da implementare |
| PR-001 | Fase 1, Fase 4 | `voter_state.py` | `test_voter_state_persistence.py` | Apertura stato cifrato | Da implementare |
| PR-002 | Fase 1, Fase 4 | `models.py`, `voter_state.py` | `test_voter_state_persistence.py` | Dimensione stato | Da implementare |
| PR-003 | Fase 1, Fase 4 | `voter_state.py`, `aead.py` | `test_voter_state_persistence.py` | Apertura stato cifrato | Da implementare |
| PR-004 | Fase 1, Fase 4 | `voter_state.py`, `password.py` | `test_voter_state_persistence.py` | Derivazione Scrypt | Da implementare |
| PR-005 | Fase 1, Fase 4 | `voter_state.py` | `test_voter_state_persistence.py` | Apertura stato cifrato | Da implementare |
| PR-006 | Fase 1, Fase 4 | `registration_authority.py`, `voter.py` | `test_voter_state_persistence.py` | Non applicabile | Da implementare |
| PR-007 | Fase 4 | `voter.py`, `bulletin_board.py` | `test_vote_replacement.py` | Non applicabile | Da implementare |
| PR-008 | Perimetro runtime | `stores.py` | Verifica repository | Non applicabile | Da implementare |
| TR-001 | Tutte le fasi | `tests/*` | Suite completa | Non applicabile | Da implementare |
| TR-002 | Tutte le fasi | `tests/unit/*` | Suite unitaria | Non applicabile | Da implementare |
| TR-003 | Tutte le fasi | `tests/integration/*` | Suite integrazione | Non applicabile | Da implementare |
| TR-004 | Fase 1, Fase 3, Fase 6 | `tests/security/*` | Test di alterazione | Non applicabile | Da implementare |
| TR-005 | Fase 1, Fase 4 | `tests/integration/test_voter_state_persistence.py` | Test persistenza | Non applicabile | Da implementare |
| TR-006 | Fase 5 | `tests/security/*` | Test negativi crypto e Shamir | Non applicabile | Da implementare |
| TR-007 | Fase 4 | `tests/integration/test_vote_replacement.py` | Test sostituzione | Non applicabile | Da implementare |
| TR-008 | Fase 5 | `tests/integration/test_tally_workflow.py` | Test scrutinio | Non applicabile | Da implementare |
| TR-009 | Fase 6 | `tests/integration/test_public_verification.py` | Test verifica | Non applicabile | Da implementare |
| TR-010 | Tutte le fasi | Suite test | `python -m pytest` | Non applicabile | Da implementare |
| TR-011 | Tutte le fasi | Processo di milestone | Suite applicabile | Non applicabile | Da implementare |
| BR-001 | WP4 prestazioni | `benchmarks/runner.py` | `test_benchmark_smoke.py` | Tutti i benchmark | Da implementare |
| BR-002 | WP4 prestazioni | `benchmarks/runner.py` | `test_benchmark_smoke.py` | Report completo | Da implementare |
| BR-003 | Fase 1, Fase 2, Fase 3 | `benchmarks/runner.py` | `test_benchmark_smoke.py` | RA, cifratura, firma, BB, hash, ricevuta | Da implementare |
| BR-004 | Fase 0, Fase 5 | `benchmarks/runner.py` | `test_benchmark_smoke.py` | Shamir, `Kwrap`, `blobTA`, scrutinio | Da implementare |
| BR-005 | Fase 6 | `benchmarks/runner.py` | `test_benchmark_smoke.py` | Verifica pubblica, dimensioni | Da implementare |
| BR-006 | WP4 prestazioni | `benchmarks/runner.py` | `test_benchmark_smoke.py` | Key generation separata | Da implementare |
| BR-007 | Fase 2 | `benchmarks/runner.py` | `test_benchmark_smoke.py` | Costo lato elettore | Da implementare |
| BR-008 | Fase 5, Fase 6 | `benchmarks/runner.py` | `test_benchmark_smoke.py` | Scalabilita' lineare | Da implementare |
| AC-001 | Tutte le fasi | `actors/*` | `test_complete_election_workflow.py` | Tutti i benchmark principali | Da implementare |
| AC-002 | Fase 1 | `registration_authority.py` | `test_registration_authority.py` | Emissione autorizzazione RA | Da implementare |
| AC-003 | Fase 3 | `bulletin_board.py` | `test_bulletin_board_rules.py` | Verifica BB, ricevuta | Da implementare |
| AC-004 | Fase 3, Fase 4 | `bulletin_board.py` | `test_bulletin_board_rules.py`, `test_vote_replacement.py` | Verifica BB | Da implementare |
| AC-005 | Fase 4, Fase 5 | `bulletin_board.py`, `tallying_authority.py` | `test_vote_replacement.py`, `test_tally_workflow.py` | Scrutinio | Da implementare |
| AC-006 | Fase 3, Fase 6 | `bulletin_board.py`, `verifier.py` | `test_bulletin_board_tampering.py` | Verifica pubblica registro | Da implementare |
| AC-007 | Fase 5 | `shamir.py`, `tallying_authority.py` | `test_shamir.py`, `test_tally_negative.py` | Ricostruzione `Kwrap` | Da implementare |
| AC-008 | Fase 5 | `shamir.py`, `aead.py` | `test_shamir_negative.py`, `test_ta_blob_protection.py` | Apertura `blobTA` | Completato in Milestone 3 |
| AC-009 | Fase 4 | `voter.py`, `registration_authority.py`, `bulletin_board.py` | `test_voter_state_persistence.py` | Non applicabile | Da implementare |
| AC-010 | Tutte le fasi | Suite test | `python -m pytest` | Non applicabile | Da implementare |
| AC-011 | WP4 prestazioni | `benchmarks/runner.py` | `test_benchmark_smoke.py` | Report benchmark | Da implementare |
| DEC-001 | Tutte le fasi | `actors/*` | Workflow locale | Non applicabile | Da implementare |
| DEC-002 | Tutte le fasi | `serialization.py` | Test serializzazione | Dimensione messaggi | Completato in Milestone 1 |
| DEC-003 | Fase 2, Fase 5 | `encryption.py` | Test cifratura | Cifratura voto | Completato in Milestone 2 per la primitiva RSA-OAEP |
| DEC-004 | Fase 1, Fase 2, Fase 3, Fase 5 | `signatures.py` | Test firme | Firma e verifica | Completato in Milestone 2 per la primitiva RSA-PSS |
| DEC-005 | Fase 1 | `password.py` | Test password | Scrypt | Completato in Milestone 2 per verifier e derivazione Scrypt |
| DEC-006 | Fase 0, Fase 5 | `aead.py`, `tallying_authority.py` | Test `blobTA` | Apertura `blobTA` | Completato in Milestone 3 |
| DEC-007 | Fase 1, Fase 4 | `voter_state.py` | Test persistenza | Apertura stato | Da implementare |
| DEC-008 | Fase 0, Fase 5 | `shamir.py` | Test Shamir | Shamir | Completato in Milestone 3 |
| DEC-009 | Fase 0 | `config.py` | Test configurazione | Profili | Da implementare |
| DEC-010 | Fase 4 | `registration_authority.py`, `voter.py` | Test stato perso | Non applicabile | Da implementare |
| DEC-011 | Fase 5 | `errors.py`, `crypto/*` | Test errori generici | Non applicabile | Completato in Milestone 2 per primitive RSA-OAEP e AES-GCM |
| DEC-012 | Tutte le fasi | `stores.py`, `actors/*` | Test separazione dati | Non applicabile | Da implementare |
