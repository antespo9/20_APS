"""Headless controller for the local demonstration GUI."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import os
from pathlib import Path
import tempfile

from evoting.actors.bulletin_board import BoardLogRecord, BulletinBoardError
from evoting.actors.verifier import (
    select_final_ballot_entries,
    verify_public_params_signature,
    verify_public_election,
    verify_public_log,
    verify_tally_result_signature,
)
from evoting.actors.voter import (
    PseudonymousVoterState,
    apply_accepted_receipt,
    generate_authorization_material,
    prepare_vote_package,
)
from evoting.config import DemoProfile, DemoVoter, default_demo_profile
from evoting.errors import EvotingError, ModelValidationError
from evoting.gui.formatting import short_hash, short_pseudonym, short_rid, yes_no
from evoting.models import Ack, BoardEntry, CloseEntry, TallyResult
from evoting.workflow import ElectionSetup, setup_demo_election


class GuiControllerError(EvotingError):
    """Raised when a GUI action is not currently available."""


@dataclass(frozen=True, slots=True)
class ConfigView:
    election_id: str
    lists: tuple[tuple[str, str], ...]
    vmax: int
    threshold: str
    voter_count: int
    election_status: str


@dataclass(frozen=True, slots=True)
class VoterView:
    voter_id: str
    authorization_status: str
    current_version: int
    receipt_count: int


@dataclass(frozen=True, slots=True)
class ReceiptView:
    board_index: int
    version: int
    rid: str
    receipt_valid: str


@dataclass(frozen=True, slots=True)
class BoardRecordView:
    index: int
    record_type: str
    pseudonym: str
    version: str
    rid: str
    chain_hash: str
    status: str


@dataclass(frozen=True, slots=True)
class VerificationView:
    params_signature_valid: bool
    ta_signature_valid: bool
    hash_chain_valid: bool
    public_log_valid: bool
    public_election_valid: bool

    @property
    def all_passed(self) -> bool:
        return (
            self.params_signature_valid
            and self.ta_signature_valid
            and self.hash_chain_valid
            and self.public_log_valid
            and self.public_election_valid
        )


@dataclass(frozen=True, slots=True)
class TallyView:
    totals_by_list: tuple[tuple[str, int], ...]
    final_ballots: int
    valid_ballots: int
    anomalous_ballots: int
    ta_signature_status: str
    hash_chain_status: str
    public_log_status: str
    public_verification_status: str


@dataclass(frozen=True, slots=True)
class ActionState:
    can_initialize: bool
    can_authorize: bool
    can_deposit: bool
    can_replace: bool
    can_close: bool
    can_tally: bool
    can_verify: bool
    can_reset: bool


@dataclass(frozen=True, slots=True)
class GuiSnapshot:
    config: ConfigView
    voters: tuple[VoterView, ...]
    bulletin_board: tuple[BoardRecordView, ...]
    tally: TallyView
    actions: ActionState
    last_receipt: ReceiptView | None
    log_messages: tuple[str, ...]


class DemoGuiController:
    """Step-by-step controller for the demonstration election."""

    def __init__(
        self,
        profile: DemoProfile | None = None,
        *,
        runtime_parent: str | Path | None = None,
    ) -> None:
        selected_profile = default_demo_profile() if profile is None else profile
        if not isinstance(selected_profile, DemoProfile):
            raise GuiControllerError("profilo dimostrativo non valido")
        self._base_profile = selected_profile
        self._runtime_parent = Path(runtime_parent) if runtime_parent is not None else selected_profile.runtime_dir
        self._runtime_handle: object | None = None
        self._profile = selected_profile
        self._setup: ElectionSetup | None = None
        self._credentials: dict[str, bytes] = {}
        self._states: dict[str, PseudonymousVoterState] = {}
        self._last_receipt: ReceiptView | None = None
        self._tally_result: TallyResult | None = None
        self._verification: VerificationView | None = None
        self._vote_counter = 0
        self._log: list[str] = []
        self.reset()

    @property
    def profile(self) -> DemoProfile:
        return self._profile

    def reset(self) -> GuiSnapshot:
        self._cleanup_runtime()
        self._profile = self._base_profile
        self._setup = None
        self._credentials = {}
        self._states = {}
        self._last_receipt = None
        self._tally_result = None
        self._verification = None
        self._vote_counter = 0
        self._log = ["Sessione dimostrativa azzerata."]
        return self.snapshot()

    def reset_and_initialize(self) -> GuiSnapshot:
        self.reset()
        return self.initialize_election()

    def initialize_election(self) -> GuiSnapshot:
        if self._setup is not None:
            raise GuiControllerError("l'elezione e' gia' inizializzata")
        runtime_path = self._new_runtime_dir()
        self._profile = replace(self._base_profile, runtime_dir=runtime_path)
        self._setup = setup_demo_election(self._profile, runtime_dir=runtime_path)
        self._credentials = {
            voter.local_voter_id: os.urandom(32) for voter in self._profile.voters
        }
        for voter in self._profile.voters:
            self._setup.registration_authority.register_voter(
                voter.institutional_id,
                self._credentials[voter.local_voter_id],
            )
        self._log.append("Elezione inizializzata con profilo dimostrativo locale.")
        return self.snapshot()

    def authorize_voter(self, voter_id: str) -> GuiSnapshot:
        setup = self._require_open_setup()
        voter = self._find_voter(voter_id)
        if voter.local_voter_id in self._states:
            raise GuiControllerError("elettore gia' autorizzato")
        try:
            material = generate_authorization_material(setup.params.election_id)
            tau_i = setup.registration_authority.issue_authorization(
                voter.institutional_id,
                self._credentials[voter.local_voter_id],
                material.authorization_request,
            )
            self._states[voter.local_voter_id] = material.complete(tau_i)
        except Exception as exc:
            raise GuiControllerError("autorizzazione non completata") from exc
        self._log.append(f"Elettore {voter.local_voter_id} autorizzato.")
        return self.snapshot()

    def deposit_vote(self, voter_id: str, list_code: str) -> GuiSnapshot:
        state = self._require_authorized_state(voter_id)
        if state.current_vote_version != 0:
            raise GuiControllerError("usa la sostituzione per una nuova versione del voto")
        return self._submit_vote(voter_id, list_code)

    def replace_vote(self, voter_id: str, list_code: str) -> GuiSnapshot:
        state = self._require_authorized_state(voter_id)
        setup = self._require_open_setup()
        if state.current_vote_version == 0:
            raise GuiControllerError("non esiste ancora un voto da sostituire")
        if state.current_vote_version >= setup.params.vmax:
            raise GuiControllerError("numero massimo di versioni raggiunto")
        return self._submit_vote(voter_id, list_code)

    def close_election(self) -> GuiSnapshot:
        setup = self._require_setup()
        if setup.bulletin_board.is_closed:
            raise GuiControllerError("l'elezione e' gia' chiusa")
        try:
            close_state = setup.bulletin_board.close(now_ms=setup.params.closes_at_ms)
        except BulletinBoardError as exc:
            raise GuiControllerError("chiusura non completata") from exc
        self._log.append(f"Elezione chiusa: hash {short_hash(close_state.h_close)}.")
        return self.snapshot()

    def run_tally(self) -> GuiSnapshot:
        setup = self._require_closed_setup()
        if self._tally_result is not None:
            raise GuiControllerError("scrutinio gia' eseguito")
        close_state = setup.bulletin_board.close_state
        if close_state is None:
            raise GuiControllerError("chiudi l'elezione prima dello scrutinio")
        if not verify_public_params_signature(setup.params):
            raise GuiControllerError("firma dei parametri pubblici non valida")
        try:
            report = setup.tallying_authority.tally(
                params=setup.params,
                records=setup.bulletin_board.records,
                close_state=close_state,
                blob=setup.blob_ta,
                shares=setup.commissioner_set.shares[: setup.params.threshold.t],
                signing_private_key=setup.ta_signing_private_key,
            )
        except Exception as exc:
            raise GuiControllerError("scrutinio non completato") from exc
        self._tally_result = report.result
        self._log.append("Scrutinio completato e risultato firmato dalla TA.")
        return self.snapshot()

    def run_public_verification(self) -> GuiSnapshot:
        setup = self._require_closed_setup()
        if self._tally_result is None:
            raise GuiControllerError("esegui lo scrutinio prima della verifica pubblica")
        close_state = setup.bulletin_board.close_state
        if close_state is None:
            raise GuiControllerError("chiudi l'elezione prima della verifica")
        self._verification = VerificationView(
            params_signature_valid=verify_public_params_signature(setup.params),
            ta_signature_valid=verify_tally_result_signature(setup.params.pk_ta_sig, self._tally_result),
            hash_chain_valid=setup.bulletin_board.verify_hash_chain(),
            public_log_valid=verify_public_log(setup.params, setup.bulletin_board.records, close_state),
            public_election_valid=verify_public_election(
                setup.params,
                setup.bulletin_board.records,
                close_state,
                self._tally_result,
            ),
        )
        self._log.append(
            "Verifica pubblica completata: "
            f"{'OK' if self._verification.all_passed else 'FALLITA'}."
        )
        return self.snapshot()

    def snapshot(self) -> GuiSnapshot:
        return GuiSnapshot(
            config=self._config_view(),
            voters=self._voter_views(),
            bulletin_board=self._board_views(),
            tally=self._tally_view(),
            actions=self._action_state(),
            last_receipt=self._last_receipt,
            log_messages=tuple(self._log),
        )

    def _submit_vote(self, voter_id: str, list_code: str) -> GuiSnapshot:
        setup = self._require_open_setup()
        voter = self._find_voter(voter_id)
        state = self._require_authorized_state(voter.local_voter_id)
        if list_code not in setup.profile.allowed_list_codes:
            raise GuiControllerError("lista non ammessa")
        try:
            package = prepare_vote_package(
                state,
                list_code,
                allowed_list_codes=setup.profile.allowed_list_codes,
                ta_public_key_pem=setup.params.pk_ta_enc,
            )
            receipt = setup.bulletin_board.submit_vote(package, now_ms=self._next_vote_time())
            updated = apply_accepted_receipt(
                state,
                package,
                receipt,
                bb_public_key_pem=setup.params.pk_bb,
            )
        except (EvotingError, ModelValidationError) as exc:
            raise GuiControllerError("voto non accettato") from exc
        self._states[voter.local_voter_id] = updated
        self._last_receipt = self._receipt_view(receipt, updated)
        self._log.append(
            "Voto accettato: "
            f"indice BB {self._last_receipt.board_index}, "
            f"versione {self._last_receipt.version}, "
            f"RID {self._last_receipt.rid}, "
            f"ricevuta valida {self._last_receipt.receipt_valid}."
        )
        return self.snapshot()

    def _receipt_view(self, receipt: Ack, state: PseudonymousVoterState) -> ReceiptView:
        setup = self._require_setup()
        return ReceiptView(
            board_index=receipt.index,
            version=state.current_vote_version,
            rid=short_rid(receipt.rid),
            receipt_valid=yes_no(setup.bulletin_board.verify_receipt(receipt)),
        )

    def _config_view(self) -> ConfigView:
        return ConfigView(
            election_id=self._profile.election_id,
            lists=tuple((item.code, item.label) for item in self._profile.lists),
            vmax=self._profile.vmax,
            threshold=f"{self._profile.threshold.t}/{self._profile.threshold.n}",
            voter_count=self._profile.voter_count,
            election_status=self._status_label(),
        )

    def _voter_views(self) -> tuple[VoterView, ...]:
        rows = []
        for voter in self._profile.voters:
            state = self._states.get(voter.local_voter_id)
            rows.append(
                VoterView(
                    voter_id=voter.local_voter_id,
                    authorization_status="Autorizzato" if state is not None else "Non autorizzato",
                    current_version=0 if state is None else state.current_vote_version,
                    receipt_count=0 if state is None else len(state.receipts),
                )
            )
        return tuple(rows)

    def _board_views(self) -> tuple[BoardRecordView, ...]:
        setup = self._setup
        if setup is None:
            return ()
        final_rids = self._current_final_rids(setup.bulletin_board.records)
        rows: list[BoardRecordView] = []
        for record in setup.bulletin_board.records:
            entry = record.entry
            if isinstance(entry, BoardEntry):
                rows.append(
                    BoardRecordView(
                        index=record.index,
                        record_type=entry.type.value,
                        pseudonym=short_pseudonym(entry.p_i),
                        version=str(entry.v_i),
                        rid=short_rid(entry.rid),
                        chain_hash=short_hash(record.chain_hash),
                        status="finale" if entry.rid in final_rids else "sostituita",
                    )
                )
            elif isinstance(entry, CloseEntry):
                rows.append(
                    BoardRecordView(
                        index=record.index,
                        record_type=entry.type.value,
                        pseudonym="",
                        version="",
                        rid="",
                        chain_hash=short_hash(record.chain_hash),
                        status="chiusura",
                    )
                )
        return tuple(rows)

    def _tally_view(self) -> TallyView:
        result = self._tally_result
        totals: Mapping[str, int]
        if result is None:
            totals = {item.code: 0 for item in self._profile.lists}
            final_ballots = 0
            valid_ballots = 0
            anomalous_ballots = 0
        else:
            totals = result.totals_by_list
            final_ballots = result.final_ballot_count
            valid_ballots = result.valid_ballot_count
            anomalous_ballots = result.anomalous_count
        verification = self._verification
        return TallyView(
            totals_by_list=tuple((item.code, totals.get(item.code, 0)) for item in self._profile.lists),
            final_ballots=final_ballots,
            valid_ballots=valid_ballots,
            anomalous_ballots=anomalous_ballots,
            ta_signature_status=_status_from_bool(None if verification is None else verification.ta_signature_valid),
            hash_chain_status=_status_from_bool(None if verification is None else verification.hash_chain_valid),
            public_log_status=_status_from_bool(None if verification is None else verification.public_log_valid),
            public_verification_status=_status_from_bool(
                None if verification is None else verification.public_election_valid
            ),
        )

    def _action_state(self) -> ActionState:
        setup = self._setup
        open_setup = setup is not None and not setup.bulletin_board.is_closed
        any_authorized = any(state.current_vote_version == 0 for state in self._states.values())
        any_replaceable = (
            setup is not None
            and any(0 < state.current_vote_version < setup.params.vmax for state in self._states.values())
        )
        return ActionState(
            can_initialize=setup is None,
            can_authorize=open_setup and len(self._states) < self._profile.voter_count,
            can_deposit=open_setup and any_authorized,
            can_replace=open_setup and any_replaceable,
            can_close=setup is not None and not setup.bulletin_board.is_closed,
            can_tally=setup is not None and setup.bulletin_board.is_closed and self._tally_result is None,
            can_verify=self._tally_result is not None and self._verification is None,
            can_reset=True,
        )

    def _current_final_rids(self, records: tuple[BoardLogRecord, ...]) -> set[bytes]:
        setup = self._setup
        if setup is None:
            return set()
        if setup.bulletin_board.close_state is not None:
            try:
                return {
                    entry.rid
                    for entry in select_final_ballot_entries(
                        setup.params,
                        records,
                        setup.bulletin_board.close_state,
                    )
                }
            except Exception:
                return set()
        latest: dict[bytes, BoardEntry] = {}
        for record in records:
            if isinstance(record.entry, BoardEntry):
                latest[record.entry.p_i] = record.entry
        return {entry.rid for entry in latest.values()}

    def _status_label(self) -> str:
        setup = self._setup
        if setup is None:
            return "Non inizializzata"
        if self._verification is not None:
            return "Verificata"
        if self._tally_result is not None:
            return "Scrutinata"
        if setup.bulletin_board.is_closed:
            return "Chiusa"
        return "Aperta"

    def _new_runtime_dir(self) -> Path:
        self._runtime_parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.TemporaryDirectory(prefix="gui-demo-", dir=self._runtime_parent)
        self._runtime_handle = handle
        return Path(handle.name)

    def _cleanup_runtime(self) -> None:
        handle = self._runtime_handle
        self._runtime_handle = None
        if handle is not None:
            cleanup = getattr(handle, "cleanup", None)
            if callable(cleanup):
                cleanup()

    def _next_vote_time(self) -> int:
        setup = self._require_open_setup()
        self._vote_counter += 1
        candidate = setup.params.opens_at_ms + self._vote_counter
        if candidate >= setup.params.closes_at_ms:
            raise GuiControllerError("periodo di voto esaurito")
        return candidate

    def _find_voter(self, voter_id: str) -> DemoVoter:
        for voter in self._profile.voters:
            if voter.local_voter_id == voter_id:
                return voter
        raise GuiControllerError("elettore non trovato")

    def _require_setup(self) -> ElectionSetup:
        if self._setup is None:
            raise GuiControllerError("inizializza l'elezione prima di questa operazione")
        return self._setup

    def _require_open_setup(self) -> ElectionSetup:
        setup = self._require_setup()
        if setup.bulletin_board.is_closed:
            raise GuiControllerError("l'elezione e' chiusa")
        return setup

    def _require_closed_setup(self) -> ElectionSetup:
        setup = self._require_setup()
        if not setup.bulletin_board.is_closed:
            raise GuiControllerError("chiudi l'elezione prima di questa operazione")
        return setup

    def _require_authorized_state(self, voter_id: str) -> PseudonymousVoterState:
        self._require_open_setup()
        voter = self._find_voter(voter_id)
        state = self._states.get(voter.local_voter_id)
        if state is None:
            raise GuiControllerError("autorizza l'elettore prima del voto")
        return state


def _status_from_bool(value: bool | None) -> str:
    if value is None:
        return "Non eseguita"
    return "OK" if value else "FALLITA"


__all__ = [
    "ActionState",
    "BoardRecordView",
    "ConfigView",
    "DemoGuiController",
    "GuiControllerError",
    "GuiSnapshot",
    "ReceiptView",
    "TallyView",
    "VerificationView",
    "VoterView",
]
