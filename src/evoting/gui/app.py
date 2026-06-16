"""Tkinter entry point for the local demonstration GUI."""

from __future__ import annotations

import argparse
import sys
import tkinter as tk
from tkinter import messagebox, ttk

from evoting.config import default_demo_profile
from evoting.gui.controller import DemoGuiController, GuiControllerError, GuiSnapshot


BOARD_COLUMNS = (
    ("index", "Indice", 70, tk.CENTER),
    ("type", "Tipo", 90, tk.CENTER),
    ("pseudonym", "Pseudonimo", 150, tk.W),
    ("version", "Versione", 90, tk.CENTER),
    ("rid", "RID", 150, tk.W),
    ("chain_hash", "Hash chain", 160, tk.W),
    ("status", "Stato", 120, tk.W),
)


class DemoGuiApp:
    """Main Tkinter application for the stand-alone demonstration."""

    def __init__(self, root: tk.Tk, controller: DemoGuiController | None = None) -> None:
        self.root = root
        self.controller = DemoGuiController() if controller is None else controller
        self.status_text = tk.StringVar(value="")
        self.list_choice = tk.StringVar(value="")
        self._list_by_label: dict[str, str] = {}
        self._voters_by_id = {}

        root.title("APS E-Voting WP4 - Demo locale")
        root.geometry("1100x720")
        root.minsize(960, 620)

        self._build_layout()
        self._refresh(self.controller.snapshot())

    def _build_layout(self) -> None:
        root_frame = ttk.Frame(self.root, padding=8)
        root_frame.pack(fill=tk.BOTH, expand=True)

        toolbar = ttk.Frame(root_frame)
        toolbar.pack(fill=tk.X)
        self.reset_button = ttk.Button(toolbar, text="Azzera e ricrea demo", command=self._reset_demo)
        self.reset_button.pack(side=tk.RIGHT)

        self.notebook = ttk.Notebook(root_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(8, 6))

        self.config_tab = ttk.Frame(self.notebook, padding=10)
        self.voters_tab = ttk.Frame(self.notebook, padding=10)
        self.board_tab = ttk.Frame(self.notebook, padding=10)
        self.tally_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.config_tab, text="Configurazione")
        self.notebook.add(self.voters_tab, text="Elettori e voto")
        self.notebook.add(self.board_tab, text="Bulletin Board")
        self.notebook.add(self.tally_tab, text="Scrutinio e verifica")

        self._build_config_tab()
        self._build_voters_tab()
        self._build_board_tab()
        self._build_tally_tab()

        log_frame = ttk.LabelFrame(root_frame, text="Log dimostrativo")
        log_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 6))
        self.log_text = tk.Text(log_frame, height=7, wrap=tk.WORD, state=tk.DISABLED)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        status = ttk.Label(root_frame, textvariable=self.status_text, anchor=tk.W, relief=tk.SUNKEN)
        status.pack(fill=tk.X)

    def _build_config_tab(self) -> None:
        self.config_vars = {
            "election_id": tk.StringVar(),
            "lists": tk.StringVar(),
            "vmax": tk.StringVar(),
            "threshold": tk.StringVar(),
            "voter_count": tk.StringVar(),
            "status": tk.StringVar(),
        }
        rows = (
            ("Election ID", "election_id"),
            ("Liste", "lists"),
            ("Vmax", "vmax"),
            ("Soglia t/n", "threshold"),
            ("Numero elettori", "voter_count"),
            ("Stato elezione", "status"),
        )
        for row_index, (label, key) in enumerate(rows):
            ttk.Label(self.config_tab, text=label).grid(row=row_index, column=0, sticky=tk.W, pady=4)
            ttk.Label(self.config_tab, textvariable=self.config_vars[key]).grid(
                row=row_index,
                column=1,
                sticky=tk.W,
                pady=4,
                padx=(16, 0),
            )
        self.init_button = ttk.Button(
            self.config_tab,
            text="Inizializza elezione",
            command=lambda: self._run_action(self.controller.initialize_election),
        )
        self.init_button.grid(row=len(rows), column=0, sticky=tk.W, pady=(18, 0))
        self.config_tab.columnconfigure(1, weight=1)

    def _build_voters_tab(self) -> None:
        self.voters_tree = ttk.Treeview(
            self.voters_tab,
            columns=("authorized", "version", "receipts"),
            show="tree headings",
            height=12,
        )
        self.voters_tree.heading("#0", text="Elettore")
        self.voters_tree.heading("authorized", text="Autorizzazione")
        self.voters_tree.heading("version", text="Versione")
        self.voters_tree.heading("receipts", text="Ricevute")
        self.voters_tree.column("#0", width=220, anchor=tk.W)
        self.voters_tree.column("authorized", width=160, anchor=tk.W)
        self.voters_tree.column("version", width=90, anchor=tk.CENTER)
        self.voters_tree.column("receipts", width=90, anchor=tk.CENTER)
        self.voters_tree.grid(row=0, column=0, columnspan=4, sticky="nsew")
        self.voters_tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_action_buttons())

        controls = ttk.Frame(self.voters_tab)
        controls.grid(row=1, column=0, columnspan=4, sticky=tk.W, pady=(12, 0))
        ttk.Label(controls, text="Lista").pack(side=tk.LEFT)
        self.list_combo = ttk.Combobox(controls, textvariable=self.list_choice, state="readonly", width=28)
        self.list_combo.pack(side=tk.LEFT, padx=(8, 12))
        self.list_combo.bind("<<ComboboxSelected>>", lambda _event: self._refresh_action_buttons())

        self.authorize_button = ttk.Button(controls, text="Autorizza elettore", command=self._authorize_selected)
        self.deposit_button = ttk.Button(controls, text="Deposita voto", command=self._deposit_selected)
        self.replace_button = ttk.Button(controls, text="Sostituisci voto", command=self._replace_selected)
        self.authorize_button.pack(side=tk.LEFT, padx=(0, 6))
        self.deposit_button.pack(side=tk.LEFT, padx=(0, 6))
        self.replace_button.pack(side=tk.LEFT)

        receipt_frame = ttk.LabelFrame(self.voters_tab, text="Ultimo deposito accettato")
        receipt_frame.grid(row=2, column=0, columnspan=4, sticky=tk.EW, pady=(14, 0))
        self.receipt_vars = {
            "index": tk.StringVar(value=""),
            "version": tk.StringVar(value=""),
            "rid": tk.StringVar(value=""),
            "valid": tk.StringVar(value=""),
        }
        receipt_rows = (
            ("Indice BB", "index"),
            ("Versione", "version"),
            ("RID", "rid"),
            ("Ricevuta valida", "valid"),
        )
        for column, (label, key) in enumerate(receipt_rows):
            ttk.Label(receipt_frame, text=label).grid(row=0, column=column * 2, sticky=tk.W, padx=(0, 6))
            ttk.Label(receipt_frame, textvariable=self.receipt_vars[key]).grid(
                row=0,
                column=column * 2 + 1,
                sticky=tk.W,
                padx=(0, 20),
            )

        self.voters_tab.rowconfigure(0, weight=1)
        self.voters_tab.columnconfigure(0, weight=1)

    def _build_board_tab(self) -> None:
        self.board_tree = ttk.Treeview(
            self.board_tab,
            columns=tuple(column for column, _label, _width, _anchor in BOARD_COLUMNS),
            show="headings",
        )
        for column, label, width, anchor in BOARD_COLUMNS:
            self.board_tree.heading(column, text=label)
            self.board_tree.column(column, width=width, anchor=anchor)
        board_scroll = ttk.Scrollbar(self.board_tab, orient=tk.VERTICAL, command=self.board_tree.yview)
        self.board_tree.configure(yscrollcommand=board_scroll.set)
        self.board_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        board_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_tally_tab(self) -> None:
        actions = ttk.Frame(self.tally_tab)
        actions.pack(fill=tk.X)
        self.close_button = ttk.Button(actions, text="Chiudi elezione", command=self._close_election)
        self.tally_button = ttk.Button(actions, text="Esegui scrutinio", command=self._run_tally)
        self.verify_button = ttk.Button(actions, text="Verifica pubblicamente", command=self._run_public_verification)
        self.close_button.pack(side=tk.LEFT, padx=(0, 6))
        self.tally_button.pack(side=tk.LEFT, padx=(0, 6))
        self.verify_button.pack(side=tk.LEFT)

        content = ttk.Frame(self.tally_tab)
        content.pack(fill=tk.BOTH, expand=True, pady=(14, 0))

        totals_frame = ttk.LabelFrame(content, text="Conteggio per lista")
        totals_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        self.totals_tree = ttk.Treeview(totals_frame, columns=("total",), show="tree headings", height=8)
        self.totals_tree.heading("#0", text="Lista")
        self.totals_tree.heading("total", text="Totale")
        self.totals_tree.column("#0", width=220)
        self.totals_tree.column("total", width=90, anchor=tk.CENTER)
        self.totals_tree.pack(fill=tk.BOTH, expand=True)

        summary_frame = ttk.LabelFrame(content, text="Verifiche")
        summary_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tally_vars = {
            "final": tk.StringVar(),
            "valid": tk.StringVar(),
            "anomalous": tk.StringVar(),
            "ta": tk.StringVar(),
            "hash_chain": tk.StringVar(),
            "public_log": tk.StringVar(),
            "public": tk.StringVar(),
        }
        rows = (
            ("Schede finali", "final"),
            ("Schede valide", "valid"),
            ("Schede anomale", "anomalous"),
            ("Firma TA", "ta"),
            ("Hash chain", "hash_chain"),
            ("Registro pubblico", "public_log"),
            ("Verifica pubblica", "public"),
        )
        for row_index, (label, key) in enumerate(rows):
            ttk.Label(summary_frame, text=label).grid(row=row_index, column=0, sticky=tk.W, pady=4)
            ttk.Label(summary_frame, textvariable=self.tally_vars[key]).grid(
                row=row_index,
                column=1,
                sticky=tk.W,
                padx=(14, 0),
                pady=4,
            )

    def _authorize_selected(self) -> None:
        voter_id = self._selected_voter_id()
        if voter_id is None:
            self._show_error("Seleziona un elettore.")
            return
        self._run_action(self.controller.authorize_voter, voter_id)

    def _deposit_selected(self) -> None:
        voter_id = self._selected_voter_id()
        list_code = self._selected_list_code()
        if voter_id is None or list_code is None:
            self._show_error("Seleziona elettore e lista.")
            return
        self._run_action(self.controller.deposit_vote, voter_id, list_code, clear_choice=True)

    def _replace_selected(self) -> None:
        voter_id = self._selected_voter_id()
        list_code = self._selected_list_code()
        if voter_id is None or list_code is None:
            self._show_error("Seleziona elettore e lista.")
            return
        self._run_action(self.controller.replace_vote, voter_id, list_code, clear_choice=True)

    def _close_election(self) -> None:
        self._run_action(self.controller.close_election)

    def _run_tally(self) -> None:
        self._run_action(self.controller.run_tally)

    def _run_public_verification(self) -> None:
        self._run_action(self.controller.run_public_verification)

    def _reset_demo(self) -> None:
        self._run_action(self.controller.reset_and_initialize, clear_choice=True)

    def _run_action(self, action, *args, clear_choice: bool = False) -> None:
        try:
            snapshot = action(*args)
        except GuiControllerError as exc:
            self._show_error(str(exc))
            return
        except Exception:
            self._show_error("Operazione non completata.")
            return
        if clear_choice:
            self.list_choice.set("")
        self._refresh(snapshot)

    def _refresh(self, snapshot: GuiSnapshot) -> None:
        config = snapshot.config
        self.config_vars["election_id"].set(config.election_id)
        self.config_vars["lists"].set(", ".join(f"{code} ({label})" for code, label in config.lists))
        self.config_vars["vmax"].set(str(config.vmax))
        self.config_vars["threshold"].set(config.threshold)
        self.config_vars["voter_count"].set(str(config.voter_count))
        self.config_vars["status"].set(config.election_status)
        self.status_text.set(f"Stato: {config.election_status}")

        labels = [f"{code} - {label}" for code, label in config.lists]
        self._list_by_label = {label: code for label, (code, _name) in zip(labels, config.lists, strict=True)}
        self.list_combo.configure(values=labels)

        self._voters_by_id = {row.voter_id: row for row in snapshot.voters}
        selected = self._selected_voter_id()
        self.voters_tree.delete(*self.voters_tree.get_children())
        for row in snapshot.voters:
            self.voters_tree.insert(
                "",
                tk.END,
                iid=row.voter_id,
                text=row.voter_id,
                values=(row.authorization_status, row.current_version, row.receipt_count),
            )
        if selected in self._voters_by_id:
            self.voters_tree.selection_set(selected)

        self.board_tree.delete(*self.board_tree.get_children())
        for row in snapshot.bulletin_board:
            self.board_tree.insert(
                "",
                tk.END,
                values=(
                    row.index,
                    row.record_type,
                    row.pseudonym,
                    row.version,
                    row.rid,
                    row.chain_hash,
                    row.status,
                ),
            )

        self.totals_tree.delete(*self.totals_tree.get_children())
        for code, total in snapshot.tally.totals_by_list:
            self.totals_tree.insert("", tk.END, text=code, values=(total,))
        self.tally_vars["final"].set(str(snapshot.tally.final_ballots))
        self.tally_vars["valid"].set(str(snapshot.tally.valid_ballots))
        self.tally_vars["anomalous"].set(str(snapshot.tally.anomalous_ballots))
        self.tally_vars["ta"].set(snapshot.tally.ta_signature_status)
        self.tally_vars["hash_chain"].set(snapshot.tally.hash_chain_status)
        self.tally_vars["public_log"].set(snapshot.tally.public_log_status)
        self.tally_vars["public"].set(snapshot.tally.public_verification_status)

        if snapshot.last_receipt is None:
            for variable in self.receipt_vars.values():
                variable.set("")
        else:
            self.receipt_vars["index"].set(str(snapshot.last_receipt.board_index))
            self.receipt_vars["version"].set(str(snapshot.last_receipt.version))
            self.receipt_vars["rid"].set(snapshot.last_receipt.rid)
            self.receipt_vars["valid"].set(snapshot.last_receipt.receipt_valid)

        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, "\n".join(snapshot.log_messages))
        self.log_text.configure(state=tk.DISABLED)
        self.log_text.see(tk.END)

        self._refresh_action_buttons(snapshot)

    def _refresh_action_buttons(self, snapshot: GuiSnapshot | None = None) -> None:
        snapshot = self.controller.snapshot() if snapshot is None else snapshot
        selected_row = self._voters_by_id.get(self._selected_voter_id())
        list_selected = self._selected_list_code() is not None
        authorized = selected_row is not None and selected_row.authorization_status == "Autorizzato"
        can_deposit_selected = (
            snapshot.actions.can_deposit
            and authorized
            and selected_row.current_version == 0
            and list_selected
        )
        can_replace_selected = (
            snapshot.actions.can_replace
            and authorized
            and 0 < selected_row.current_version < self.controller.profile.vmax
            and list_selected
        )
        self.init_button.configure(state=tk.NORMAL if snapshot.actions.can_initialize else tk.DISABLED)
        self.authorize_button.configure(
            state=tk.NORMAL
            if snapshot.actions.can_authorize and selected_row is not None and not authorized
            else tk.DISABLED
        )
        self.deposit_button.configure(state=tk.NORMAL if can_deposit_selected else tk.DISABLED)
        self.replace_button.configure(state=tk.NORMAL if can_replace_selected else tk.DISABLED)
        self.close_button.configure(state=tk.NORMAL if snapshot.actions.can_close else tk.DISABLED)
        self.tally_button.configure(state=tk.NORMAL if snapshot.actions.can_tally else tk.DISABLED)
        self.verify_button.configure(state=tk.NORMAL if snapshot.actions.can_verify else tk.DISABLED)
        self.reset_button.configure(state=tk.NORMAL if snapshot.actions.can_reset else tk.DISABLED)

    def _selected_voter_id(self) -> str | None:
        selection = self.voters_tree.selection()
        if not selection:
            return None
        return str(selection[0])

    def _selected_list_code(self) -> str | None:
        selected = self.list_choice.get()
        if not selected:
            return None
        return self._list_by_label.get(selected)

    def _show_error(self, message: str) -> None:
        self.status_text.set(message)
        messagebox.showerror("Operazione non disponibile", message)


def run_check() -> int:
    profile = default_demo_profile()
    controller = DemoGuiController(profile)
    snapshot = controller.snapshot()
    if snapshot.config.election_id != profile.election_id:
        return 1
    if len(snapshot.voters) != profile.voter_count:
        return 1
    print("GUI check OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Demo GUI locale del protocollo APS E-Voting")
    parser.add_argument("--check", action="store_true", help="verifica import e controller senza aprire finestre")
    args = parser.parse_args(argv)
    if args.check:
        return run_check()

    root = tk.Tk()
    DemoGuiApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
