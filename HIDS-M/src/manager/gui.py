from __future__ import annotations

import json
import logging
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from typing import List, Tuple, Optional

from manager.storage import Storage

logger = logging.getLogger(__name__)


Row = Tuple[int, str, str, str, str, str, str]
# (_id, ts, sev, src, kind, summary, details)


class ManagerGUI(tk.Tk):
    def __init__(self, db_path: str):
        super().__init__()
        self.title("HIDS Manager & Monitoring Console")
        self.geometry("1900x850")
        self.minsize(1100, 700)

        self.store = Storage(db_path)

        # state
        self.rows: List[Row] = []
        self.filtered_rows: List[Row] = []
        self.auto_refresh_enabled = tk.BooleanVar(value=True)
        self.popup_critical_enabled = tk.BooleanVar(value=True)
        self.beep_critical_enabled = tk.BooleanVar(value=False)
        self.refresh_interval_ms = tk.IntVar(value=2000)

        # last seen event id (for “new critical popup”)
        self.last_seen_id: int = 0

        # UI
        self._build_style()
        self._build_menu()
        self._build_layout()

        # initial load
        self.refresh()
        self._schedule_auto_refresh()

    # ---------------- UI building ----------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("Small.TLabel", font=("Segoe UI", 9))
        style.configure("Danger.TLabel", foreground="#b00020")
        style.configure("Ok.TLabel", foreground="#1b5e20")

    def _build_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Filtered CSV...", command=self.export_csv_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)

        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_checkbutton(label="Auto-refresh", variable=self.auto_refresh_enabled)
        view_menu.add_checkbutton(label="Popup on CRITICAL", variable=self.popup_critical_enabled)
        view_menu.add_checkbutton(label="Beep on CRITICAL", variable=self.beep_critical_enabled)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def _build_layout(self):
        # status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        status.pack(side=tk.BOTTOM, fill=tk.X)

        # notebook tabs
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True)

        self.tab_events = ttk.Frame(self.nb, padding=(10, 10))
        self.tab_dashboard = ttk.Frame(self.nb, padding=(10, 10))
        self.tab_tools = ttk.Frame(self.nb, padding=(10, 10))

        self.nb.add(self.tab_events, text="Events")
        self.nb.add(self.tab_dashboard, text="Dashboard")
        self.nb.add(self.tab_tools, text="Tools")

        self._build_events_tab()
        self._build_dashboard_tab()
        self._build_tools_tab()

    # ---------------- Events tab ----------------
    def _build_events_tab(self):
        top = ttk.Frame(self.tab_events)
        top.pack(fill="x", pady=(0, 8))

        ttk.Label(top, text="Filters", style="Header.TLabel").pack(side=tk.LEFT)

        # Severity filter
        ttk.Label(top, text="Severity:", padding=(10, 0, 0, 0)).pack(side=tk.LEFT)
        self.sev_var = tk.StringVar(value="ALL")
        self.sev_cb = ttk.Combobox(
            top,
            textvariable=self.sev_var,
            values=["ALL", "CRITICAL", "HIGH", "WARN", "INFO"],
            state="readonly",
            width=10,
        )
        self.sev_cb.pack(side=tk.LEFT, padx=(4, 0))
        self.sev_cb.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        # Kind filter
        ttk.Label(top, text="Kind:", padding=(10, 0, 0, 0)).pack(side=tk.LEFT)
        self.kind_var = tk.StringVar(value="ALL")
        self.kind_cb = ttk.Combobox(top, textvariable=self.kind_var, values=["ALL"], state="readonly", width=22)
        self.kind_cb.pack(side=tk.LEFT, padx=(4, 0))
        self.kind_cb.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        # Source filter
        ttk.Label(top, text="Source:", padding=(10, 0, 0, 0)).pack(side=tk.LEFT)
        self.src_var = tk.StringVar(value="ALL")
        self.src_cb = ttk.Combobox(top, textvariable=self.src_var, values=["ALL"], state="readonly", width=12)
        self.src_cb.pack(side=tk.LEFT, padx=(4, 0))
        self.src_cb.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        # Search
        ttk.Label(top, text="Search:", padding=(10, 0, 0, 0)).pack(side=tk.LEFT)
        self.search_var = tk.StringVar(value="")
        self.search_entry = ttk.Entry(top, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=(4, 0))
        self.search_entry.bind("<Return>", lambda _e: self.refresh())

        ttk.Button(top, text="Apply", command=self.refresh).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(top, text="Clear", command=self._clear_filters).pack(side=tk.LEFT, padx=(4, 0))

        # main split: table + details
        mid = ttk.Frame(self.tab_events)
        mid.pack(fill="both", expand=True)

        # table
        cols = ("id", "ts", "severity", "source", "kind", "summary")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=18)
        self.tree.heading("id", text="ID")
        self.tree.heading("ts", text="TIME")
        self.tree.heading("severity", text="SEV")
        self.tree.heading("source", text="SRC")
        self.tree.heading("kind", text="KIND")
        self.tree.heading("summary", text="SUMMARY")

        self.tree.column("id", width=70, anchor="center")
        self.tree.column("ts", width=180)
        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("source", width=90, anchor="center")
        self.tree.column("kind", width=160)
        self.tree.column("summary", width=780)

        vsb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        mid.grid_columnconfigure(0, weight=1)
        mid.grid_rowconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        # row coloring
        self.tree.tag_configure("CRITICAL", foreground="white", background="#b00020")
        self.tree.tag_configure("HIGH", foreground="black", background="#ffcc80")
        self.tree.tag_configure("WARN", foreground="black", background="#bbdefb")
        self.tree.tag_configure("INFO", foreground="black", background="#c8e6c9")

        # details area
        details_box = ttk.LabelFrame(self.tab_events, text="Event Details", padding=(10, 10))
        details_box.pack(fill="both", expand=False, pady=(10, 0))

        self.details = tk.Text(details_box, height=10, wrap="word")
        dscroll = ttk.Scrollbar(details_box, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=dscroll.set)

        self.details.grid(row=0, column=0, sticky="nsew")
        dscroll.grid(row=0, column=1, sticky="ns")
        details_box.grid_columnconfigure(0, weight=1)
        details_box.grid_rowconfigure(0, weight=1)

        # actions
        actions = ttk.Frame(self.tab_events)
        actions.pack(fill="x", pady=(8, 0))

        ttk.Button(actions, text="Refresh", command=self.refresh).pack(side=tk.LEFT)
        ttk.Button(actions, text="Export Filtered CSV...", command=self.export_csv_dialog).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(actions, text="Copy Details", command=self.copy_details).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(actions, text="Save Selected JSON...", command=self.save_selected_json).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(actions, text="Clear ALL Events", command=self.clear_all).pack(side=tk.RIGHT)

    def _clear_filters(self):
        self.sev_var.set("ALL")
        self.kind_var.set("ALL")
        self.src_var.set("ALL")
        self.search_var.set("")
        self.refresh()

    # ---------------- Dashboard tab ----------------
    def _build_dashboard_tab(self):
        header = ttk.Label(self.tab_dashboard, text="Live Summary", style="Header.TLabel")
        header.pack(anchor="w")

        cards = ttk.Frame(self.tab_dashboard)
        cards.pack(fill="x", pady=(10, 0))

        self.card_total = ttk.Label(cards, text="Total: 0", style="Header.TLabel")
        self.card_total.grid(row=0, column=0, sticky="w", padx=(0, 20))

        self.card_crit = ttk.Label(cards, text="CRITICAL: 0", style="Danger.TLabel")
        self.card_crit.grid(row=0, column=1, sticky="w", padx=(0, 20))

        self.card_high = ttk.Label(cards, text="HIGH: 0", style="Header.TLabel")
        self.card_high.grid(row=0, column=2, sticky="w", padx=(0, 20))

        self.card_warn = ttk.Label(cards, text="WARN: 0", style="Header.TLabel")
        self.card_warn.grid(row=0, column=3, sticky="w", padx=(0, 20))

        self.card_info = ttk.Label(cards, text="INFO: 0", style="Header.TLabel")
        self.card_info.grid(row=0, column=4, sticky="w")

        # top kinds table
        box = ttk.LabelFrame(self.tab_dashboard, text="Top Event Types (last 500)", padding=(10, 10))
        box.pack(fill="both", expand=True, pady=(12, 0))

        self.top_tree = ttk.Treeview(box, columns=("kind", "count"), show="headings", height=14)
        self.top_tree.heading("kind", text="KIND")
        self.top_tree.heading("count", text="COUNT")
        self.top_tree.column("kind", width=300)
        self.top_tree.column("count", width=120, anchor="center")

        sb = ttk.Scrollbar(box, orient="vertical", command=self.top_tree.yview)
        self.top_tree.configure(yscrollcommand=sb.set)

        self.top_tree.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        box.grid_columnconfigure(0, weight=1)
        box.grid_rowconfigure(0, weight=1)

    # ---------------- Tools tab ----------------
    def _build_tools_tab(self):
        header = ttk.Label(self.tab_tools, text="Tools & Settings", style="Header.TLabel")
        header.pack(anchor="w")

        sec = ttk.LabelFrame(self.tab_tools, text="Refresh", padding=(10, 10))
        sec.pack(fill="x", pady=(10, 0))

        ttk.Checkbutton(sec, text="Auto-refresh", variable=self.auto_refresh_enabled).grid(row=0, column=0, sticky="w")
        ttk.Label(sec, text="Interval (ms):").grid(row=0, column=1, sticky="e", padx=(10, 0))
        ttk.Spinbox(sec, from_=500, to=30000, increment=500, textvariable=self.refresh_interval_ms, width=10).grid(
            row=0, column=2, sticky="w", padx=(6, 0)
        )
        ttk.Button(sec, text="Refresh now", command=self.refresh).grid(row=0, column=3, sticky="w", padx=(10, 0))

        alerts = ttk.LabelFrame(self.tab_tools, text="Alerting", padding=(10, 10))
        alerts.pack(fill="x", pady=(10, 0))
        ttk.Checkbutton(alerts, text="Popup on CRITICAL", variable=self.popup_critical_enabled).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Checkbutton(alerts, text="Beep on CRITICAL", variable=self.beep_critical_enabled).grid(
            row=0, column=1, sticky="w", padx=(15, 0)
        )

        db = ttk.LabelFrame(self.tab_tools, text="Database", padding=(10, 10))
        db.pack(fill="x", pady=(10, 0))
        ttk.Button(db, text="Export Filtered CSV...", command=self.export_csv_dialog).grid(row=0, column=0, sticky="w")
        ttk.Button(db, text="Clear ALL Events", command=self.clear_all).grid(row=0, column=1, sticky="w", padx=(10, 0))

    # ---------------- Core actions ----------------
    def refresh(self):
        try:
            self.rows = self.store.latest(500)
            self._rebuild_filter_choices()
            self.filtered_rows = self._apply_filters(self.rows)
            self._render_table(self.filtered_rows)
            self._render_dashboard(self.rows)
            self._update_status()

            # after rendering, check critical popup on new events only
            self._check_new_critical_popup(self.filtered_rows)

        except Exception as e:
            logger.error(f"Refresh error: {e}", exc_info=True)
            self.status_var.set(f"Refresh error: {e}")

    def _apply_filters(self, rows: List[Row]) -> List[Row]:
        sev = self.sev_var.get()
        kind = self.kind_var.get()
        src = self.src_var.get()
        q = self.search_var.get().strip().lower()

        out: List[Row] = []
        for r in rows:
            _id, ts, rsev, rsrc, rkind, summary, details = r

            if sev != "ALL" and rsev != sev:
                continue
            if kind != "ALL" and rkind != kind:
                continue
            if src != "ALL" and rsrc != src:
                continue

            if q:
                hay = f"{ts} {rsev} {rsrc} {rkind} {summary} {details}".lower()
                if q not in hay:
                    continue

            out.append(r)

        return out

    def _render_table(self, rows: List[Row]):
        self.tree.delete(*self.tree.get_children())

        # render oldest->newest (nice for reading)
        for r in reversed(rows):
            _id, ts, sev, src, kind, summary, _details = r
            tag = sev if sev in ("CRITICAL", "HIGH", "WARN", "INFO") else "INFO"
            self.tree.insert("", "end", values=(_id, ts, sev, src, kind, summary), tags=(tag,))

    def _render_dashboard(self, rows: List[Row]):
        counts = {"CRITICAL": 0, "HIGH": 0, "WARN": 0, "INFO": 0}
        kind_counts: Dict[str, int] = {}

        for _id, ts, sev, src, kind, summary, details in rows:
            if sev in counts:
                counts[sev] += 1
            kind_counts[kind] = kind_counts.get(kind, 0) + 1

        total = self.store.count()
        self.card_total.config(text=f"Total: {total}")
        self.card_crit.config(text=f"CRITICAL: {counts['CRITICAL']}")
        self.card_high.config(text=f"HIGH: {counts['HIGH']}")
        self.card_warn.config(text=f"WARN: {counts['WARN']}")
        self.card_info.config(text=f"INFO: {counts['INFO']}")

        # top kinds
        self.top_tree.delete(*self.top_tree.get_children())
        for kind, c in sorted(kind_counts.items(), key=lambda kv: kv[1], reverse=True)[:25]:
            self.top_tree.insert("", "end", values=(kind, c))

    def _rebuild_filter_choices(self):
        # build from current rows
        kinds = sorted({r[4] for r in self.rows})
        srcs = sorted({r[3] for r in self.rows})

        # preserve selection when possible
        current_kind = self.kind_var.get()
        current_src = self.src_var.get()

        self.kind_cb["values"] = ["ALL"] + kinds
        self.src_cb["values"] = ["ALL"] + srcs

        if current_kind not in self.kind_cb["values"]:
            self.kind_var.set("ALL")
        if current_src not in self.src_cb["values"]:
            self.src_var.set("ALL")

    def on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return

        vals = self.tree.item(sel[0], "values")
        if not vals:
            return
        _id = int(vals[0])

        match = next((r for r in self.rows if r[0] == _id), None)
        if not match:
            return

        _id, ts, sev, src, kind, summary, details = match
        try:
            details_obj = json.loads(details)
            details_pretty = json.dumps(details_obj, indent=2, ensure_ascii=False)
        except Exception:
            details_pretty = details

        text = (
            f"ID: {_id}\n"
            f"Timestamp: {ts}\n"
            f"Severity: {sev}\n"
            f"Source: {src}\n"
            f"Kind: {kind}\n\n"
            f"Summary:\n{summary}\n\n"
            f"Details:\n{details_pretty}\n"
        )

        self.details.delete("1.0", "end")
        self.details.insert("end", text)

    def _update_status(self):
        total = self.store.count()
        self.status_var.set(
            f"Ready | Total events: {total} | Showing: {len(self.filtered_rows)} | Auto-refresh: {self.auto_refresh_enabled.get()}"
        )

    # ---------------- Alerting ----------------
    def _check_new_critical_popup(self, rows: List[Row]):
        # We only popup on new events since last refresh
        newest_id = max((r[0] for r in self.rows), default=0)

        # find critical events that are new
        new_crit = [r for r in self.rows if r[0] > self.last_seen_id and r[2] == "CRITICAL"]

        self.last_seen_id = max(self.last_seen_id, newest_id)

        if not new_crit:
            return

        if self.beep_critical_enabled.get():
            try:
                self.bell()
            except Exception:
                pass

        if self.popup_critical_enabled.get():
            # show one popup summarizing latest critical
            latest = max(new_crit, key=lambda r: r[0])
            _id, ts, sev, src, kind, summary, _details = latest
            messagebox.showwarning(
                "CRITICAL Alert",
                f"[{ts}] {kind}\nSource: {src}\n\n{summary}",
            )

    # ---------------- Tools ----------------
    def export_csv_dialog(self):
        try:
            default_name = f"hids_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                initialfile=default_name,
                title="Export filtered events to CSV",
            )
            if not path:
                return

            # Export ONLY filtered rows
            self._export_rows_to_csv(path, self.filtered_rows)
            messagebox.showinfo("Exported", f"Exported {len(self.filtered_rows)} events to:\n{path}")
        except Exception as e:
            logger.error(f"Export failed: {e}", exc_info=True)
            messagebox.showerror("Export failed", str(e))

    def _export_rows_to_csv(self, path: str, rows: List[Row]):
        import csv

        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "ts", "severity", "source", "kind", "summary", "details"])
            for r in rows:
                w.writerow(list(r))

    def clear_all(self):
        if not messagebox.askyesno("Confirm", "Clear ALL events from the database?"):
            return
        try:
            self.store.clear()
            self.last_seen_id = 0
            self.refresh()
            messagebox.showinfo("Cleared", "All events cleared.")
        except Exception as e:
            logger.error(f"Clear failed: {e}", exc_info=True)
            messagebox.showerror("Clear failed", str(e))

    def copy_details(self):
        txt = self.details.get("1.0", "end").strip()
        if not txt:
            return
        self.clipboard_clear()
        self.clipboard_append(txt)
        self.status_var.set("Copied details to clipboard.")

    def save_selected_json(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select an event row first.")
            return

        vals = self.tree.item(sel[0], "values")
        if not vals:
            return
        _id = int(vals[0])
        match = next((r for r in self.rows if r[0] == _id), None)
        if not match:
            return

        _id, ts, sev, src, kind, summary, details = match

        # build json object
        obj = {
            "id": _id,
            "ts": ts,
            "severity": sev,
            "source": src,
            "kind": kind,
            "summary": summary,
        }
        try:
            obj["details"] = json.loads(details)
        except Exception:
            obj["details"] = details

        default_name = f"hids_event_{_id}.json"
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=default_name,
            title="Save selected event as JSON",
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)

        messagebox.showinfo("Saved", f"Saved event {_id} to:\n{path}")

    # ---------------- Auto-refresh ----------------
    def _schedule_auto_refresh(self):
        try:
            if self.auto_refresh_enabled.get():
                self.refresh()
        finally:
            self.after(max(500, int(self.refresh_interval_ms.get())), self._schedule_auto_refresh)

    # ---------------- Misc ----------------
    def show_about(self):
        messagebox.showinfo(
            "About HIDS Manager",
            "HIDS Manager v1.0+\n\n"
            "Host-based Intrusion Detection System\n"
            "Central monitoring GUI (Tkinter)\n\n"
            "Features:\n"
            "- Live events + filters + search\n"
            "- Dashboard counters\n"
            "- CSV export\n"
            "- CRITICAL popups\n",
        )
