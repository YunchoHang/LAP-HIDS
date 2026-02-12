from __future__ import annotations
import tkinter as tk
from tkinter import ttk
import json
import logging
from datetime import datetime
from manager.storage import Storage

logger = logging.getLogger(__name__)

class ManagerGUI(tk.Tk):
    def __init__(self, db_path: str):
        super().__init__()
        self.title("HIDS Manager & Monitoring Console")
        self.geometry("1400x800")
        self.store = Storage(db_path)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s]: %(message)s'
        )
        
        # Create menu bar
        self.create_menu()
        
        # Create status bar
        self.status_var = tk.StringVar(value="Ready | Events: 0")
        status_bar = ttk.Label(
            self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Create main frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Event list table
        cols = ("id", "ts", "severity", "source", "kind", "summary")
        self.tree = ttk.Treeview(main_frame, columns=cols, show="headings", height=20)
        
        # Define column headings and widths
        widths = {"id": 50, "ts": 170, "severity": 80, "source": 80, "kind": 120, "summary": 600}
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=widths.get(c, 150))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        
        # Details panel
        details_frame = ttk.LabelFrame(self, text="Event Details", padx=5, pady=5)
        details_frame.pack(fill="x", padx=10, pady=(10, 10))
        
        self.details = tk.Text(details_frame, height=10, wrap=tk.WORD)
        details_scrollbar = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.details.yview)
        self.details.configure(yscroll=details_scrollbar.set)
        
        self.details.pack(side=tk.LEFT, fill="both", expand=True)
        details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Button frame
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        ttk.Button(btn_frame, text="Refresh", command=self.refresh).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Clear All Events", command=self.clear_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=2)
        
        # Filter controls
        ttk.Label(btn_frame, text="Filter by severity:").pack(side=tk.LEFT, padx=10)
        self.severity_filter = ttk.Combobox(
            btn_frame, values=["ALL", "CRITICAL", "HIGH", "WARN", "INFO"],
            state="readonly", width=12
        )
        self.severity_filter.set("ALL")
        self.severity_filter.pack(side=tk.LEFT, padx=2)
        self.severity_filter.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        
        # Data
        self.rows = []
        
        # Color tags for severity
        self.tree.tag_configure("CRITICAL", foreground="red", background="#ffcccc")
        self.tree.tag_configure("HIGH", foreground="orange", background="#ffe6cc")
        self.tree.tag_configure("WARN", foreground="blue")
        self.tree.tag_configure("INFO", foreground="green")
        
        # Initial load and auto-refresh
        self.refresh()
        self.auto_refresh()
    
    def create_menu(self):
        """Create menu bar."""
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export CSV", command=self.export_csv)
        file_menu.add_command(label="Clear All Events", command=self.clear_all)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def show_about(self):
        """Show about dialog."""
        about_text = """HIDS Manager v1.0
        
Host-based Intrusion Detection System
Centralized event monitoring and analysis

Made for home server security monitoring."""
        tk.messagebox.showinfo("About HIDS Manager", about_text)
    
    def auto_refresh(self):
        """Auto-refresh events every 2 seconds."""
        self.refresh()
        self.after(2000, self.auto_refresh)
    
    def refresh(self):
        """Refresh event list from database."""
        try:
            severity_filter = self.severity_filter.get()
            self.rows = self.store.latest(500)
            
            # Filter if needed
            if severity_filter != "ALL":
                self.rows = [r for r in self.rows if r[2] == severity_filter]
            
            # Update UI
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            for r in reversed(self.rows):
                _id, ts, sev, src, kind, summary, details = r
                tag = sev if sev in ("CRITICAL", "HIGH", "WARN", "INFO") else "INFO"
                self.tree.insert("", "end", values=(_id, ts, sev, src, kind, summary), tags=(tag,))
            
            # Update status
            total = self.store.count()
            self.status_var.set(f"Ready | Total Events: {total} | Filtered: {len(self.rows)}")
        except Exception as e:
            logger.error(f"Refresh error: {e}")
    
    def on_select(self, _):
        """Handle tree selection."""
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        _id = int(vals[0])
        match = next((r for r in self.rows if r[0] == _id), None)
        if not match:
            return
        _id, ts, sev, src, kind, summary, details = match
        
        try:
            details_dict = json.loads(details)
            details_str = json.dumps(details_dict, indent=2)
        except:
            details_str = details
        
        self.details.delete("1.0", "end")
        info = f"ID: {_id}\nTimestamp: {ts}\nSeverity: {sev}\nSource: {src}\nKind: {kind}\n\nSummary:\n{summary}\n\nDetails:\n{details_str}"
        self.details.insert("end", info)
    
    def clear_all(self):
        """Clear all events from database."""
        if tk.messagebox.askyesno("Confirm", "Clear all events from database?"):
            self.store.clear()
            self.refresh()
            logger.info("All events cleared")
    
    def export_csv(self):
        """Export events to CSV."""
        try:
            from datetime import datetime
            filename = f"hids_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            self.store.export_csv(filename)
            tk.messagebox.showinfo("Success", f"Events exported to {filename}")
            logger.info(f"Exported events to {filename}")
        except Exception as e:
            tk.messagebox.showerror("Error", f"Export failed: {e}")
            logger.error(f"Export error: {e}")