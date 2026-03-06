"""
GonePhishing - Phishing Detection System
main.py - Entry point, launches the GUI window
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import joblib
import os
from feature_extractor import extract_features
from database import init_db, save_result, get_history, mark_reported, mark_ignored

# ── Constants ──────────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join("models", "phishing_model.pkl")

COLOUR_BG        = "#1A1A2E"   # Dark navy background
COLOUR_PANEL     = "#16213E"   # Slightly lighter panel
COLOUR_ACCENT    = "#0F3460"   # Accent blue
COLOUR_SAFE      = "#2ECC71"   # Green
COLOUR_WARN      = "#F39C12"   # Amber
COLOUR_DANGER    = "#E74C3C"   # Red
COLOUR_TEXT      = "#EAEAEA"   # Light text
COLOUR_SUBTEXT   = "#95A5A6"   # Dimmed text
COLOUR_BTN_BLUE  = "#2980B9"   # Blue button
COLOUR_BTN_GREY  = "#555555"   # Grey button

FONT_TITLE  = ("Arial", 22, "bold")
FONT_LARGE  = ("Arial", 14, "bold")
FONT_NORMAL = ("Arial", 11)
FONT_SMALL  = ("Arial", 9)
FONT_MONO   = ("Courier New", 10)


# ── Main Application Class ─────────────────────────────────────────────────────
class GonePhishingApp:

    def __init__(self, root):
        self.root = root
        self.root.title("GonePhishing — Phishing Detection System")
        self.root.geometry("900x700")
        self.root.configure(bg=COLOUR_BG)
        self.root.resizable(True, True)

        # Load ML model
        self.model = self._load_model()

        # Initialise database
        init_db()

        # Track current result
        self.current_result_id = None

        # Build UI
        self._build_header()
        self._build_notebook()
        self._build_status_bar()

    # ── Model Loading ──────────────────────────────────────────────────────────
    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                model = joblib.load(MODEL_PATH)
                print("[GonePhishing] Model loaded successfully.")
                return model
            except Exception as e:
                print(f"[GonePhishing] Failed to load model: {e}")
                return None
        else:
            print("[GonePhishing] No model found. Run model_trainer.py first.")
            return None

    # ── Header ─────────────────────────────────────────────────────────────────
    def _build_header(self):
        header = tk.Frame(self.root, bg=COLOUR_ACCENT, pady=12)
        header.pack(fill=tk.X)

        tk.Label(
            header,
            text="🎣  GonePhishing",
            font=FONT_TITLE,
            bg=COLOUR_ACCENT,
            fg=COLOUR_TEXT
        ).pack(side=tk.LEFT, padx=20)

        model_status = "✅ Model Loaded" if self.model else "⚠️  No Model — Run model_trainer.py"
        tk.Label(
            header,
            text=model_status,
            font=FONT_SMALL,
            bg=COLOUR_ACCENT,
            fg=COLOUR_SAFE if self.model else COLOUR_WARN
        ).pack(side=tk.RIGHT, padx=20)

    # ── Notebook Tabs ──────────────────────────────────────────────────────────
    def _build_notebook(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=COLOUR_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=COLOUR_ACCENT, foreground=COLOUR_TEXT,
                        padding=[16, 8], font=FONT_NORMAL)
        style.map("TNotebook.Tab", background=[("selected", COLOUR_BTN_BLUE)])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)

        # Tab 1: Analyse
        self.tab_analyse = tk.Frame(self.notebook, bg=COLOUR_BG)
        self.notebook.add(self.tab_analyse, text="  🔍  Analyse  ")
        self._build_analyse_tab(self.tab_analyse)

        # Tab 2: History
        self.tab_history = tk.Frame(self.notebook, bg=COLOUR_BG)
        self.notebook.add(self.tab_history, text="  📋  History  ")
        self._build_history_tab(self.tab_history)

        # Tab 3: About
        self.tab_about = tk.Frame(self.notebook, bg=COLOUR_BG)
        self.notebook.add(self.tab_about, text="  ℹ️  About  ")
        self._build_about_tab(self.tab_about)

    # ── Analyse Tab ────────────────────────────────────────────────────────────
    def _build_analyse_tab(self, parent):

        # Input type selector
        top_frame = tk.Frame(parent, bg=COLOUR_BG)
        top_frame.pack(fill=tk.X, padx=16, pady=(12, 4))

        tk.Label(top_frame, text="Input Type:", font=FONT_NORMAL,
                 bg=COLOUR_BG, fg=COLOUR_TEXT).pack(side=tk.LEFT)

        self.input_type = tk.StringVar(value="url")
        ttk.Radiobutton(top_frame, text="URL", variable=self.input_type,
                        value="url").pack(side=tk.LEFT, padx=12)
        ttk.Radiobutton(top_frame, text="Email Content", variable=self.input_type,
                        value="email").pack(side=tk.LEFT)

        # Input box
        tk.Label(parent, text="Paste a URL or email content below:",
                 font=FONT_NORMAL, bg=COLOUR_BG, fg=COLOUR_SUBTEXT).pack(
                     anchor=tk.W, padx=16, pady=(8, 2))

        self.input_text = scrolledtext.ScrolledText(
            parent, height=6, font=FONT_MONO,
            bg=COLOUR_PANEL, fg=COLOUR_TEXT,
            insertbackground=COLOUR_TEXT,
            relief=tk.FLAT, padx=10, pady=8
        )
        self.input_text.pack(fill=tk.X, padx=16, pady=(0, 8))

        # Analyse button
        self.btn_analyse = tk.Button(
            parent, text="  🔍  Analyse Now  ",
            font=FONT_LARGE, bg=COLOUR_BTN_BLUE, fg=WHITE,
            activebackground="#1A6A9A", activeforeground=WHITE,
            relief=tk.FLAT, pady=10, cursor="hand2",
            command=self._run_analysis
        )
        self.btn_analyse.pack(pady=8)

        # Results panel
        results_frame = tk.Frame(parent, bg=COLOUR_PANEL, pady=16)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)

        # Score gauge (Canvas arc)
        self.canvas = tk.Canvas(results_frame, width=200, height=130,
                                bg=COLOUR_PANEL, highlightthickness=0)
        self.canvas.pack(side=tk.LEFT, padx=24)
        self._draw_gauge(0, COLOUR_SUBTEXT)

        # Verdict and details
        right_panel = tk.Frame(results_frame, bg=COLOUR_PANEL)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8)

        self.lbl_verdict = tk.Label(right_panel, text="—", font=("Arial", 28, "bold"),
                                    bg=COLOUR_PANEL, fg=COLOUR_SUBTEXT)
        self.lbl_verdict.pack(anchor=tk.W, pady=(8, 4))

        self.lbl_score = tk.Label(right_panel, text="Submit a URL or email to get started.",
                                  font=FONT_NORMAL, bg=COLOUR_PANEL, fg=COLOUR_SUBTEXT)
        self.lbl_score.pack(anchor=tk.W)

        self.lbl_detail = tk.Label(right_panel, text="", font=FONT_SMALL,
                                   bg=COLOUR_PANEL, fg=COLOUR_SUBTEXT, wraplength=400,
                                   justify=tk.LEFT)
        self.lbl_detail.pack(anchor=tk.W, pady=4)

        # Action buttons
        action_frame = tk.Frame(right_panel, bg=COLOUR_PANEL)
        action_frame.pack(anchor=tk.W, pady=12)

        self.btn_ignore = tk.Button(
            action_frame, text="  ✅  Ignore  ",
            font=FONT_NORMAL, bg=COLOUR_BTN_GREY, fg=COLOUR_TEXT,
            relief=tk.FLAT, padx=10, pady=6, cursor="hand2",
            state=tk.DISABLED, command=self._ignore_result
        )
        self.btn_ignore.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_report = tk.Button(
            action_frame, text="  🚨  Report  ",
            font=FONT_NORMAL, bg=COLOUR_DANGER, fg=WHITE,
            activebackground="#C0392B", activeforeground=WHITE,
            relief=tk.FLAT, padx=10, pady=6, cursor="hand2",
            state=tk.DISABLED, command=self._report_result
        )
        self.btn_report.pack(side=tk.LEFT)

    # ── Gauge Drawing ──────────────────────────────────────────────────────────
    def _draw_gauge(self, score, colour):
        self.canvas.delete("all")

        # Background arc
        self.canvas.create_arc(20, 10, 180, 130, start=0, extent=180,
                               style=tk.ARC, outline="#333333", width=14)

        # Score arc (proportion of 180 degrees)
        extent = int((score / 100) * 180)
        if extent > 0:
            self.canvas.create_arc(20, 10, 180, 130, start=0, extent=extent,
                                   style=tk.ARC, outline=colour, width=14)

        # Score text
        self.canvas.create_text(100, 100, text=f"{int(score)}",
                                font=("Arial", 26, "bold"), fill=colour)
        self.canvas.create_text(100, 120, text="Risk Score",
                                font=("Arial", 9), fill=COLOUR_SUBTEXT)

    # ── Run Analysis ───────────────────────────────────────────────────────────
    def _run_analysis(self):
        raw_input = self.input_text.get("1.0", tk.END).strip()

        if not raw_input:
            messagebox.showwarning("No Input", "Please paste a URL or email content first.")
            return

        if not self.model:
            messagebox.showerror("No Model", "Model not loaded.\nRun model_trainer.py first, then restart the app.")
            return

        input_type = self.input_type.get()

        try:
            # Extract features and predict
            features = extract_features(raw_input, input_type)
            score = self.model.predict_proba([features])[0][1] * 100
            prediction = self.model.predict([features])[0]

            # Determine verdict
            if score < 30:
                verdict = "SAFE"
                colour = COLOUR_SAFE
                detail = "No significant phishing indicators detected."
            elif score < 70:
                verdict = "SUSPICIOUS"
                colour = COLOUR_WARN
                detail = "Some phishing indicators found. Proceed with caution."
            else:
                verdict = "PHISHING"
                colour = COLOUR_DANGER
                detail = "High probability of phishing. Do not click or interact."

            # Update UI
            self._draw_gauge(score, colour)
            self.lbl_verdict.config(text=verdict, fg=colour)
            self.lbl_score.config(text=f"Risk Score: {score:.1f} / 100", fg=colour)
            self.lbl_detail.config(text=detail, fg=COLOUR_SUBTEXT)

            # Enable action buttons
            self.btn_ignore.config(state=tk.NORMAL, bg=COLOUR_SAFE)
            self.btn_report.config(state=tk.NORMAL)

            # Save to database
            self.current_result_id = save_result(raw_input, input_type, score, verdict)

            self._update_status(f"Analysis complete — {verdict}  ({score:.1f}/100)")

        except Exception as e:
            messagebox.showerror("Analysis Error", f"Something went wrong:\n{e}")

    # ── Ignore ─────────────────────────────────────────────────────────────────
    def _ignore_result(self):
        if self.current_result_id:
            mark_ignored(self.current_result_id)
            self.btn_ignore.config(state=tk.DISABLED, text="✅  Ignored", bg=COLOUR_BTN_GREY)
            self.btn_report.config(state=tk.DISABLED)
            self._update_status("Marked as ignored.")

    # ── Report ─────────────────────────────────────────────────────────────────
    def _report_result(self):
        if not self.current_result_id:
            return

        # Open report dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Report Phishing")
        dialog.geometry("400x240")
        dialog.configure(bg=COLOUR_BG)
        dialog.grab_set()

        tk.Label(dialog, text="🚨  Report as Phishing",
                 font=FONT_LARGE, bg=COLOUR_BG, fg=COLOUR_DANGER).pack(pady=12)

        tk.Label(dialog, text="Select a reason:",
                 font=FONT_NORMAL, bg=COLOUR_BG, fg=COLOUR_TEXT).pack(anchor=tk.W, padx=20)

        reasons = [
            "Suspicious URL / domain",
            "Credential harvesting attempt",
            "Urgent / threatening language",
            "Fake login page",
            "Malicious attachment",
            "Other"
        ]
        reason_var = tk.StringVar(value=reasons[0])
        reason_box = ttk.Combobox(dialog, textvariable=reason_var,
                                  values=reasons, state="readonly", width=38)
        reason_box.pack(padx=20, pady=8)

        def submit_report():
            mark_reported(self.current_result_id, reason_var.get())
            self.btn_report.config(state=tk.DISABLED, text="🚨  Reported", bg=COLOUR_BTN_GREY)
            self.btn_ignore.config(state=tk.DISABLED)
            self._update_status(f"Reported: {reason_var.get()}")
            dialog.destroy()
            messagebox.showinfo("Reported", "Thank you. This has been logged in the database.")

        tk.Button(dialog, text="Submit Report", font=FONT_NORMAL,
                  bg=COLOUR_DANGER, fg=WHITE, relief=tk.FLAT,
                  padx=12, pady=6, command=submit_report).pack(pady=12)

    # ── History Tab ────────────────────────────────────────────────────────────
    def _build_history_tab(self, parent):
        tk.Label(parent, text="Analysis History", font=FONT_LARGE,
                 bg=COLOUR_BG, fg=COLOUR_TEXT).pack(anchor=tk.W, padx=16, pady=12)

        # Refresh button
        tk.Button(parent, text="🔄  Refresh", font=FONT_SMALL,
                  bg=COLOUR_BTN_BLUE, fg=WHITE, relief=tk.FLAT,
                  padx=8, pady=4, command=self._load_history).pack(anchor=tk.W, padx=16)

        # Table
        cols = ("Date/Time", "Type", "Input", "Score", "Verdict", "Status")
        style = ttk.Style()
        style.configure("Treeview", background=COLOUR_PANEL, foreground=COLOUR_TEXT,
                        fieldbackground=COLOUR_PANEL, rowheight=28, font=FONT_SMALL)
        style.configure("Treeview.Heading", background=COLOUR_ACCENT,
                        foreground=COLOUR_TEXT, font=("Arial", 10, "bold"))

        self.tree = ttk.Treeview(parent, columns=cols, show="headings", height=18)

        widths = [140, 60, 340, 60, 90, 80]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor=tk.W)

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(16, 0), pady=8)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=8, padx=(0, 8))

        self._load_history()

    def _load_history(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        rows = get_history(limit=50)
        for row in rows:
            # row: (id, input_text, input_type, score, verdict, timestamp, status)
            _, input_text, input_type, score, verdict, timestamp, status = row
            short_input = (input_text[:45] + "...") if len(input_text) > 45 else input_text
            self.tree.insert("", tk.END, values=(
                timestamp[:16], input_type.upper(), short_input,
                f"{score:.0f}", verdict, status.upper()
            ))

    # ── About Tab ──────────────────────────────────────────────────────────────
    def _build_about_tab(self, parent):
        frame = tk.Frame(parent, bg=COLOUR_BG)
        frame.pack(expand=True)

        tk.Label(frame, text="🎣", font=("Arial", 48), bg=COLOUR_BG).pack(pady=(40, 8))
        tk.Label(frame, text="GonePhishing", font=("Arial", 26, "bold"),
                 bg=COLOUR_BG, fg=COLOUR_TEXT).pack()
        tk.Label(frame, text="Phishing Detection System", font=FONT_NORMAL,
                 bg=COLOUR_BG, fg=COLOUR_SUBTEXT).pack(pady=4)

        tk.Label(frame, text="Cybersecurity Synoptic Project",
                 font=FONT_SMALL, bg=COLOUR_BG, fg=COLOUR_SUBTEXT).pack(pady=(16, 4))

        info = [
            ("Language",  "Python 3.10+"),
            ("GUI",       "Tkinter / ttk"),
            ("ML Model",  "scikit-learn — Random Forest"),
            ("Database",  "SQLite (local)"),
            ("Internet",  "Not required — fully offline"),
        ]
        for label, value in info:
            row = tk.Frame(frame, bg=COLOUR_BG)
            row.pack(pady=2)
            tk.Label(row, text=f"{label}:", font=("Arial", 10, "bold"),
                     bg=COLOUR_BG, fg=COLOUR_SUBTEXT, width=14, anchor=tk.E).pack(side=tk.LEFT)
            tk.Label(row, text=value, font=("Arial", 10),
                     bg=COLOUR_BG, fg=COLOUR_TEXT).pack(side=tk.LEFT, padx=8)

    # ── Status Bar ─────────────────────────────────────────────────────────────
    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Ready")
        bar = tk.Frame(self.root, bg=COLOUR_ACCENT, pady=4)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(bar, textvariable=self.status_var, font=FONT_SMALL,
                 bg=COLOUR_ACCENT, fg=COLOUR_TEXT).pack(side=tk.LEFT, padx=12)

    def _update_status(self, msg):
        self.status_var.set(msg)
        self.root.update_idletasks()


# ── Colour constant needed inside class ────────────────────────────────────────
WHITE = "#FFFFFF"


# ── Launch ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app = GonePhishingApp(root)
    root.mainloop()
