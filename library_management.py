import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import ttkbootstrap as tbs
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledFrame
import json, os, time, threading, random, string, math, base64, hashlib, secrets
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyperclip

# ─── Constants ────────────────────────────────────────────────────────────────
APP_TITLE   = "FORTRESS — Password Vault"
VAULT_FILE  = os.path.join(os.path.expanduser("~"), ".fortress_vault.enc")
LOCK_AFTER  = 300          # seconds of inactivity → auto-lock
CLIP_CLEAR  = 30           # seconds before clipboard wipe
PBKDF2_ITER = 480_000      # OWASP 2024 recommendation

CATEGORIES = ["🌐 Web", "📧 Email", "💳 Finance", "🏢 Work",
              "🎮 Gaming", "🛒 Shopping", "🔒 SSH/Keys", "📱 Mobile", "⚙️ Other"]

PALETTES = {
    "dark":  {"bg": "#0d1117", "panel": "#161b22", "card": "#21262d",
              "border": "#30363d", "accent": "#58a6ff", "accent2": "#3fb950",
              "warn": "#d29922", "danger": "#f85149", "text": "#e6edf3",
              "subtext": "#8b949e", "input": "#0d1117"},
    "light": {"bg": "#f0f2f5", "panel": "#ffffff", "card": "#f6f8fa",
              "border": "#d0d7de", "accent": "#0969da", "accent2": "#1a7f37",
              "warn": "#9a6700", "danger": "#d1242f", "text": "#1f2328",
              "subtext": "#656d76", "input": "#ffffff"},
}

# ─── Crypto Layer ─────────────────────────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=PBKDF2_ITER)
    return kdf.derive(password.encode())

def encrypt_vault(data: dict, key: bytes) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)
    return nonce + ct

def decrypt_vault(raw: bytes, key: bytes) -> dict:
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return json.loads(aesgcm.decrypt(nonce, ct, None))

# ─── Password Utilities ───────────────────────────────────────────────────────
def generate_password(length=16, upper=True, lower=True, digits=True,
                      symbols=True, ambiguous=False, custom_chars="") -> str:
    pool = custom_chars
    if not pool:
        if lower:   pool += string.ascii_lowercase
        if upper:   pool += string.ascii_uppercase
        if digits:  pool += string.digits
        if symbols: pool += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if not ambiguous:
        pool = pool.translate(str.maketrans('', '', 'Il1O0'))
    if not pool:
        pool = string.ascii_letters + string.digits
    return ''.join(secrets.choice(pool) for _ in range(length))

def password_entropy(pwd: str) -> float:
    pool = 0
    if any(c in string.ascii_lowercase for c in pwd): pool += 26
    if any(c in string.ascii_uppercase for c in pwd): pool += 26
    if any(c in string.digits for c in pwd):          pool += 10
    if any(c in string.punctuation for c in pwd):     pool += 32
    pool = max(pool, len(set(pwd)))
    return len(pwd) * math.log2(pool) if pool > 0 else 0

def strength_label(entropy: float):
    if entropy < 28:  return "Very Weak",  "#f85149", 0.15
    if entropy < 36:  return "Weak",        "#ffa657", 0.35
    if entropy < 60:  return "Fair",        "#d29922", 0.55
    if entropy < 80:  return "Strong",      "#3fb950", 0.78
    return               "Very Strong", "#58a6ff", 1.0

def password_age_days(created_iso: str) -> int:
    try:
        dt = datetime.fromisoformat(created_iso)
        return (datetime.now() - dt).days
    except Exception:
        return 0

# ─── Tooltip Helper ───────────────────────────────────────────────────────────
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _=None):
        x, y = self.widget.winfo_rootx() + 20, self.widget.winfo_rooty() + 28
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(self.tip, text=self.text, background="#21262d",
                       foreground="#e6edf3", relief="solid", borderwidth=1,
                       font=("Consolas", 9), padx=8, pady=4)
        lbl.pack()

    def hide(self, _=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None

# ─── Main Application ─────────────────────────────────────────────────────────
class FortressApp:
    def __init__(self):
        self.root = tbs.Window(themename="darkly")
        self.root.title(APP_TITLE)
        self.root.geometry("1280x820")
        self.root.minsize(960, 640)

        self.theme_name = "dark"
        self.C = PALETTES["dark"]

        self.vault_key   = None
        self.vault_salt  = None
        self.vault_data  = {"entries": [], "settings": {}}
        self.last_active = time.time()
        self.locked      = True
        self.clip_timer  = None
        self.lock_timer  = None
        self.search_var  = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_vault())
        self.selected_id = None
        self.sort_col    = "site"
        self.sort_rev    = False

        self._build_ui()
        self._show_login()
        self._start_lock_watch()
        self.root.mainloop()

    # ── Activity tracker ──────────────────────────────────────────────────────
    def _touch(self, _=None):
        self.last_active = time.time()

    def _start_lock_watch(self):
        def _watch():
            while True:
                time.sleep(10)
                if not self.locked and (time.time() - self.last_active > LOCK_AFTER):
                    self.root.after(0, self._auto_lock)
        t = threading.Thread(target=_watch, daemon=True)
        t.start()
        self.root.bind_all("<Any-KeyPress>", self._touch)
        self.root.bind_all("<Any-Button>",   self._touch)

    def _auto_lock(self):
        messagebox.showinfo("Auto-Locked", "Fortress locked due to inactivity.")
        self._do_lock()

    # ── Build UI skeleton ─────────────────────────────────────────────────────
    def _build_ui(self):
        C = self.C
        self.root.configure(bg=C["bg"])

        # ── Top bar ──────────────────────────────────────────────────────────
        self.topbar = tk.Frame(self.root, bg=C["panel"], height=56)
        self.topbar.pack(fill=X, side=TOP)
        self.topbar.pack_propagate(False)

        logo_lbl = tk.Label(self.topbar, text="🔐 FORTRESS",
                            font=("Courier New", 17, "bold"),
                            bg=C["panel"], fg=C["accent"])
        logo_lbl.pack(side=LEFT, padx=20)

        sub = tk.Label(self.topbar, text="Password Vault  •  Professional Edition",
                       font=("Consolas", 9), bg=C["panel"], fg=C["subtext"])
        sub.pack(side=LEFT, padx=0, pady=18)

        # right buttons
        self.btn_lock   = self._topbtn("🔒 Lock",      self._do_lock)
        self.btn_theme  = self._topbtn("🌙 Theme",     self._toggle_theme)
        self.btn_export = self._topbtn("📤 Export",    self._export_vault)
        self.btn_import = self._topbtn("📥 Import",    self._import_vault)
        self.btn_gen    = self._topbtn("⚡ Generator",  self._open_generator)

        # separator
        sep = tk.Frame(self.root, bg=C["border"], height=1)
        sep.pack(fill=X)

        # ── Main content ──────────────────────────────────────────────────────
        self.content = tk.Frame(self.root, bg=C["bg"])
        self.content.pack(fill=BOTH, expand=True)

        self._build_sidebar()
        self._build_vault_panel()
        self._build_detail_panel()

    def _topbtn(self, text, cmd):
        C = self.C
        btn = tk.Button(self.topbar, text=text, command=cmd,
                        bg=C["card"], fg=C["text"], relief="flat",
                        font=("Consolas", 9, "bold"), cursor="hand2",
                        padx=12, pady=6, bd=0,
                        activebackground=C["accent"], activeforeground="#fff")
        btn.pack(side=RIGHT, padx=6, pady=10)
        return btn

    # ── Sidebar ───────────────────────────────────────────────────────────────
    def _build_sidebar(self):
        C = self.C
        self.sidebar = tk.Frame(self.content, bg=C["panel"], width=200)
        self.sidebar.pack(side=LEFT, fill=Y)
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="CATEGORIES", font=("Consolas", 8, "bold"),
                 bg=C["panel"], fg=C["subtext"]).pack(anchor=W, padx=14, pady=(16,4))

        self.cat_var = tk.StringVar(value="All")
        cats = ["All"] + CATEGORIES
        self.cat_buttons = []
        for cat in cats:
            btn = tk.Button(self.sidebar, text=cat, anchor=W,
                            font=("Consolas", 10), relief="flat", bd=0,
                            bg=C["panel"], fg=C["text"], cursor="hand2",
                            padx=14, pady=5,
                            command=lambda c=cat: self._filter_cat(c))
            btn.pack(fill=X)
            self.cat_buttons.append(btn)

        # stats
        sep = tk.Frame(self.sidebar, bg=C["border"], height=1)
        sep.pack(fill=X, pady=12)
        self.stat_lbl = tk.Label(self.sidebar, text="", font=("Consolas", 8),
                                 bg=C["panel"], fg=C["subtext"], justify=LEFT)
        self.stat_lbl.pack(anchor=W, padx=14)

    def _filter_cat(self, cat):
        self.cat_var.set(cat)
        self.refresh_vault()
        C = self.C
        for btn in self.cat_buttons:
            chosen = btn.cget("text") == cat
            btn.config(bg=C["accent"] if chosen else C["panel"],
                       fg="#fff" if chosen else C["text"])

    # ── Vault panel ───────────────────────────────────────────────────────────
    def _build_vault_panel(self):
        C = self.C
        mid = tk.Frame(self.content, bg=C["bg"])
        mid.pack(side=LEFT, fill=BOTH, expand=True)

        # search bar
        sbar = tk.Frame(mid, bg=C["bg"])
        sbar.pack(fill=X, padx=14, pady=10)

        tk.Label(sbar, text="🔍", bg=C["bg"], fg=C["subtext"],
                 font=("Segoe UI Emoji", 12)).pack(side=LEFT, padx=(0,4))
        self.search_entry = tk.Entry(sbar, textvariable=self.search_var,
                                     bg=C["card"], fg=C["text"], relief="flat",
                                     font=("Consolas", 11), insertbackground=C["accent"],
                                     bd=0)
        self.search_entry.pack(side=LEFT, fill=X, expand=True, ipady=7, ipadx=8)
        self.search_entry.insert(0, "Search vault…")
        self.search_entry.bind("<FocusIn>",  lambda e: self._clr_ph(e))
        self.search_entry.bind("<FocusOut>", lambda e: self._add_ph(e))

        add_btn = tk.Button(sbar, text="+ Add Entry", command=self._add_entry,
                            bg=C["accent"], fg="#fff", relief="flat",
                            font=("Consolas", 9, "bold"), cursor="hand2",
                            padx=14, pady=6)
        add_btn.pack(side=RIGHT, padx=(8,0))

        # column headers
        hdr = tk.Frame(mid, bg=C["panel"])
        hdr.pack(fill=X, padx=14)
        for col, lbl, w in [("site","SITE/SERVICE",200), ("username","USERNAME",160),
                              ("category","CATEGORY",110), ("strength","STRENGTH",90),
                              ("updated","UPDATED",100)]:
            b = tk.Button(hdr, text=lbl, font=("Consolas", 8, "bold"),
                          bg=C["panel"], fg=C["subtext"], relief="flat",
                          anchor=W, width=w//8, cursor="hand2",
                          command=lambda c=col: self._sort_by(c))
            b.pack(side=LEFT, padx=4, pady=6)

        # scrolled list
        self.vault_scroll = ScrolledFrame(mid, autohide=True)
        self.vault_scroll.pack(fill=BOTH, expand=True, padx=14, pady=(0,10))
        self.vault_list_frame = self.vault_scroll

    def _clr_ph(self, e):
        if self.search_entry.get() == "Search vault…":
            self.search_entry.delete(0, END)
            self.search_entry.config(fg=self.C["text"])

    def _add_ph(self, e):
        if not self.search_entry.get():
            self.search_entry.insert(0, "Search vault…")
            self.search_entry.config(fg=self.C["subtext"])

    def _sort_by(self, col):
        if self.sort_col == col:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col = col
            self.sort_rev = False
        self.refresh_vault()

    # ── Detail panel ──────────────────────────────────────────────────────────
    def _build_detail_panel(self):
        C = self.C
        self.detail = tk.Frame(self.content, bg=C["panel"], width=340)
        self.detail.pack(side=RIGHT, fill=Y)
        self.detail.pack_propagate(False)

        sep = tk.Frame(self.detail, bg=C["border"], width=1)
        sep.place(x=0, y=0, relheight=1)

        self.detail_inner = tk.Frame(self.detail, bg=C["panel"])
        self.detail_inner.pack(fill=BOTH, expand=True, padx=20, pady=20)
        self._show_empty_detail()

    def _show_empty_detail(self):
        for w in self.detail_inner.winfo_children():
            w.destroy()
        C = self.C
        tk.Label(self.detail_inner, text="🔐", font=("Segoe UI Emoji", 48),
                 bg=C["panel"], fg=C["border"]).pack(pady=(80,10))
        tk.Label(self.detail_inner, text="Select an entry\nto view details",
                 font=("Consolas", 12), bg=C["panel"], fg=C["subtext"],
                 justify=CENTER).pack()

    # ── Login / Master Password ───────────────────────────────────────────────
    def _show_login(self):
        self.locked = True
        self.login_win = tk.Toplevel(self.root)
        self.login_win.title("FORTRESS — Unlock")
        self.login_win.geometry("420x520")
        self.login_win.resizable(False, False)
        self.login_win.grab_set()
        self.login_win.protocol("WM_DELETE_WINDOW", self.root.destroy)
        C = self.C
        self.login_win.configure(bg=C["bg"])

        is_new = not os.path.exists(VAULT_FILE)

        tk.Label(self.login_win, text="🔐", font=("Segoe UI Emoji", 56),
                 bg=C["bg"]).pack(pady=(40,0))
        tk.Label(self.login_win, text="FORTRESS",
                 font=("Courier New", 24, "bold"), bg=C["bg"], fg=C["accent"]).pack()
        tk.Label(self.login_win, text="Password Vault",
                 font=("Consolas", 11), bg=C["bg"], fg=C["subtext"]).pack(pady=(0,30))

        if is_new:
            tk.Label(self.login_win, text="Create Master Password",
                     font=("Consolas", 10, "bold"), bg=C["bg"], fg=C["text"]).pack()
        else:
            tk.Label(self.login_win, text="Enter Master Password",
                     font=("Consolas", 10, "bold"), bg=C["bg"], fg=C["text"]).pack()

        self.mp_var  = tk.StringVar()
        self.mp2_var = tk.StringVar()

        mp_frame = tk.Frame(self.login_win, bg=C["bg"])
        mp_frame.pack(pady=8, padx=40, fill=X)
        self.mp_entry = tk.Entry(mp_frame, textvariable=self.mp_var, show="●",
                                 bg=C["card"], fg=C["text"], relief="flat",
                                 font=("Consolas", 13), insertbackground=C["accent"],
                                 bd=0)
        self.mp_entry.pack(side=LEFT, fill=X, expand=True, ipady=10, ipadx=10)
        show_btn = tk.Button(mp_frame, text="👁", bg=C["card"], fg=C["subtext"],
                             relief="flat", bd=0, cursor="hand2",
                             command=lambda: self._toggle_show(self.mp_entry))
        show_btn.pack(side=RIGHT)

        if is_new:
            tk.Label(self.login_win, text="Confirm Password",
                     font=("Consolas", 9), bg=C["bg"], fg=C["subtext"]).pack(pady=(6,0))
            mp2_frame = tk.Frame(self.login_win, bg=C["bg"])
            mp2_frame.pack(pady=4, padx=40, fill=X)
            self.mp2_entry = tk.Entry(mp2_frame, textvariable=self.mp2_var, show="●",
                                      bg=C["card"], fg=C["text"], relief="flat",
                                      font=("Consolas", 13), insertbackground=C["accent"],
                                      bd=0)
            self.mp2_entry.pack(side=LEFT, fill=X, expand=True, ipady=10, ipadx=10)

        # strength bar for master pwd
        self.mp_strength_bar = tk.Canvas(self.login_win, height=6, bg=C["card"],
                                          highlightthickness=0)
        self.mp_strength_bar.pack(fill=X, padx=40, pady=4)
        self.mp_var.trace_add("write", self._update_mp_strength)

        self.mp_lbl = tk.Label(self.login_win, text="", font=("Consolas", 9),
                                bg=C["bg"], fg=C["subtext"])
        self.mp_lbl.pack()

        action = "Create Vault" if is_new else "Unlock Vault"
        cmd    = self._create_vault if is_new else self._unlock_vault
        unlock_btn = tk.Button(self.login_win, text=action, command=cmd,
                               bg=C["accent"], fg="#fff", relief="flat",
                               font=("Consolas", 12, "bold"), cursor="hand2",
                               padx=20, pady=10)
        unlock_btn.pack(pady=20)
        self.mp_entry.bind("<Return>", lambda e: cmd())
        self.mp_entry.focus_set()

    def _update_mp_strength(self, *_):
        pwd = self.mp_var.get()
        if not pwd:
            self.mp_strength_bar.delete("all")
            self.mp_lbl.config(text="")
            return
        ent = password_entropy(pwd)
        lbl, color, ratio = strength_label(ent)
        w = self.mp_strength_bar.winfo_width() or 300
        self.mp_strength_bar.delete("all")
        self.mp_strength_bar.create_rectangle(0, 0, w, 6, fill=self.C["card"], outline="")
        self.mp_strength_bar.create_rectangle(0, 0, int(w*ratio), 6, fill=color, outline="")
        self.mp_lbl.config(text=f"{lbl}  •  {ent:.0f} bits", fg=color)

    def _toggle_show(self, entry):
        entry.config(show="" if entry.cget("show") == "●" else "●")

    def _create_vault(self):
        pwd  = self.mp_var.get()
        pwd2 = self.mp2_var.get()
        if len(pwd) < 8:
            messagebox.showerror("Error", "Master password must be at least 8 characters.")
            return
        if pwd != pwd2:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        self.vault_salt = os.urandom(32)
        self.vault_key  = derive_key(pwd, self.vault_salt)
        self.vault_data = {"entries": [], "settings": {"created": datetime.now().isoformat()}}
        self._save_vault()
        self.login_win.destroy()
        self.locked = False
        self.refresh_vault()
        self._show_welcome()

    def _unlock_vault(self):
        pwd = self.mp_var.get()
        try:
            with open(VAULT_FILE, "rb") as f:
                raw = f.read()
            salt = raw[:32]
            key  = derive_key(pwd, salt)
            self.vault_data = decrypt_vault(raw[32:], key)
            self.vault_key  = key
            self.vault_salt = salt
            self.login_win.destroy()
            self.locked = False
            self.refresh_vault()
        except Exception:
            messagebox.showerror("Error", "Wrong master password or corrupted vault.")

    def _save_vault(self):
        if self.vault_key is None: return
        enc = encrypt_vault(self.vault_data, self.vault_key)
        with open(VAULT_FILE, "wb") as f:
            f.write(self.vault_salt + enc)

    def _do_lock(self):
        self.vault_key  = None
        self.vault_salt = None
        self.locked = True
        self._clear_vault_list()
        self._show_empty_detail()
        self._show_login()

    # ── Vault display ─────────────────────────────────────────────────────────
    def refresh_vault(self):
        if self.locked: return
        self._clear_vault_list()
        q   = self.search_var.get().lower().strip()
        cat = self.cat_var.get()
        entries = self.vault_data.get("entries", [])

        if q and q != "search vault…":
            entries = [e for e in entries if
                       q in e.get("site","").lower() or
                       q in e.get("username","").lower() or
                       q in e.get("notes","").lower() or
                       q in e.get("url","").lower()]
        if cat != "All":
            entries = [e for e in entries if e.get("category","") == cat]

        entries = sorted(entries, key=lambda e: e.get(self.sort_col,"").lower(),
                         reverse=self.sort_rev)

        weak = sum(1 for e in self.vault_data["entries"]
                   if password_entropy(e.get("password","")) < 60)
        old  = sum(1 for e in self.vault_data["entries"]
                   if password_age_days(e.get("updated","1970-01-01")) > 90)
        self.stat_lbl.config(
            text=f"Total:  {len(self.vault_data['entries'])}\n"
                 f"Shown:  {len(entries)}\n"
                 f"Weak:   {weak}  ⚠\n"
                 f"Stale:  {old}  🕒")

        if not entries:
            C = self.C
            tk.Label(self.vault_list_frame, text="No entries found.",
                     font=("Consolas", 11), bg=C["bg"], fg=C["subtext"]).pack(pady=40)
            return

        for e in entries:
            self._vault_row(e)

    def _clear_vault_list(self):
        for w in self.vault_list_frame.winfo_children():
            w.destroy()

    def _vault_row(self, entry):
        C = self.C
        eid = entry.get("id","")
        is_selected = eid == self.selected_id

        row = tk.Frame(self.vault_list_frame,
                       bg=C["accent"] if is_selected else C["card"],
                       cursor="hand2")
        row.pack(fill=X, pady=2)

        # site icon + name
        site = entry.get("site","Unknown")
        icon = entry.get("icon","🌐")
        tk.Label(row, text=icon, font=("Segoe UI Emoji", 14),
                 bg=row.cget("bg"), fg=C["text"]).pack(side=LEFT, padx=(10,4), pady=8)
        info = tk.Frame(row, bg=row.cget("bg"))
        info.pack(side=LEFT, fill=X, expand=True)
        tk.Label(info, text=site, font=("Consolas", 10, "bold"),
                 bg=row.cget("bg"), fg="#fff" if is_selected else C["text"],
                 anchor=W).pack(anchor=W)
        tk.Label(info, text=entry.get("username",""), font=("Consolas", 9),
                 bg=row.cget("bg"), fg="#ddd" if is_selected else C["subtext"],
                 anchor=W).pack(anchor=W)

        # strength pill
        ent_val = password_entropy(entry.get("password",""))
        slbl, scolor, _ = strength_label(ent_val)
        pill = tk.Label(row, text=slbl, font=("Consolas", 8, "bold"),
                        bg=scolor, fg="#fff", padx=6, pady=2)
        pill.pack(side=RIGHT, padx=6)

        # category
        tk.Label(row, text=entry.get("category",""), font=("Consolas", 8),
                 bg=row.cget("bg"), fg="#ddd" if is_selected else C["subtext"],
                 padx=6).pack(side=RIGHT)

        # click
        for w in [row, info] + list(info.winfo_children()) + [pill]:
            w.bind("<Button-1>", lambda e, eid=eid: self._select_entry(eid))

    def _select_entry(self, eid):
        self.selected_id = eid
        entry = next((e for e in self.vault_data["entries"] if e.get("id") == eid), None)
        if entry:
            self.refresh_vault()
            self._show_detail(entry)

    # ── Detail view ───────────────────────────────────────────────────────────
    def _show_detail(self, entry):
        for w in self.detail_inner.winfo_children():
            w.destroy()
        C = self.C

        # header
        hdr = tk.Frame(self.detail_inner, bg=C["panel"])
        hdr.pack(fill=X, pady=(0,12))
        tk.Label(hdr, text=entry.get("icon","🌐"), font=("Segoe UI Emoji", 32),
                 bg=C["panel"]).pack(side=LEFT, padx=(0,10))
        titl = tk.Frame(hdr, bg=C["panel"])
        titl.pack(side=LEFT, fill=X, expand=True)
        tk.Label(titl, text=entry.get("site",""), font=("Consolas", 14, "bold"),
                 bg=C["panel"], fg=C["text"], anchor=W).pack(anchor=W)
        tk.Label(titl, text=entry.get("category",""), font=("Consolas", 9),
                 bg=C["panel"], fg=C["subtext"], anchor=W).pack(anchor=W)

        # fields
        self._detail_field("Username",   entry.get("username",""),  copyable=True)
        self._detail_field("URL",        entry.get("url",""),       copyable=True)
        self._detail_pwd_field(entry)
        self._detail_field("Notes",      entry.get("notes",""),     multiline=True)
        self._detail_field("Created",    entry.get("created","")[:10])
        self._detail_field("Updated",    entry.get("updated","")[:10])

        age = password_age_days(entry.get("updated","1970-01-01"))
        if age > 90:
            tk.Label(self.detail_inner,
                     text=f"⚠️  Password is {age} days old — consider updating",
                     font=("Consolas", 8), bg=C["panel"], fg=C["warn"],
                     wraplength=280, justify=LEFT).pack(anchor=W, pady=4)

        # actions
        abtn = tk.Frame(self.detail_inner, bg=C["panel"])
        abtn.pack(fill=X, pady=12)
        self._action_btn(abtn, "✏️ Edit",   lambda: self._edit_entry(entry))
        self._action_btn(abtn, "🗑 Delete", lambda: self._delete_entry(entry))
        self._action_btn(abtn, "📋 History",lambda: self._show_history(entry))

    def _detail_field(self, label, value, copyable=False, multiline=False):
        if not value: return
        C = self.C
        frame = tk.Frame(self.detail_inner, bg=C["card"])
        frame.pack(fill=X, pady=3)
        tk.Label(frame, text=label.upper(), font=("Consolas", 7, "bold"),
                 bg=C["card"], fg=C["subtext"], padx=8, pady=4, anchor=W).pack(anchor=W)
        row = tk.Frame(frame, bg=C["card"])
        row.pack(fill=X)
        lbl = tk.Label(row, text=value, font=("Consolas", 9),
                       bg=C["card"], fg=C["text"], padx=8, pady=4,
                       wraplength=240, justify=LEFT, anchor=W)
        lbl.pack(side=LEFT, fill=X, expand=True)
        if copyable:
            tk.Button(row, text="📋", bg=C["card"], fg=C["subtext"], relief="flat",
                      bd=0, cursor="hand2", font=("Segoe UI Emoji", 10),
                      command=lambda v=value: self._copy(v)).pack(side=RIGHT, padx=4)

    def _detail_pwd_field(self, entry):
        C = self.C
        pwd = entry.get("password","")
        ent_val = password_entropy(pwd)
        slbl, scolor, ratio = strength_label(ent_val)

        frame = tk.Frame(self.detail_inner, bg=C["card"])
        frame.pack(fill=X, pady=3)
        tk.Label(frame, text="PASSWORD", font=("Consolas", 7, "bold"),
                 bg=C["card"], fg=C["subtext"], padx=8, pady=4).pack(anchor=W)

        row = tk.Frame(frame, bg=C["card"])
        row.pack(fill=X)
        self.pwd_shown = False
        self.pwd_var_detail = tk.StringVar(value="●" * len(pwd))
        pwd_lbl = tk.Label(row, textvariable=self.pwd_var_detail,
                           font=("Courier New", 10), bg=C["card"], fg=C["text"],
                           padx=8, pady=4, anchor=W)
        pwd_lbl.pack(side=LEFT, fill=X, expand=True)

        def toggle_show():
            self.pwd_shown = not self.pwd_shown
            self.pwd_var_detail.set(pwd if self.pwd_shown else "●"*len(pwd))
        tk.Button(row, text="👁", bg=C["card"], fg=C["subtext"], relief="flat",
                  bd=0, cursor="hand2", command=toggle_show).pack(side=RIGHT)
        tk.Button(row, text="📋", bg=C["card"], fg=C["subtext"], relief="flat",
                  bd=0, cursor="hand2",
                  command=lambda: self._copy(pwd)).pack(side=RIGHT, padx=4)

        # strength bar
        bar = tk.Canvas(frame, height=5, bg=C["border"], highlightthickness=0)
        bar.pack(fill=X, padx=8, pady=(0,4))
        bar.update_idletasks()
        w = bar.winfo_width() or 280
        bar.create_rectangle(0,0,int(w*ratio),5, fill=scolor, outline="")
        tk.Label(frame, text=f"{slbl}  •  {ent_val:.0f} bits entropy",
                 font=("Consolas", 8), bg=C["card"], fg=scolor,
                 padx=8).pack(anchor=W)

    def _action_btn(self, parent, text, cmd):
        C = self.C
        tk.Button(parent, text=text, command=cmd, bg=C["card"], fg=C["text"],
                  relief="flat", font=("Consolas", 9), cursor="hand2",
                  padx=10, pady=5).pack(side=LEFT, padx=3)

    # ── Copy with auto-clear ──────────────────────────────────────────────────
    def _copy(self, text):
        pyperclip.copy(text)
        if self.clip_timer:
            self.clip_timer.cancel()
        def clear():
            try:
                if pyperclip.paste() == text:
                    pyperclip.copy("")
            except Exception:
                pass
        self.clip_timer = threading.Timer(CLIP_CLEAR, clear)
        self.clip_timer.start()
        self._toast(f"Copied! Clipboard clears in {CLIP_CLEAR}s")

    def _toast(self, msg):
        C = self.C
        t = tk.Toplevel(self.root)
        t.overrideredirect(True)
        t.attributes("-alpha", 0.92)
        x = self.root.winfo_x() + self.root.winfo_width()//2 - 160
        y = self.root.winfo_y() + self.root.winfo_height() - 80
        t.geometry(f"320x44+{x}+{y}")
        t.configure(bg=C["accent2"])
        tk.Label(t, text=msg, bg=C["accent2"], fg="#fff",
                 font=("Consolas", 10)).pack(expand=True)
        t.after(2800, t.destroy)

    # ── Add / Edit Entry ──────────────────────────────────────────────────────
    def _add_entry(self):
        self._entry_form(None)

    def _edit_entry(self, entry):
        self._entry_form(entry)

    def _entry_form(self, entry=None):
        is_new = entry is None
        C = self.C
        win = tk.Toplevel(self.root)
        win.title("Add Entry" if is_new else "Edit Entry")
        win.geometry("560x720")
        win.configure(bg=C["bg"])
        win.grab_set()

        sf = ScrolledFrame(win, autohide=True)
        sf.pack(fill=BOTH, expand=True, padx=0, pady=0)
        inner = sf

        def lbl(t):
            tk.Label(inner, text=t, font=("Consolas", 9, "bold"),
                     bg=C["bg"], fg=C["subtext"]).pack(anchor=W, padx=20, pady=(10,2))

        def field(var, show=""):
            e = tk.Entry(inner, textvariable=var, show=show,
                         bg=C["card"], fg=C["text"], relief="flat",
                         font=("Consolas", 11), insertbackground=C["accent"],
                         bd=0)
            e.pack(fill=X, padx=20, ipady=8, ipadx=8)
            return e

        tk.Label(inner, text="🔐  " + ("New Entry" if is_new else "Edit Entry"),
                 font=("Courier New", 16, "bold"),
                 bg=C["bg"], fg=C["accent"]).pack(pady=(20,10), padx=20, anchor=W)

        vars_ = {k: tk.StringVar(value=entry.get(k,"") if entry else "")
                 for k in ["site","username","url","password","notes","category","icon"]}

        lbl("SITE / SERVICE"); field(vars_["site"])
        lbl("USERNAME / EMAIL"); field(vars_["username"])
        lbl("URL"); field(vars_["url"])

        lbl("CATEGORY")
        cat_menu = ttk.Combobox(inner, textvariable=vars_["category"],
                                values=CATEGORIES, font=("Consolas", 10),
                                state="readonly")
        cat_menu.pack(fill=X, padx=20, ipady=4)

        lbl("ICON (emoji)")
        icon_row = tk.Frame(inner, bg=C["bg"])
        icon_row.pack(fill=X, padx=20)
        icon_entry = tk.Entry(icon_row, textvariable=vars_["icon"],
                              bg=C["card"], fg=C["text"], relief="flat",
                              font=("Consolas", 14), bd=0, width=4)
        icon_entry.pack(side=LEFT, ipady=6, ipadx=6)
        for ico in ["🌐","📧","💳","🏢","🎮","🛒","🔒","📱","⚙️","🔑","💡","🎵"]:
            tk.Button(icon_row, text=ico, bg=C["card"], fg=C["text"],
                      relief="flat", bd=0, cursor="hand2",
                      font=("Segoe UI Emoji", 13),
                      command=lambda i=ico: vars_["icon"].set(i)).pack(side=LEFT, padx=2)

        lbl("PASSWORD")
        pwd_row = tk.Frame(inner, bg=C["bg"])
        pwd_row.pack(fill=X, padx=20)
        pwd_entry = tk.Entry(pwd_row, textvariable=vars_["password"], show="●",
                             bg=C["card"], fg=C["text"], relief="flat",
                             font=("Courier New", 12), insertbackground=C["accent"],
                             bd=0)
        pwd_entry.pack(side=LEFT, fill=X, expand=True, ipady=8, ipadx=8)
        tk.Button(pwd_row, text="👁", bg=C["card"], fg=C["subtext"], relief="flat",
                  bd=0, cursor="hand2",
                  command=lambda: pwd_entry.config(
                      show="" if pwd_entry.cget("show")=="●" else "●"
                  )).pack(side=LEFT)
        tk.Button(pwd_row, text="⚡", bg=C["accent"], fg="#fff", relief="flat",
                  bd=0, cursor="hand2", font=("Consolas",9,"bold"), padx=8,
                  command=lambda: vars_["password"].set(
                      generate_password(16,True,True,True,True)
                  )).pack(side=LEFT, padx=4)

        # live strength bar
        str_canvas = tk.Canvas(inner, height=5, bg=C["border"], highlightthickness=0)
        str_canvas.pack(fill=X, padx=20, pady=4)
        str_lbl = tk.Label(inner, text="", font=("Consolas", 8),
                           bg=C["bg"], fg=C["subtext"])
        str_lbl.pack(anchor=W, padx=20)

        def _update_str(*_):
            pwd = vars_["password"].get()
            ent_val = password_entropy(pwd)
            sl, sc, sr = strength_label(ent_val)
            str_canvas.delete("all")
            w = str_canvas.winfo_width() or 480
            str_canvas.create_rectangle(0,0,w,5, fill=C["border"], outline="")
            str_canvas.create_rectangle(0,0,int(w*sr),5, fill=sc, outline="")
            str_lbl.config(text=f"{sl}  •  {ent_val:.0f} bits", fg=sc)

        vars_["password"].trace_add("write", _update_str)

        lbl("NOTES")
        notes_box = tk.Text(inner, height=4, bg=C["card"], fg=C["text"],
                            relief="flat", font=("Consolas", 10),
                            insertbackground=C["accent"], padx=8, pady=6)
        notes_box.pack(fill=X, padx=20)
        if entry:
            notes_box.insert("1.0", entry.get("notes",""))

        def save():
            site = vars_["site"].get().strip()
            pwd  = vars_["password"].get()
            if not site:
                messagebox.showerror("Error", "Site/Service is required.", parent=win)
                return
            if not pwd:
                messagebox.showerror("Error", "Password is required.", parent=win)
                return
            now = datetime.now().isoformat()
            if is_new:
                new_e = {
                    "id":       secrets.token_hex(8),
                    "site":     site,
                    "username": vars_["username"].get(),
                    "url":      vars_["url"].get(),
                    "password": pwd,
                    "notes":    notes_box.get("1.0","end-1c"),
                    "category": vars_["category"].get(),
                    "icon":     vars_["icon"].get() or "🌐",
                    "created":  now,
                    "updated":  now,
                    "history":  [],
                    "strength": password_entropy(pwd),
                }
                self.vault_data["entries"].append(new_e)
            else:
                for e in self.vault_data["entries"]:
                    if e["id"] == entry["id"]:
                        if e.get("password") != pwd:
                            e.setdefault("history",[]).append(
                                {"password": e["password"], "date": e.get("updated")})
                        e["site"]     = site
                        e["username"] = vars_["username"].get()
                        e["url"]      = vars_["url"].get()
                        e["password"] = pwd
                        e["notes"]    = notes_box.get("1.0","end-1c")
                        e["category"] = vars_["category"].get()
                        e["icon"]     = vars_["icon"].get() or "🌐"
                        e["updated"]  = now
                        e["strength"] = password_entropy(pwd)
                        break
            self._save_vault()
            win.destroy()
            self.refresh_vault()

        tk.Button(inner, text="💾  Save Entry", command=save,
                  bg=C["accent"], fg="#fff", relief="flat",
                  font=("Consolas", 11, "bold"), cursor="hand2",
                  pady=12).pack(fill=X, padx=20, pady=20)

    # ── Delete Entry ──────────────────────────────────────────────────────────
    def _delete_entry(self, entry):
        if messagebox.askyesno("Delete", f"Delete '{entry.get('site')}'? This cannot be undone."):
            self.vault_data["entries"] = [
                e for e in self.vault_data["entries"] if e["id"] != entry["id"]]
            self._save_vault()
            self.selected_id = None
            self._show_empty_detail()
            self.refresh_vault()

    # ── Password History ──────────────────────────────────────────────────────
    def _show_history(self, entry):
        C = self.C
        win = tk.Toplevel(self.root)
        win.title(f"Password History — {entry.get('site','')}")
        win.geometry("500x400")
        win.configure(bg=C["bg"])
        win.grab_set()

        tk.Label(win, text="🕒 Password History", font=("Consolas", 13, "bold"),
                 bg=C["bg"], fg=C["accent"]).pack(pady=16, padx=20, anchor=W)

        history = entry.get("history", [])
        if not history:
            tk.Label(win, text="No previous passwords recorded.",
                     font=("Consolas", 10), bg=C["bg"], fg=C["subtext"]).pack(pady=40)
            return

        sf = ScrolledFrame(win, autohide=True)
        sf.pack(fill=BOTH, expand=True, padx=20, pady=10)
        for h in reversed(history):
            row = tk.Frame(sf, bg=C["card"])
            row.pack(fill=X, pady=3)
            tk.Label(row, text=h.get("date","")[:10], font=("Consolas", 8),
                     bg=C["card"], fg=C["subtext"], padx=8, pady=4).pack(side=LEFT)
            tk.Label(row, text="●"*len(h.get("password","")),
                     font=("Courier New", 10), bg=C["card"], fg=C["text"],
                     padx=8).pack(side=LEFT)

    # ── Password Generator ─────────────────────────────────────────────────────
    def _open_generator(self):
        C = self.C
        win = tk.Toplevel(self.root)
        win.title("⚡ Password Generator")
        win.geometry("560x640")
        win.configure(bg=C["bg"])
        win.grab_set()

        tk.Label(win, text="⚡ Password Generator",
                 font=("Courier New", 18, "bold"),
                 bg=C["bg"], fg=C["accent"]).pack(pady=20, padx=20, anchor=W)

        # Options
        opts = tk.Frame(win, bg=C["bg"])
        opts.pack(fill=X, padx=20)

        len_var = tk.IntVar(value=20)
        upper_v = tk.BooleanVar(value=True)
        lower_v = tk.BooleanVar(value=True)
        digit_v = tk.BooleanVar(value=True)
        sym_v   = tk.BooleanVar(value=True)
        ambig_v = tk.BooleanVar(value=False)
        custom_v= tk.StringVar(value="")
        count_v = tk.IntVar(value=1)

        def row_slider(parent, text, var, from_, to):
            f = tk.Frame(parent, bg=C["bg"])
            f.pack(fill=X, pady=4)
            tk.Label(f, text=text, font=("Consolas",9), bg=C["bg"],
                     fg=C["text"], width=22, anchor=W).pack(side=LEFT)
            val_lbl = tk.Label(f, textvariable=var, font=("Consolas",9,"bold"),
                               bg=C["bg"], fg=C["accent"], width=4)
            val_lbl.pack(side=RIGHT)
            sl = tk.Scale(f, variable=var, from_=from_, to=to,
                          orient=HORIZONTAL, bg=C["bg"], fg=C["text"],
                          troughcolor=C["border"], activebackground=C["accent"],
                          highlightthickness=0, bd=0,
                          command=lambda _: _regen())
            sl.pack(side=LEFT, fill=X, expand=True)

        def row_check(parent, text, var):
            f = tk.Frame(parent, bg=C["bg"])
            f.pack(fill=X, pady=2)
            cb = tk.Checkbutton(f, text=text, variable=var,
                                bg=C["bg"], fg=C["text"], selectcolor=C["card"],
                                activebackground=C["bg"], font=("Consolas",10),
                                command=_regen)
            cb.pack(side=LEFT)

        row_slider(opts, "Length", len_var, 4, 128)
        row_slider(opts, "Count (batch)", count_v, 1, 20)
        row_check(opts, "Uppercase (A–Z)", upper_v)
        row_check(opts, "Lowercase (a–z)", lower_v)
        row_check(opts, "Digits (0–9)",    digit_v)
        row_check(opts, "Symbols (!@#…)",  sym_v)
        row_check(opts, "Exclude ambiguous (Il1O0)", ambig_v)

        cf = tk.Frame(opts, bg=C["bg"])
        cf.pack(fill=X, pady=4)
        tk.Label(cf, text="Custom charset override:", font=("Consolas",9),
                 bg=C["bg"], fg=C["subtext"]).pack(side=LEFT)
        tk.Entry(cf, textvariable=custom_v, bg=C["card"], fg=C["text"],
                 relief="flat", font=("Consolas",10), bd=0,
                 insertbackground=C["accent"]).pack(side=LEFT, fill=X, expand=True,
                                                    ipady=4, ipadx=6, padx=6)

        # Output area
        out_lbl = tk.Label(win, text="", font=("Courier New", 12),
                           bg=C["card"], fg=C["text"], wraplength=480,
                           justify=LEFT, pady=10, padx=14, anchor=W)
        out_lbl.pack(fill=X, padx=20, pady=12)

        # Strength
        str_canvas2 = tk.Canvas(win, height=6, bg=C["border"], highlightthickness=0)
        str_canvas2.pack(fill=X, padx=20)
        str_lbl2 = tk.Label(win, text="", font=("Consolas",9),
                            bg=C["bg"], fg=C["subtext"])
        str_lbl2.pack(anchor=W, padx=20, pady=2)

        generated = []

        def _regen(*_):
            nonlocal generated
            generated = [generate_password(len_var.get(), upper_v.get(), lower_v.get(),
                                           digit_v.get(), sym_v.get(), ambig_v.get(),
                                           custom_v.get())
                         for _ in range(count_v.get())]
            out_lbl.config(text="\n".join(generated))
            if generated:
                ent_val = password_entropy(generated[0])
                sl, sc, sr = strength_label(ent_val)
                str_canvas2.delete("all")
                w = str_canvas2.winfo_width() or 480
                str_canvas2.create_rectangle(0,0,w,6, fill=C["border"], outline="")
                str_canvas2.create_rectangle(0,0,int(w*sr),6, fill=sc, outline="")
                str_lbl2.config(text=f"{sl}  •  {ent_val:.0f} bits entropy  (first password)",
                                fg=sc)

        _regen()
        custom_v.trace_add("write", _regen)

        btn_row = tk.Frame(win, bg=C["bg"])
        btn_row.pack(fill=X, padx=20, pady=10)

        def _copy_all():
            pyperclip.copy("\n".join(generated))
            self._toast("All passwords copied to clipboard!")

        tk.Button(btn_row, text="🔄 Regenerate", command=_regen,
                  bg=C["card"], fg=C["text"], relief="flat",
                  font=("Consolas",10,"bold"), cursor="hand2",
                  padx=14, pady=8).pack(side=LEFT, padx=4)
        tk.Button(btn_row, text="📋 Copy All", command=_copy_all,
                  bg=C["accent"], fg="#fff", relief="flat",
                  font=("Consolas",10,"bold"), cursor="hand2",
                  padx=14, pady=8).pack(side=LEFT, padx=4)
        tk.Button(btn_row, text="💾 Use in New Entry",
                  command=lambda: [win.destroy(), self._prefill_add(generated[0] if generated else "")],
                  bg=C["accent2"], fg="#fff", relief="flat",
                  font=("Consolas",10,"bold"), cursor="hand2",
                  padx=14, pady=8).pack(side=LEFT, padx=4)

    def _prefill_add(self, pwd):
        # open add form with pre-filled password
        dummy = {"password": pwd, "id": None}
        self._entry_form(None)

    # ── Export / Import ────────────────────────────────────────────────────────
    def _export_vault(self):
        if self.locked: return
        path = filedialog.asksaveasfilename(
            defaultextension=".fortress",
            filetypes=[("Fortress Encrypted", "*.fortress"), ("All", "*.*")],
            title="Export Vault")
        if not path: return
        pwd = simpledialog.askstring("Export Password",
                                     "Set an export password:", show="*",
                                     parent=self.root)
        if not pwd: return
        salt = os.urandom(32)
        key  = derive_key(pwd, salt)
        enc  = encrypt_vault(self.vault_data, key)
        with open(path, "wb") as f:
            f.write(salt + enc)
        self._toast(f"Vault exported to {os.path.basename(path)}")

    def _import_vault(self):
        path = filedialog.askopenfilename(
            filetypes=[("Fortress Encrypted", "*.fortress"), ("All", "*.*")],
            title="Import Vault")
        if not path: return
        pwd = simpledialog.askstring("Import Password",
                                     "Enter export password:", show="*",
                                     parent=self.root)
        if not pwd: return
        try:
            with open(path, "rb") as f:
                raw = f.read()
            salt = raw[:32]
            key  = derive_key(pwd, salt)
            data = decrypt_vault(raw[32:], key)
            imported = data.get("entries", [])
            existing_ids = {e["id"] for e in self.vault_data["entries"]}
            added = 0
            for e in imported:
                if e.get("id") not in existing_ids:
                    self.vault_data["entries"].append(e)
                    added += 1
            self._save_vault()
            self.refresh_vault()
            self._toast(f"Imported {added} new entries.")
        except Exception as ex:
            messagebox.showerror("Import Failed", str(ex))

    # ── Theme toggle ───────────────────────────────────────────────────────────
    def _toggle_theme(self):
        self.theme_name = "light" if self.theme_name == "dark" else "dark"
        self.C = PALETTES[self.theme_name]
        # Rebuild UI
        for w in self.root.winfo_children():
            w.destroy()
        self._build_ui()
        if not self.locked:
            self.refresh_vault()
        self.btn_theme.config(text="☀️ Theme" if self.theme_name=="dark" else "🌙 Theme")

    # ── Welcome screen ─────────────────────────────────────────────────────────
    def _show_welcome(self):
        self._toast("🔐 Vault created! Start adding your passwords.")

# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        import ttkbootstrap
    except ImportError:
        print("Installing ttkbootstrap...")
        os.system("pip install ttkbootstrap cryptography pyperclip")
        print("Please restart the application.")
        exit()
    FortressApp()
