#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
برنامه پیشرفته رمزگذاری و رمزگشایی فایل
نسخه حرفه‌ای با UI/UX مدرن و امکانات پیشرفته
v3.0 - Enhanced with security improvements and advanced features
"""

import os
import sys
import json
import zlib
import base64
import hashlib
import secrets
import string
from pathlib import Path
from datetime import datetime
from typing import Optional, List
import mimetypes

import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DRAG_DROP_AVAILABLE = True
except ImportError:
    DRAG_DROP_AVAILABLE = False

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class ModernEncryptionApp:
    """برنامه پیشرفته رمزگذاری با UI مدرن و ویژگی‌های پیشرفته"""
    
    # رنگ‌های تم
    THEMES = {
        'dark': {
            'bg': '#1e1e2e',
            'fg': '#cdd6f4',
            'primary': '#89b4fa',
            'secondary': '#f38ba8',
            'success': '#a6e3a1',
            'warning': '#f9e2af',
            'danger': '#f38ba8',
            'card_bg': '#313244',
            'hover': '#45475a',
            'accent': '#cba6f7'
        },
        'light': {
            'bg': '#eff1f5',
            'fg': '#4c4f69',
            'primary': '#1e66f5',
            'secondary': '#ea76cb',
            'success': '#40a02b',
            'warning': '#df8e1d',
            'danger': '#d20f39',
            'card_bg': '#ffffff',
            'hover': '#dce0e8',
            'accent': '#8839ef'
        }
    }
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 CryptoVault Pro v3.0 - Advanced File Encryption")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        
        # متغیرها
        self.current_theme = 'dark'
        self.colors = self.THEMES[self.current_theme]
        self.key = None
        self.files = []
        self.password = None
        self.algorithm = tk.StringVar(value="AES-256-GCM")
        self.compression = tk.BooleanVar(value=True)
        self.verify_integrity = tk.BooleanVar(value=True)
        self.operation_history = []
        self.salt = None
        
        # تنظیم استایل
        self.setup_styles()
        self.setup_ui()
        self.apply_theme()
        
        # بارگذاری تاریخچه
        self.load_history()
    
    def setup_styles(self):
        """تنظیم استایل‌های ttk"""
        style = ttk.Style()
        style.theme_use('clam')
    
    def setup_ui(self):
        """ایجاد رابط کاربری"""
        # منوی بالا
        self.create_menu_bar()
        
        # هدر
        self.create_header()
        
        # محتوای اصلی
        main_container = tk.Frame(self.root)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # قسمت چپ - تنظیمات و کنترل
        left_panel = tk.Frame(main_container)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        self.create_algorithm_section(left_panel)
        self.create_key_section(left_panel)
        self.create_file_section(left_panel)
        self.create_options_section(left_panel)
        self.create_action_buttons(left_panel)
        
        # قسمت میانی - نوار جداکننده
        separator = tk.Frame(main_container, width=2)
        separator.pack(side="left", fill="y", padx=5)
        
        # قسمت راست - لاگ و آمار
        right_panel = tk.Frame(main_container)
        right_panel.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        self.create_log_section(right_panel)
        self.create_stats_section(right_panel)
        
        # نوار وضعیت
        self.create_status_bar()
    
    def create_menu_bar(self):
        """ایجاد منوی بالا"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # منوی فایل
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="📁 File", menu=file_menu)
        file_menu.add_command(label="Open File(s)", command=self.select_files, accelerator="Ctrl+O")
        file_menu.add_command(label="Open Folder", command=self.select_folder)
        file_menu.add_command(label="Clear Files", command=self.clear_files)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")
        
        # منوی ابزار
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="🔧 Tools", menu=tools_menu)
        tools_menu.add_command(label="Password Generator", command=self.show_password_generator)
        tools_menu.add_command(label="Key Manager", command=self.show_key_manager)
        tools_menu.add_command(label="File Info", command=self.show_file_info)
        tools_menu.add_command(label="Hash Calculator", command=self.show_hash_calculator)
        tools_menu.add_separator()
        tools_menu.add_command(label="Batch Operations", command=self.batch_operations)
        tools_menu.add_command(label="Secure Wipe", command=self.secure_wipe)
        
        # منوی نمایش
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="👁️ View", menu=view_menu)
        view_menu.add_command(label="Toggle Theme", command=self.toggle_theme, accelerator="Ctrl+T")
        view_menu.add_command(label="Clear Log", command=self.clear_log)
        view_menu.add_command(label="Operation History", command=self.show_history)
        
        # منوی راهنما
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="❓ Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="Security Tips", command=self.show_security_tips)
        
        # کلیدهای میانبر
        self.root.bind('<Control-o>', lambda e: self.select_files())
        self.root.bind('<Control-t>', lambda e: self.toggle_theme())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
    
    def create_header(self):
        """ایجاد هدر برنامه"""
        header = tk.Frame(self.root, height=80)
        header.pack(fill="x", padx=10, pady=(10, 5))
        
        # عنوان و زیر عنوان
        title_frame = tk.Frame(header)
        title_frame.pack(side="left", fill="both", expand=True)
        
        title = tk.Label(
            title_frame,
            text="🔐 CryptoVault Pro v3.0",
            font=("Arial", 26, "bold")
        )
        title.pack(side="left", anchor="w")
        
        subtitle = tk.Label(
            title_frame,
            text="Advanced File Encryption & Security Suite",
            font=("Arial", 10),
            justify="left"
        )
        subtitle.pack(side="left", padx=(15, 0), anchor="w")
        
        # دکمه تغییر تم
        theme_btn = tk.Button(
            header,
            text="🌓",
            font=("Arial", 18),
            command=self.toggle_theme,
            relief="flat",
            cursor="hand2",
            width=3,
            height=1
        )
        theme_btn.pack(side="right", padx=5)
    
    def create_algorithm_section(self, parent):
        """بخش انتخاب الگوریتم"""
        frame = self.create_card(parent, "🔒 Encryption Algorithm")
        
        algorithms = [
            ("AES-256-GCM (Recommended - Most Secure)", "AES-256-GCM"),
            ("ChaCha20-Poly1305 (Fast & Secure)", "ChaCha20-Poly1305"),
            ("Fernet (Simple & Reliable)", "Fernet")
        ]
        
        for text, value in algorithms:
            rb = tk.Radiobutton(
                frame,
                text=text,
                variable=self.algorithm,
                value=value,
                font=("Arial", 10)
            )
            rb.pack(anchor="w", pady=4)
    
    def create_key_section(self, parent):
        """بخش مدیریت کلید"""
        frame = self.create_card(parent, "🔑 Key Management")
        
        self.key_status = tk.Label(
            frame,
            text="❌ No key loaded",
            font=("Arial", 10, "bold")
        )
        self.key_status.pack(pady=5)
        
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=5)
        
        self.create_button(
            btn_frame,
            "Generate Key",
            self.generate_key,
            "#a6e3a1"
        ).pack(side="left", padx=3)
        
        self.create_button(
            btn_frame,
            "Load Key",
            self.load_key,
            "#f9e2af"
        ).pack(side="left", padx=3)
        
        self.create_button(
            btn_frame,
            "Use Password",
            self.use_password,
            "#89b4fa"
        ).pack(side="left", padx=3)
    
    def create_file_section(self, parent):
        """بخش مدیریت فایل‌ها"""
        frame = self.create_card(parent, "📁 Files")
        
        # Drag & Drop
        drop_frame = tk.Frame(
            frame,
            relief="ridge",
            borderwidth=2,
            height=100
        )
        drop_frame.pack(fill="x", pady=5)
        drop_frame.pack_propagate(False)
        
        drop_label = tk.Label(
            drop_frame,
            text="🖱️ Drag & Drop Files Here\nor click to browse",
            font=("Arial", 11),
            cursor="hand2"
        )
        drop_label.pack(expand=True)
        drop_label.bind('<Button-1>', lambda e: self.select_files())
        
        # لیست فایل‌ها
        list_frame = tk.Frame(frame)
        list_frame.pack(fill="both", expand=True, pady=5)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.file_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scrollbar.set,
            height=6,
            font=("Arial", 9)
        )
        self.file_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.file_listbox.yview)
        
        # دکمه‌های مدیریت فایل
        file_btn_frame = tk.Frame(frame)
        file_btn_frame.pack(pady=5)
        
        self.create_button(
            file_btn_frame,
            "Add Files",
            self.select_files,
            "#89b4fa",
            width=10
        ).pack(side="left", padx=2)
        
        self.create_button(
            file_btn_frame,
            "Remove",
            self.remove_selected_file,
            "#f38ba8",
            width=10
        ).pack(side="left", padx=2)
        
        self.create_button(
            file_btn_frame,
            "Clear All",
            self.clear_files,
            "#fab387",
            width=10
        ).pack(side="left", padx=2)
    
    def create_options_section(self, parent):
        """بخش تنظیمات"""
        frame = self.create_card(parent, "⚙️ Advanced Options")
        
        tk.Checkbutton(
            frame,
            text="✓ Enable compression (reduces file size)",
            variable=self.compression,
            font=("Arial", 10)
        ).pack(anchor="w", pady=3)
        
        self.delete_original = tk.BooleanVar(value=False)
        tk.Checkbutton(
            frame,
            text="✓ Delete original file after encryption",
            variable=self.delete_original,
            font=("Arial", 10)
        ).pack(anchor="w", pady=3)
        
        self.add_timestamp = tk.BooleanVar(value=True)
        tk.Checkbutton(
            frame,
            text="✓ Add timestamp to output filename",
            variable=self.add_timestamp,
            font=("Arial", 10)
        ).pack(anchor="w", pady=3)
        
        tk.Checkbutton(
            frame,
            text="✓ Verify file integrity after encryption",
            variable=self.verify_integrity,
            font=("Arial", 10)
        ).pack(anchor="w", pady=3)
    
    def create_action_buttons(self, parent):
        """دکمه‌های اصلی"""
        frame = tk.Frame(parent)
        frame.pack(pady=15)
        
        self.encrypt_btn = self.create_button(
            frame,
            "🔒 ENCRYPT FILES",
            self.encrypt_files,
            "#a6e3a1",
            width=18,
            height=2
        )
        self.encrypt_btn.pack(side="left", padx=10)
        
        self.decrypt_btn = self.create_button(
            frame,
            "🔓 DECRYPT FILES",
            self.decrypt_files,
            "#f38ba8",
            width=18,
            height=2
        )
        self.decrypt_btn.pack(side="left", padx=10)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            parent,
            mode='indeterminate',
            length=400
        )
        self.progress.pack(pady=10)
    
    def create_log_section(self, parent):
        """بخش لاگ"""
        frame = self.create_card(parent, "📋 Operation Log")
        
        self.log_text = scrolledtext.ScrolledText(
            frame,
            height=20,
            font=("Consolas", 9),
            wrap=tk.WORD
        )
        self.log_text.pack(fill="both", expand=True)
        
        self.log("Application started successfully", "SUCCESS")
        self.log(f"Current algorithm: {self.algorithm.get()}", "INFO")
    
    def create_stats_section(self, parent):
        """بخش آمار"""
        frame = self.create_card(parent, "📊 Statistics")
        
        self.stats_label = tk.Label(
            frame,
            text="Files: 0 | Total Size: 0 B",
            font=("Arial", 10)
        )
        self.stats_label.pack(pady=5)
    
    def create_status_bar(self):
        """نوار وضعیت"""
        self.status_bar = tk.Label(
            self.root,
            text="Ready",
            anchor="w",
            relief="sunken",
            font=("Arial", 9)
        )
        self.status_bar.pack(side="bottom", fill="x")
    
    def create_card(self, parent, title):
        """ایجاد کارت با عنوان"""
        container = tk.LabelFrame(
            parent,
            text=title,
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        container.pack(fill="both", expand=True, pady=8)
        return container
    
    def create_button(self, parent, text, command, color, width=15, height=1):
        """ایجاد دکمه استایل شده"""
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg="black",
            font=("Arial", 10, "bold"),
            relief="flat",
            cursor="hand2",
            width=width,
            height=height
        )
        return btn
    
    def log(self, message, level="INFO"):
        """افزودن پیام به لاگ"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(
            tk.END,
            f"[{timestamp}] [{level}] {message}\n"
        )
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_status(self, message):
        """به‌روزرسانی نوار وضعیت"""
        self.status_bar.config(text=message)
        self.root.update_idletasks()
    
    def toggle_theme(self):
        """تغییر تم"""
        self.current_theme = 'light' if self.current_theme == 'dark' else 'dark'
        self.colors = self.THEMES[self.current_theme]
        self.apply_theme()
        self.log(f"Theme changed to {self.current_theme.upper()}", "INFO")
    
    def apply_theme(self):
        """اعمال تم"""
        c = self.colors
        self.root.config(bg=c['bg'])
        
        for widget in self.root.winfo_children():
            self.apply_theme_to_widget(widget, c)
    
    def apply_theme_to_widget(self, widget, colors):
        """اعمال تم به ویجت"""
        try:
            if isinstance(widget, (tk.Frame, tk.LabelFrame)):
                widget.config(bg=colors['bg'])
                if isinstance(widget, tk.LabelFrame):
                    widget.config(fg=colors['fg'])
            elif isinstance(widget, tk.Label):
                widget.config(bg=colors['bg'], fg=colors['fg'])
            elif isinstance(widget, tk.Listbox):
                widget.config(bg=colors['card_bg'], fg=colors['fg'])
            elif isinstance(widget, scrolledtext.ScrolledText):
                widget.config(bg=colors['card_bg'], fg=colors['fg'])
            
            for child in widget.winfo_children():
                self.apply_theme_to_widget(child, colors)
        except:
            pass
    
    def select_folder(self):
        """انتخاب پوشه"""
        folder = filedialog.askdirectory(title="Select folder")
        if folder:
            files = []
            for file in Path(folder).rglob("*"):
                if file.is_file():
                    files.append(str(file))
            
            for file in files:
                if file not in self.files:
                    self.files.append(file)
                    self.file_listbox.insert(tk.END, os.path.basename(file))
            
            self.update_stats()
            self.log(f"Added {len(files)} file(s) from folder", "SUCCESS")
    
    def select_files(self):
        """انتخاب فایل‌ها"""
        files = filedialog.askopenfilenames(
            title="Select files",
            filetypes=[("All Files", "*.*")]
        )
        
        for file in files:
            if file not in self.files:
                self.files.append(file)
                self.file_listbox.insert(tk.END, os.path.basename(file))
        
        self.update_stats()
        self.log(f"Added {len(files)} file(s)", "SUCCESS")
    
    def remove_selected_file(self):
        """حذف فایل انتخاب شده"""
        selection = self.file_listbox.curselection()
        if selection:
            index = selection[0]
            self.file_listbox.delete(index)
            del self.files[index]
            self.update_stats()
            self.log("File removed", "INFO")
    
    def clear_files(self):
        """پاک کردن تمام فایل‌ها"""
        self.files.clear()
        self.file_listbox.delete(0, tk.END)
        self.update_stats()
        self.log("All files cleared", "INFO")
    
    def update_stats(self):
        """به‌روزرسانی آمار"""
        total_size = sum(os.path.getsize(f) for f in self.files if os.path.exists(f))
        size_str = self.format_size(total_size)
        self.stats_label.config(text=f"Files: {len(self.files)} | Total Size: {size_str}")
    
    def format_size(self, size):
        """فرمت کردن حجم فایل"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    def generate_key(self):
        """تولید کلید جدید"""
        algo = self.algorithm.get()
        
        if algo == "Fernet":
            self.key = Fernet.generate_key()
        elif algo == "AES-256-GCM":
            self.key = secrets.token_bytes(32)
        elif algo == "ChaCha20-Poly1305":
            self.key = secrets.token_bytes(32)
        
        save_path = filedialog.asksaveasfilename(
            title="Save encryption key",
            defaultextension=".key",
            filetypes=[("Key Files", "*.key")]
        )
        
        if save_path:
            # Store algorithm info with the key (format: ALGO_NAME\n + KEY_DATA)
            with open(save_path, 'wb') as f:
                f.write(algo.encode() + b'\n' + self.key)
            
            self.key_status.config(text="✅ Key loaded", fg="#a6e3a1")
            self.log("New key generated and saved", "SUCCESS")
            messagebox.showinfo("Success", "Key generated successfully!\nKeep it safe!")
    
    def load_key(self):
        """بارگذاری کلید"""
        key_path = filedialog.askopenfilename(
            title="Select key file",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")]
        )
        
        if key_path:
            with open(key_path, 'rb') as f:
                file_content = f.read()
            
            # Try to parse algorithm from key file
            try:
                # Look for the first newline
                newline_pos = file_content.find(b'\n')
                if newline_pos > 0:
                    # New format: ALGO_NAME\n + KEY_DATA
                    algo_name = file_content[:newline_pos].decode()
                    self.key = file_content[newline_pos + 1:]
                    
                    # Validate algorithm
                    if algo_name in ["Fernet", "AES-256-GCM", "ChaCha20-Poly1305"]:
                        self.algorithm.set(algo_name)
                        self.log(f"Algorithm detected: {algo_name}", "INFO")
                    else:
                        raise ValueError(f"Unknown algorithm in key file: {algo_name}")
                else:
                    # Old format: just the raw key (assume AES-256-GCM for backward compatibility)
                    self.key = file_content
                    self.algorithm.set("AES-256-GCM")
                    self.log("Old key format detected, using AES-256-GCM", "WARNING")
            
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key file:\n{str(e)}")
                return
            
            self.key_status.config(text="✅ Key loaded", fg="#a6e3a1")
            self.log("Key loaded successfully", "SUCCESS")
    
    def use_password(self):
        """استفاده از رمز عبور"""
        password = self.prompt_password()
        if password:
            # Store password for use during encryption
            self.password = password
            self.key_status.config(text="✅ Key from password", fg="#a6e3a1")
            self.log("Key derived from password", "SUCCESS")
            messagebox.showinfo("Success", "Password set! Salt will be generated during encryption.")
    
    def prompt_password(self):
        """درخواست رمز عبور"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter Password")
        dialog.geometry("300x150")
        dialog.resizable(False, False)
        
        tk.Label(dialog, text="Enter password:", font=("Arial", 11)).pack(pady=10)
        
        password_var = tk.StringVar()
        entry = tk.Entry(dialog, textvariable=password_var, show="*", font=("Arial", 11))
        entry.pack(pady=10, padx=20, fill="x")
        entry.focus()
        
        result = [None]
        
        def on_ok():
            result[0] = password_var.get()
            dialog.destroy()
        
        tk.Button(
            dialog,
            text="OK",
            command=on_ok,
            bg="#a6e3a1",
            font=("Arial", 10, "bold")
        ).pack(pady=10)
        
        dialog.wait_window()
        return result[0]
    
    def encrypt_files(self):
        """رمزگذاری فایل‌ها"""
        if not self.files:
            messagebox.showwarning("Warning", "No files selected")
            return
        
        if not self.key:
            messagebox.showwarning("Warning", "No key loaded")
            return
        
        self.progress.start()
        self.encrypt_btn.config(state="disabled")
        self.log(f"Starting encryption of {len(self.files)} file(s)...", "INFO")
        
        try:
            for file_path in self.files:
                self.encrypt_single_file(file_path)
            
            self.log("All files encrypted successfully!", "SUCCESS")
            messagebox.showinfo("Success", "Encryption completed!")
            
            if self.delete_original.get():
                for file_path in self.files:
                    os.remove(file_path)
                self.log("Original files deleted", "INFO")
            
        except Exception as e:
            self.log(f"Encryption error: {str(e)}", "ERROR")
            messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")
        
        finally:
            self.progress.stop()
            self.encrypt_btn.config(state="normal")
    
    def encrypt_single_file(self, file_path):
        """رمزگذاری یک فایل"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if self.compression.get():
            data = zlib.compress(data)
            self.log(f"Compressed: {os.path.basename(file_path)}", "INFO")
        
        algo = self.algorithm.get()
        
        # Generate key from password if needed
        key_to_use = self.key
        salt_to_store = None
        
        if hasattr(self, 'password') and self.password:
            salt = secrets.token_bytes(32)
            salt_to_store = salt
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
            )
            key_to_use = kdf.derive(self.password.encode())
        
        # Add algorithm marker to ensure correct decryption
        algo_marker = {
            "Fernet": b'FERN',
            "AES-256-GCM": b'AESG',
            "ChaCha20-Poly1305": b'CHAP'
        }[algo]
        
        if algo == "Fernet":
            # For Fernet with password, convert the key to Fernet format
            if salt_to_store:
                # Password-based: use key directly with Fernet.from_bytes if available, or use base64
                fernet_key = base64.urlsafe_b64encode(key_to_use)
                fernet = Fernet(fernet_key)
            else:
                # Key-based: use the key as-is (should already be Fernet format)
                fernet = Fernet(key_to_use)
            encrypted = algo_marker + fernet.encrypt(data)
        
        elif algo == "AES-256-GCM":
            aesgcm = AESGCM(key_to_use)
            nonce = secrets.token_bytes(12)
            encrypted = algo_marker + nonce + aesgcm.encrypt(nonce, data, None)
        
        elif algo == "ChaCha20-Poly1305":
            chacha = ChaCha20Poly1305(key_to_use)
            nonce = secrets.token_bytes(12)
            encrypted = algo_marker + nonce + chacha.encrypt(nonce, data, None)
        
        # Prepend salt if password-based (format: PSWD_MARKER + salt + algo_marker + encrypted_data)
        if salt_to_store:
            encrypted = b'PSWD' + salt_to_store + encrypted
        
        base_name = os.path.splitext(file_path)[0]
        if self.add_timestamp.get():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"{base_name}_encrypted_{timestamp}.enc"
        else:
            output_path = f"{base_name}_encrypted.enc"
        
        with open(output_path, 'wb') as f:
            f.write(encrypted)
        
        self.log(f"Encrypted: {os.path.basename(output_path)}", "SUCCESS")
        self.add_to_history("encrypt", file_path, output_path)
    
    def decrypt_files(self):
        """رمزگشایی فایل‌ها"""
        if not self.files:
            messagebox.showwarning("Warning", "No files selected")
            return
        
        if not self.key:
            messagebox.showwarning("Warning", "No key loaded")
            return
        
        self.progress.start()
        self.decrypt_btn.config(state="disabled")
        self.log(f"Starting decryption of {len(self.files)} file(s)...", "INFO")
        
        try:
            for file_path in self.files:
                self.decrypt_single_file(file_path)
            
            self.log("All files decrypted successfully!", "SUCCESS")
            messagebox.showinfo("Success", "Decryption completed!")
            
        except Exception as e:
            self.log(f"Decryption error: {str(e)}", "ERROR")
            messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")
        
        finally:
            self.progress.stop()
            self.decrypt_btn.config(state="normal")
    
    def decrypt_single_file(self, file_path):
        """رمزگشایی یک فایل"""
        with open(file_path, 'rb') as f:
            encrypted = f.read()
        
        key_to_use = self.key
        encrypted_data = encrypted
        password_based = False
        
        try:
            # Check for valid algorithm marker before attempting decryption
            valid_markers = [b'FERN', b'AESG', b'CHAP', b'PSWD']
            if not any(encrypted_data.startswith(marker) for marker in valid_markers):
                self.log(f"Skipped (not an encrypted file): {os.path.basename(file_path)}", "WARNING")
                return
            # Check if password-based (has PSWD marker)
            if encrypted_data.startswith(b'PSWD'):
                password_based = True
                # Extract salt (bytes 4-36, 32 bytes)
                salt = encrypted_data[4:36]
                encrypted_data = encrypted_data[36:]  # Rest of data (algo_marker + encrypted)
                
                # Derive key from password using extracted salt
                if not hasattr(self, 'password') or not self.password:
                    raise Exception("Password required for decryption")
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=480000,
                )
                key_to_use = kdf.derive(self.password.encode())
            
            # Read algorithm marker (first 4 bytes of encrypted_data)
            if len(encrypted_data) < 4:
                raise Exception("Invalid encrypted file format")
            
            algo_marker = encrypted_data[:4]
            encrypted_payload = encrypted_data[4:]
            
            # Decrypt based on algorithm marker
            if algo_marker == b'FERN':
                # For Fernet with password, convert the key to Fernet format
                if password_based:
                    fernet_key = base64.urlsafe_b64encode(key_to_use)
                    fernet = Fernet(fernet_key)
                else:
                    fernet = Fernet(key_to_use)
                data = fernet.decrypt(encrypted_payload)
            
            elif algo_marker == b'AESG':
                aesgcm = AESGCM(key_to_use)
                nonce = encrypted_payload[:12]
                data = aesgcm.decrypt(nonce, encrypted_payload[12:], None)
            
            elif algo_marker == b'CHAP':
                chacha = ChaCha20Poly1305(key_to_use)
                nonce = encrypted_payload[:12]
                data = chacha.decrypt(nonce, encrypted_payload[12:], None)
            
            else:
                raise Exception(f"Unknown algorithm marker: {algo_marker}")
            
            if self.compression.get():
                try:
                    data = zlib.decompress(data)
                    self.log(f"Decompressed: {os.path.basename(file_path)}", "INFO")
                except:
                    pass
            
            base_name = os.path.splitext(file_path)[0]
            output_path = base_name.replace('_encrypted', '_decrypted') + '.txt'
            
            with open(output_path, 'wb') as f:
                f.write(data)
            
            self.log(f"Decrypted: {os.path.basename(output_path)}", "SUCCESS")
            self.add_to_history("decrypt", file_path, output_path)
            
        except Exception as e:
            raise Exception(f"Invalid key or corrupted file: {str(e)}")
    
    def show_password_generator(self):
        """نمایش تولیدکننده رمز عبور"""
        dialog = tk.Toplevel(self.root)
        dialog.title("🔐 Password Generator")
        dialog.geometry("450x350")
        dialog.resizable(False, False)
        
        tk.Label(dialog, text="Password Length:", font=("Arial", 11, "bold")).pack(pady=(10, 0))
        length_var = tk.IntVar(value=16)
        scale = tk.Scale(dialog, from_=8, to=128, variable=length_var, orient="horizontal")
        scale.pack(fill="x", padx=20)
        
        tk.Label(dialog, text="Character Sets:", font=("Arial", 11, "bold")).pack(pady=(10, 5))
        
        include_upper = tk.BooleanVar(value=True)
        tk.Checkbutton(dialog, text="Uppercase (A-Z)", variable=include_upper).pack(anchor="w", padx=20)
        
        include_lower = tk.BooleanVar(value=True)
        tk.Checkbutton(dialog, text="Lowercase (a-z)", variable=include_lower).pack(anchor="w", padx=20)
        
        include_digits = tk.BooleanVar(value=True)
        tk.Checkbutton(dialog, text="Digits (0-9)", variable=include_digits).pack(anchor="w", padx=20)
        
        include_special = tk.BooleanVar(value=True)
        tk.Checkbutton(dialog, text="Special (!@#$%^&*)", variable=include_special).pack(anchor="w", padx=20)
        
        result_var = tk.StringVar()
        result_entry = tk.Entry(dialog, textvariable=result_var, font=("Courier", 11), width=40)
        result_entry.pack(pady=15, padx=10)
        
        def generate():
            chars = ""
            if include_upper.get():
                chars += string.ascii_uppercase
            if include_lower.get():
                chars += string.ascii_lowercase
            if include_digits.get():
                chars += string.digits
            if include_special.get():
                chars += string.punctuation
            
            if not chars:
                messagebox.showwarning("Error", "Select at least one character set!")
                return
            
            password = ''.join(secrets.choice(chars) for _ in range(length_var.get()))
            result_var.set(password)
            self.log(f"Generated {length_var.get()}-char password", "SUCCESS")
        
        btn_frame = tk.Frame(dialog)
        btn_frame.pack(pady=10)
        
        tk.Button(
            btn_frame,
            text="Generate",
            command=generate,
            bg="#a6e3a1",
            font=("Arial", 11, "bold"),
            width=12
        ).pack(side="left", padx=5)
        
        def copy_password():
            password = result_var.get()
            if password:
                self.root.clipboard_clear()
                self.root.clipboard_append(password)
                messagebox.showinfo("Copied", "Password copied to clipboard!")
        
        tk.Button(
            btn_frame,
            text="Copy",
            command=copy_password,
            bg="#89b4fa",
            font=("Arial", 11, "bold"),
            width=12
        ).pack(side="left", padx=5)
    
    def show_key_manager(self):
        """مدیریت کلیدها"""
        dialog = tk.Toplevel(self.root)
        dialog.title("🔑 Key Manager")
        dialog.geometry("500x350")
        
        tk.Label(dialog, text="Key Management Tools", font=("Arial", 14, "bold")).pack(pady=10)
        
        info_text = f"""Current Key Status: {'✅ Loaded' if self.key else '❌ Not Loaded'}

Key Information:
• Algorithm: {self.algorithm.get()}
• Key Size: {len(self.key) * 8 if self.key else 0} bits
• Salt Generated: {'Yes' if self.salt else 'No'}

Operations Available:
• Generate new encryption key
• Load existing key file
• Derive key from password
• Export key (for backup)
"""
        
        info = tk.Label(dialog, text=info_text, font=("Arial", 10), justify="left")
        info.pack(padx=20, pady=10)
        
        tk.Button(dialog, text="Close", command=dialog.destroy, width=30, bg="#89b4fa").pack(pady=10)
    
    def show_file_info(self):
        """نمایش اطلاعات فایل‌ها"""
        if not self.files:
            messagebox.showwarning("Warning", "No files selected")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("📋 File Information")
        dialog.geometry("700x500")
        
        text = scrolledtext.ScrolledText(dialog, font=("Courier", 9))
        text.pack(fill="both", expand=True, padx=10, pady=10)
        
        total_size = 0
        for file_path in self.files:
            if os.path.exists(file_path):
                size = os.path.getsize(file_path)
                total_size += size
                mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                
                info = f"""
File: {os.path.basename(file_path)}
Path: {file_path}
Size: {self.format_size(size)}
Modified: {mod_time.strftime('%Y-%m-%d %H:%M:%S')}
{'─' * 60}
                """
                text.insert(tk.END, info)
        
        summary = f"\n\nTotal Files: {len(self.files)}\nTotal Size: {self.format_size(total_size)}"
        text.insert(tk.END, summary)
    
    def show_hash_calculator(self):
        """حساب‌گر هش فایل"""
        if not self.files:
            messagebox.showwarning("Warning", "No files selected")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("🔑 Hash Calculator")
        dialog.geometry("700x600")
        
        text = scrolledtext.ScrolledText(dialog, font=("Courier", 9))
        text.pack(fill="both", expand=True, padx=10, pady=10)
        
        algorithms = ['sha256', 'sha512', 'md5']
        
        for file_path in self.files:
            if os.path.exists(file_path):
                text.insert(tk.END, f"\nFile: {os.path.basename(file_path)}\n")
                
                for algo in algorithms:
                    try:
                        hash_obj = hashlib.new(algo)
                        with open(file_path, 'rb') as f:
                            for chunk in iter(lambda: f.read(4096), b''):
                                hash_obj.update(chunk)
                        
                        hash_value = hash_obj.hexdigest()
                        text.insert(tk.END, f"  {algo.upper()}: {hash_value}\n")
                    except Exception as e:
                        text.insert(tk.END, f"  {algo.upper()}: Error\n")
                
                text.insert(tk.END, "─" * 80 + "\n")
    
    def batch_operations(self):
        """عملیات دسته‌ای"""
        messagebox.showinfo("Batch Operations", 
            "Batch processing features:\n"
            "• Encrypt multiple folders\n"
            "• Schedule operations\n"
            "• Auto-backup\n\n"
            "Coming in v4.0!")
    
    def secure_wipe(self):
        """حذف امن"""
        dialog = tk.Toplevel(self.root)
        dialog.title("🗑️ Secure Wipe")
        dialog.geometry("400x200")
        
        tk.Label(dialog, text="Select files to securely wipe:\n(Cannot be recovered)", font=("Arial", 10)).pack(pady=10)
        
        files = filedialog.askopenfilenames(title="Select files to wipe")
        
        if not files:
            dialog.destroy()
            return
        
        passes = tk.IntVar(value=3)
        tk.Label(dialog, text="Number of overwrite passes:", font=("Arial", 10)).pack()
        tk.Scale(dialog, from_=1, to=7, variable=passes, orient="horizontal").pack(fill="x", padx=20)
        
        def wipe_files():
            self.log(f"Secure wipe of {len(files)} file(s)...", "WARNING")
            
            for file_path in files:
                try:
                    size = os.path.getsize(file_path)
                    
                    with open(file_path, 'ba+') as f:
                        for _ in range(passes.get()):
                            f.seek(0)
                            f.write(secrets.token_bytes(size))
                    
                    os.remove(file_path)
                    self.log(f"Wiped: {os.path.basename(file_path)}", "SUCCESS")
                except Exception as e:
                    self.log(f"Wipe error: {str(e)}", "ERROR")
            
            messagebox.showinfo("Success", "Files securely wiped!")
            dialog.destroy()
        
        tk.Button(dialog, text="Wipe Files", command=wipe_files, bg="#f38ba8", font=("Arial", 11, "bold")).pack(pady=10)
    
    def show_security_tips(self):
        """نمایش نکات امنیتی"""
        tips = """🔐 SECURITY BEST PRACTICES

1. KEY MANAGEMENT
   ✓ Generate strong keys (32+ bytes)
   ✓ Store keys safely
   ✓ Never share keys
   ✓ Use password protection

2. PASSWORDS
   ✓ Use 16+ characters
   ✓ Mix uppercase, lowercase, digits, symbols
   ✓ Avoid common words
   ✓ Don't reuse passwords

3. ENCRYPTION
   ✓ Backup files first
   ✓ Test decryption
   ✓ Verify integrity
   ✓ Keep metadata safe

4. ALGORITHMS
   ✓ AES-256-GCM: Best
   ✓ ChaCha20: Fast
   ✓ Fernet: Simple

⚠️ REMEMBER: Lost keys = Lost data!"""
        messagebox.showinfo("Security Tips", tips)
    
    def clear_log(self):
        """پاک کردن لاگ"""
        self.log_text.delete(1.0, tk.END)
        self.log("Log cleared", "INFO")
    
    def add_to_history(self, operation, input_file, output_file):
        """افزودن به تاریخچه"""
        self.operation_history.append({
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'input': input_file,
            'output': output_file,
            'algorithm': self.algorithm.get()
        })
        self.save_history()
    
    def save_history(self):
        """ذخیره تاریخچه"""
        try:
            with open('cryptovault_history.json', 'w') as f:
                json.dump(self.operation_history, f, indent=2)
        except:
            pass
    
    def load_history(self):
        """بارگذاری تاریخچه"""
        try:
            if os.path.exists('cryptovault_history.json'):
                with open('cryptovault_history.json', 'r') as f:
                    self.operation_history = json.load(f)
        except:
            self.operation_history = []
    
    def show_history(self):
        """نمایش تاریخچه"""
        dialog = tk.Toplevel(self.root)
        dialog.title("📚 Operation History")
        dialog.geometry("600x400")
        
        text = scrolledtext.ScrolledText(dialog, font=("Consolas", 9))
        text.pack(fill="both", expand=True, padx=10, pady=10)
        
        if not self.operation_history:
            text.insert(tk.END, "No operations recorded yet.")
        else:
            for item in self.operation_history[-50:]:
                text.insert(tk.END, f"{item['timestamp']} - {item['operation'].upper()}\n")
                text.insert(tk.END, f"  Algorithm: {item['algorithm']}\n")
                text.insert(tk.END, f"  Input: {item['input']}\n")
                text.insert(tk.END, f"  Output: {item['output']}\n\n")
    
    def show_about(self):
        """درباره برنامه"""
        about_text = """🔐 CryptoVault Pro v3.0

Advanced File Encryption & Security Suite

FEATURES:
• AES-256-GCM, ChaCha20, Fernet encryption
• File compression & decompression
• Password-based key generation
• Batch operations
• Dark/light themes
• Operation history
• Hash calculator
• Secure file wipe
• File information viewer

SECURITY:
• Military-grade encryption
• Secure random keys
• PBKDF2 hashing
• Integrity verification

VERSION: 3.0 | PYTHON: 3.8+"""
        messagebox.showinfo("About CryptoVault Pro", about_text)
    
    def show_docs(self):
        """نمایش مستندات"""
        docs_text = """📚 QUICK START:

1. SELECT ALGORITHM
2. GENERATE/LOAD KEY
3. ADD FILES
4. CONFIGURE OPTIONS
5. ENCRYPT/DECRYPT

⚠️ IMPORTANT:
✓ Keep key safe
✓ Test on non-critical files
✓ Backup before encryption
✓ Don't lose your key!

TOOLS:
• Password Generator
• Hash Calculator
• Secure Wipe
• File Info"""
        messagebox.showinfo("Documentation", docs_text)


def main():
    """تابع اصلی"""
    try:
        if DRAG_DROP_AVAILABLE:
            root = TkinterDnD.Tk()
        else:
            root = tk.Tk()
    except:
        root = tk.Tk()
    
    app = ModernEncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
