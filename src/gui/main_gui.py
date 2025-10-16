#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main GUI Interface for Al-Mirsad
الواجهة الرسومية الرئيسية لأداة المرصاد

Graphical user interface for Al-Mirsad incident response automation tool.
الواجهة الرسومية لأداة المرصاد لأتمتة الاستجابة للحوادث.
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from typing import Dict, List, Optional, Any
import json
from datetime import datetime

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.log_collector import LogCollector
from core.network_isolator import NetworkIsolator
from core.malware_analyzer import MalwareAnalyzer
from core.report_generator import ReportGenerator


class AlMirsadGUI:
    """
    Main GUI class for Al-Mirsad incident response tool.
    فئة الواجهة الرسومية الرئيسية لأداة المرصاد للاستجابة للحوادث.
    """
    
    def __init__(self):
        """Initialize the GUI."""
        self.root = tk.Tk()
        self.root.title("Al-Mirsad المرصاد - Incident Response Automation Tool")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Initialize core modules
        self.log_collector = LogCollector()
        self.network_isolator = NetworkIsolator()
        self.malware_analyzer = MalwareAnalyzer()
        self.report_generator = ReportGenerator()
        
        # GUI state variables
        self.current_operation = None
        self.operation_results = {}
        
        # Setup GUI
        self.setup_styles()
        self.create_widgets()
        self.setup_layout()
        
        # Center window
        self.center_window()
    
    def setup_styles(self):
        """Setup custom styles for the GUI."""
        style = ttk.Style()
        
        # Configure styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Subtitle.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 10, 'bold'))
        style.configure('Success.TLabel', foreground='green')
        style.configure('Error.TLabel', foreground='red')
        style.configure('Warning.TLabel', foreground='orange')
    
    def create_widgets(self):
        """Create all GUI widgets."""
        # Main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        
        # Title
        self.title_label = ttk.Label(
            self.main_frame,
            text="Al-Mirsad المرصاد - أداة أتمتة الاستجابة للحوادث",
            style='Title.TLabel'
        )
        
        # Author info
        self.author_label = ttk.Label(
            self.main_frame,
            text="Author: Hassan Mohamed Hassan Ahmed | GitHub: kush-king249",
            font=('Arial', 9)
        )
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        
        # Create tabs
        self.create_log_collection_tab()
        self.create_network_isolation_tab()
        self.create_malware_analysis_tab()
        self.create_report_generation_tab()
        self.create_status_tab()
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.main_frame,
            variable=self.progress_var,
            maximum=100
        )
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_label = ttk.Label(
            self.main_frame,
            textvariable=self.status_var
        )
        
        # Output text area
        self.output_text = scrolledtext.ScrolledText(
            self.main_frame,
            height=8,
            width=80,
            wrap=tk.WORD
        )
    
    def create_log_collection_tab(self):
        """Create log collection tab."""
        self.log_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.log_tab, text="Log Collection جمع السجلات")
        
        # Connection settings frame
        conn_frame = ttk.LabelFrame(self.log_tab, text="Connection Settings إعدادات الاتصال", padding="10")
        
        # Local/Remote selection
        self.log_connection_var = tk.StringVar(value="local")
        ttk.Radiobutton(conn_frame, text="Local System النظام المحلي", 
                       variable=self.log_connection_var, value="local").grid(row=0, column=0, sticky="w", padx=5)
        ttk.Radiobutton(conn_frame, text="Remote System النظام البعيد", 
                       variable=self.log_connection_var, value="remote").grid(row=0, column=1, sticky="w", padx=5)
        
        # Remote connection fields
        ttk.Label(conn_frame, text="Host:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.log_host_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=self.log_host_var, width=20).grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(conn_frame, text="Username:").grid(row=1, column=2, sticky="w", padx=5, pady=2)
        self.log_username_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=self.log_username_var, width=15).grid(row=1, column=3, padx=5, pady=2)
        
        ttk.Label(conn_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.log_password_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=self.log_password_var, width=20, show="*").grid(row=2, column=1, padx=5, pady=2)
        
        ttk.Label(conn_frame, text="SSH Key Path:").grid(row=2, column=2, sticky="w", padx=5, pady=2)
        self.log_key_path_var = tk.StringVar()
        key_frame = ttk.Frame(conn_frame)
        key_frame.grid(row=2, column=3, padx=5, pady=2)
        ttk.Entry(key_frame, textvariable=self.log_key_path_var, width=12).pack(side="left")
        ttk.Button(key_frame, text="Browse", command=self.browse_ssh_key, width=8).pack(side="right", padx=(2,0))
        
        # Log types frame
        types_frame = ttk.LabelFrame(self.log_tab, text="Log Types أنواع السجلات", padding="10")
        
        self.log_system_var = tk.BooleanVar(value=True)
        self.log_security_var = tk.BooleanVar(value=True)
        self.log_application_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(types_frame, text="System Logs سجلات النظام", 
                       variable=self.log_system_var).grid(row=0, column=0, sticky="w", padx=5)
        ttk.Checkbutton(types_frame, text="Security Logs سجلات الأمان", 
                       variable=self.log_security_var).grid(row=0, column=1, sticky="w", padx=5)
        ttk.Checkbutton(types_frame, text="Application Logs سجلات التطبيقات", 
                       variable=self.log_application_var).grid(row=0, column=2, sticky="w", padx=5)
        
        # Analysis options
        analysis_frame = ttk.LabelFrame(self.log_tab, text="Analysis Options خيارات التحليل", padding="10")
        
        self.log_analyze_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(analysis_frame, text="Analyze for suspicious activities تحليل الأنشطة المشبوهة", 
                       variable=self.log_analyze_var).grid(row=0, column=0, sticky="w", padx=5)
        
        ttk.Label(analysis_frame, text="Custom Keywords:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.log_keywords_var = tk.StringVar()
        ttk.Entry(analysis_frame, textvariable=self.log_keywords_var, width=50).grid(row=1, column=1, padx=5, pady=2)
        
        # Collect button
        ttk.Button(self.log_tab, text="Collect Logs جمع السجلات", 
                  command=self.collect_logs, style='Header.TLabel').grid(row=3, column=0, pady=10)
        
        # Layout log tab
        conn_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        types_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        analysis_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        
        self.log_tab.columnconfigure(0, weight=1)
    
    def create_network_isolation_tab(self):
        """Create network isolation tab."""
        self.network_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.network_tab, text="Network Isolation عزل الشبكة")
        
        # Connection settings frame
        conn_frame = ttk.LabelFrame(self.network_tab, text="Connection Settings إعدادات الاتصال", padding="10")
        
        # Local/Remote selection
        self.net_connection_var = tk.StringVar(value="local")
        ttk.Radiobutton(conn_frame, text="Local System النظام المحلي", 
                       variable=self.net_connection_var, value="local").grid(row=0, column=0, sticky="w", padx=5)
        ttk.Radiobutton(conn_frame, text="Remote System النظام البعيد", 
                       variable=self.net_connection_var, value="remote").grid(row=0, column=1, sticky="w", padx=5)
        
        # Remote connection fields
        ttk.Label(conn_frame, text="Host:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.net_host_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=self.net_host_var, width=20).grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(conn_frame, text="Username:").grid(row=1, column=2, sticky="w", padx=5, pady=2)
        self.net_username_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=self.net_username_var, width=15).grid(row=1, column=3, padx=5, pady=2)
        
        ttk.Label(conn_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.net_password_var = tk.StringVar()
        ttk.Entry(conn_frame, textvariable=self.net_password_var, width=20, show="*").grid(row=2, column=1, padx=5, pady=2)
        
        # Isolation settings frame
        isolation_frame = ttk.LabelFrame(self.network_tab, text="Isolation Settings إعدادات العزل", padding="10")
        
        ttk.Label(isolation_frame, text="Central Server IP:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.central_server_var = tk.StringVar()
        ttk.Entry(isolation_frame, textvariable=self.central_server_var, width=20).grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(isolation_frame, text="Allowed Ports:").grid(row=0, column=2, sticky="w", padx=5, pady=2)
        self.allowed_ports_var = tk.StringVar(value="22,443,80")
        ttk.Entry(isolation_frame, textvariable=self.allowed_ports_var, width=20).grid(row=0, column=3, padx=5, pady=2)
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.network_tab)
        ttk.Button(buttons_frame, text="Apply Isolation تطبيق العزل", 
                  command=self.apply_isolation).pack(side="left", padx=5)
        ttk.Button(buttons_frame, text="Restore Access استعادة الوصول", 
                  command=self.restore_access).pack(side="left", padx=5)
        
        # Layout network tab
        conn_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        isolation_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        buttons_frame.grid(row=2, column=0, pady=10)
        
        self.network_tab.columnconfigure(0, weight=1)
    
    def create_malware_analysis_tab(self):
        """Create malware analysis tab."""
        self.malware_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.malware_tab, text="Malware Analysis تحليل البرمجيات الخبيثة")
        
        # File selection frame
        file_frame = ttk.LabelFrame(self.malware_tab, text="File Selection اختيار الملف", padding="10")
        
        ttk.Label(file_frame, text="File/Directory Path:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.malware_path_var = tk.StringVar()
        path_frame = ttk.Frame(file_frame)
        path_frame.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        ttk.Entry(path_frame, textvariable=self.malware_path_var, width=40).pack(side="left", fill="x", expand=True)
        ttk.Button(path_frame, text="Browse File", command=self.browse_malware_file).pack(side="right", padx=(2,0))
        ttk.Button(path_frame, text="Browse Dir", command=self.browse_malware_dir).pack(side="right", padx=(2,0))
        
        # Analysis options frame
        options_frame = ttk.LabelFrame(self.malware_tab, text="Analysis Options خيارات التحليل", padding="10")
        
        self.deep_analysis_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Deep Analysis (Behavioral) تحليل عميق (سلوكي)", 
                       variable=self.deep_analysis_var).grid(row=0, column=0, sticky="w", padx=5)
        
        ttk.Label(options_frame, text="File Extensions:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.file_extensions_var = tk.StringVar(value=".exe,.dll,.bat,.ps1,.scr,.com")
        ttk.Entry(options_frame, textvariable=self.file_extensions_var, width=40).grid(row=1, column=1, padx=5, pady=2)
        
        # Analyze button
        ttk.Button(self.malware_tab, text="Analyze Malware تحليل البرمجيات الخبيثة", 
                  command=self.analyze_malware, style='Header.TLabel').grid(row=2, column=0, pady=10)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.malware_tab, text="Analysis Results نتائج التحليل", padding="10")
        
        # Results treeview
        columns = ("File", "Risk Score", "Threat Type", "Status")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=8)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)
        
        # Scrollbar for treeview
        results_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scrollbar.set)
        
        # Layout malware tab
        file_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        options_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        results_frame.grid(row=3, column=0, sticky="ew", padx=5, pady=5)
        
        self.results_tree.pack(side="left", fill="both", expand=True)
        results_scrollbar.pack(side="right", fill="y")
        
        file_frame.columnconfigure(1, weight=1)
        path_frame.columnconfigure(0, weight=1)
        self.malware_tab.columnconfigure(0, weight=1)
    
    def create_report_generation_tab(self):
        """Create report generation tab."""
        self.report_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.report_tab, text="Report Generation إنشاء التقارير")
        
        # Incident information frame
        incident_frame = ttk.LabelFrame(self.report_tab, text="Incident Information معلومات الحادث", padding="10")
        
        ttk.Label(incident_frame, text="Incident ID:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.incident_id_var = tk.StringVar()
        ttk.Entry(incident_frame, textvariable=self.incident_id_var, width=20).grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(incident_frame, text="Incident Type:").grid(row=0, column=2, sticky="w", padx=5, pady=2)
        self.incident_type_var = tk.StringVar()
        incident_type_combo = ttk.Combobox(incident_frame, textvariable=self.incident_type_var, width=18)
        incident_type_combo['values'] = ('Malware', 'Data Breach', 'DDoS', 'Phishing', 'Insider Threat', 'Other')
        incident_type_combo.grid(row=0, column=3, padx=5, pady=2)
        
        ttk.Label(incident_frame, text="Severity:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.severity_var = tk.StringVar()
        severity_combo = ttk.Combobox(incident_frame, textvariable=self.severity_var, width=18)
        severity_combo['values'] = ('High', 'Medium', 'Low')
        severity_combo.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(incident_frame, text="Status:").grid(row=1, column=2, sticky="w", padx=5, pady=2)
        self.status_combo_var = tk.StringVar()
        status_combo = ttk.Combobox(incident_frame, textvariable=self.status_combo_var, width=18)
        status_combo['values'] = ('Open', 'Under Investigation', 'Contained', 'Closed')
        status_combo.grid(row=1, column=3, padx=5, pady=2)
        
        # Executive summary frame
        summary_frame = ttk.LabelFrame(self.report_tab, text="Executive Summary الملخص التنفيذي", padding="10")
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, height=6, width=80, wrap=tk.WORD)
        self.summary_text.pack(fill="both", expand=True)
        
        # Report format frame
        format_frame = ttk.LabelFrame(self.report_tab, text="Report Format تنسيق التقرير", padding="10")
        
        self.report_format_var = tk.StringVar(value="docx")
        ttk.Radiobutton(format_frame, text="Word Document (.docx)", 
                       variable=self.report_format_var, value="docx").pack(side="left", padx=10)
        ttk.Radiobutton(format_frame, text="PDF Document (.pdf)", 
                       variable=self.report_format_var, value="pdf").pack(side="left", padx=10)
        ttk.Radiobutton(format_frame, text="JSON Data (.json)", 
                       variable=self.report_format_var, value="json").pack(side="left", padx=10)
        
        # Generate button
        ttk.Button(self.report_tab, text="Generate Report إنشاء التقرير", 
                  command=self.generate_report, style='Header.TLabel').grid(row=3, column=0, pady=10)
        
        # Layout report tab
        incident_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        summary_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        format_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        
        self.report_tab.columnconfigure(0, weight=1)
    
    def create_status_tab(self):
        """Create status monitoring tab."""
        self.status_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.status_tab, text="Status حالة النظام")
        
        # System status frame
        system_frame = ttk.LabelFrame(self.status_tab, text="System Status حالة النظام", padding="10")
        
        self.system_status_text = scrolledtext.ScrolledText(system_frame, height=15, width=80, wrap=tk.WORD)
        self.system_status_text.pack(fill="both", expand=True)
        
        # Refresh button
        ttk.Button(self.status_tab, text="Refresh Status تحديث الحالة", 
                  command=self.refresh_status).grid(row=1, column=0, pady=10)
        
        # Layout status tab
        system_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        self.status_tab.columnconfigure(0, weight=1)
        self.status_tab.rowconfigure(0, weight=1)
    
    def setup_layout(self):
        """Setup the main layout."""
        self.main_frame.pack(fill="both", expand=True)
        
        self.title_label.pack(pady=10)
        self.author_label.pack(pady=5)
        self.notebook.pack(fill="both", expand=True, pady=10)
        self.progress_bar.pack(fill="x", pady=5)
        self.status_label.pack(pady=2)
        self.output_text.pack(fill="both", expand=True, pady=5)
    
    def center_window(self):
        """Center the window on the screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def log_message(self, message: str, level: str = "INFO"):
        """Log message to output text area."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {level}: {message}\n"
        
        self.output_text.insert(tk.END, formatted_message)
        self.output_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_status(self, status: str):
        """Update status label."""
        self.status_var.set(status)
        self.root.update_idletasks()
    
    def update_progress(self, value: float):
        """Update progress bar."""
        self.progress_var.set(value)
        self.root.update_idletasks()
    
    def browse_ssh_key(self):
        """Browse for SSH key file."""
        filename = filedialog.askopenfilename(
            title="Select SSH Private Key",
            filetypes=[("All files", "*.*"), ("PEM files", "*.pem"), ("Key files", "*.key")]
        )
        if filename:
            self.log_key_path_var.set(filename)
    
    def browse_malware_file(self):
        """Browse for malware file."""
        filename = filedialog.askopenfilename(
            title="Select File to Analyze",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if filename:
            self.malware_path_var.set(filename)
    
    def browse_malware_dir(self):
        """Browse for malware directory."""
        dirname = filedialog.askdirectory(title="Select Directory to Analyze")
        if dirname:
            self.malware_path_var.set(dirname)
    
    def collect_logs(self):
        """Handle log collection in a separate thread."""
        def collect_logs_thread():
            try:
                self.update_status("Collecting logs...")
                self.update_progress(10)
                self.log_message("Starting log collection...")
                
                # Get log types
                log_types = []
                if self.log_system_var.get():
                    log_types.append('system')
                if self.log_security_var.get():
                    log_types.append('security')
                if self.log_application_var.get():
                    log_types.append('application')
                
                self.update_progress(30)
                
                # Collect logs
                if self.log_connection_var.get() == "remote":
                    host = self.log_host_var.get()
                    username = self.log_username_var.get()
                    password = self.log_password_var.get() if self.log_password_var.get() else None
                    key_path = self.log_key_path_var.get() if self.log_key_path_var.get() else None
                    
                    if not host or not username:
                        messagebox.showerror("Error", "Host and username are required for remote collection")
                        return
                    
                    collected_logs = self.log_collector.collect_remote_logs(
                        host=host,
                        username=username,
                        password=password,
                        key_path=key_path,
                        log_types=log_types
                    )
                else:
                    collected_logs = self.log_collector.collect_local_logs(log_types=log_types)
                
                self.update_progress(70)
                
                if collected_logs:
                    self.log_message(f"Successfully collected {len(collected_logs)} log types")
                    for log_type, file_path in collected_logs.items():
                        self.log_message(f"  {log_type}: {file_path}")
                    
                    # Analyze if requested
                    if self.log_analyze_var.get():
                        self.log_message("Analyzing collected logs...")
                        self.update_progress(80)
                        
                        keywords = None
                        if self.log_keywords_var.get():
                            keywords = [k.strip() for k in self.log_keywords_var.get().split(',')]
                        
                        analysis_results = self.log_collector.analyze_logs(collected_logs, keywords)
                        
                        for log_type, suspicious_entries in analysis_results.items():
                            if suspicious_entries:
                                self.log_message(f"Found {len(suspicious_entries)} suspicious entries in {log_type} logs", "WARNING")
                            else:
                                self.log_message(f"No suspicious entries found in {log_type} logs", "SUCCESS")
                    
                    self.operation_results['log_collection'] = {
                        'collected_logs': collected_logs,
                        'analysis_results': analysis_results if self.log_analyze_var.get() else None
                    }
                    
                    self.update_progress(100)
                    self.update_status("Log collection completed")
                    messagebox.showinfo("Success", "Log collection completed successfully!")
                else:
                    self.log_message("No logs were collected", "ERROR")
                    messagebox.showerror("Error", "Log collection failed")
                
            except Exception as e:
                self.log_message(f"Log collection error: {str(e)}", "ERROR")
                messagebox.showerror("Error", f"Log collection failed: {str(e)}")
            finally:
                self.update_progress(0)
                self.update_status("Ready")
        
        # Run in separate thread to prevent GUI freezing
        threading.Thread(target=collect_logs_thread, daemon=True).start()
    
    def apply_isolation(self):
        """Handle network isolation in a separate thread."""
        def isolate_thread():
            try:
                self.update_status("Applying network isolation...")
                self.update_progress(20)
                self.log_message("Starting network isolation...")
                
                central_server = self.central_server_var.get()
                if not central_server:
                    messagebox.showerror("Error", "Central server IP is required")
                    return
                
                # Parse allowed ports
                allowed_ports = []
                if self.allowed_ports_var.get():
                    try:
                        allowed_ports = [int(p.strip()) for p in self.allowed_ports_var.get().split(',')]
                    except ValueError:
                        messagebox.showerror("Error", "Invalid port format. Use comma-separated numbers.")
                        return
                
                self.update_progress(50)
                
                # Apply isolation
                if self.net_connection_var.get() == "remote":
                    host = self.net_host_var.get()
                    username = self.net_username_var.get()
                    password = self.net_password_var.get() if self.net_password_var.get() else None
                    
                    if not host or not username:
                        messagebox.showerror("Error", "Host and username are required for remote isolation")
                        return
                    
                    success = self.network_isolator.isolate_remote_system(
                        host=host,
                        username=username,
                        password=password,
                        central_server_ip=central_server,
                        allowed_ports=allowed_ports
                    )
                else:
                    success = self.network_isolator.isolate_local_system(
                        central_server_ip=central_server,
                        allowed_ports=allowed_ports
                    )
                
                self.update_progress(100)
                
                if success:
                    self.log_message("Network isolation applied successfully", "SUCCESS")
                    self.update_status("System isolated")
                    messagebox.showinfo("Success", "Network isolation applied successfully!")
                else:
                    self.log_message("Network isolation failed", "ERROR")
                    messagebox.showerror("Error", "Network isolation failed")
                
            except Exception as e:
                self.log_message(f"Network isolation error: {str(e)}", "ERROR")
                messagebox.showerror("Error", f"Network isolation failed: {str(e)}")
            finally:
                self.update_progress(0)
                if not success:
                    self.update_status("Ready")
        
        threading.Thread(target=isolate_thread, daemon=True).start()
    
    def restore_access(self):
        """Handle network access restoration in a separate thread."""
        def restore_thread():
            try:
                self.update_status("Restoring network access...")
                self.update_progress(50)
                self.log_message("Restoring network access...")
                
                # Restore access
                if self.net_connection_var.get() == "remote":
                    host = self.net_host_var.get()
                    username = self.net_username_var.get()
                    password = self.net_password_var.get() if self.net_password_var.get() else None
                    
                    success = self.network_isolator.restore_network_access(
                        host=host,
                        username=username,
                        password=password
                    )
                else:
                    success = self.network_isolator.restore_network_access()
                
                self.update_progress(100)
                
                if success:
                    self.log_message("Network access restored successfully", "SUCCESS")
                    self.update_status("Ready")
                    messagebox.showinfo("Success", "Network access restored successfully!")
                else:
                    self.log_message("Network restoration failed", "ERROR")
                    messagebox.showerror("Error", "Network restoration failed")
                
            except Exception as e:
                self.log_message(f"Network restoration error: {str(e)}", "ERROR")
                messagebox.showerror("Error", f"Network restoration failed: {str(e)}")
            finally:
                self.update_progress(0)
                if success:
                    self.update_status("Ready")
        
        threading.Thread(target=restore_thread, daemon=True).start()
    
    def analyze_malware(self):
        """Handle malware analysis in a separate thread."""
        def analyze_thread():
            try:
                self.update_status("Analyzing malware...")
                self.update_progress(10)
                self.log_message("Starting malware analysis...")
                
                file_path = self.malware_path_var.get()
                if not file_path or not os.path.exists(file_path):
                    messagebox.showerror("Error", "Please select a valid file or directory")
                    return
                
                # Clear previous results
                for item in self.results_tree.get_children():
                    self.results_tree.delete(item)
                
                self.update_progress(30)
                
                # Get file extensions
                extensions = [ext.strip() for ext in self.file_extensions_var.get().split(',')]
                
                # Analyze
                if os.path.isfile(file_path):
                    analysis_result = self.malware_analyzer.analyze_file(
                        file_path,
                        deep_analysis=self.deep_analysis_var.get()
                    )
                    
                    if analysis_result:
                        self.update_progress(80)
                        self._add_analysis_result_to_tree(analysis_result)
                        self.log_message(f"Analysis completed for {os.path.basename(file_path)}")
                    
                elif os.path.isdir(file_path):
                    analysis_results = self.malware_analyzer.analyze_directory(
                        file_path,
                        file_extensions=extensions
                    )
                    
                    if analysis_results:
                        self.update_progress(80)
                        for result in analysis_results:
                            self._add_analysis_result_to_tree(result)
                        
                        self.log_message(f"Analysis completed for {len(analysis_results)} files")
                        
                        # Generate summary
                        summary = self.malware_analyzer.generate_summary_report(analysis_results)
                        self.log_message(f"Summary: {summary.get('total_files_analyzed', 0)} files analyzed")
                        self.log_message(f"High risk: {len(summary.get('high_risk_files', []))}, " +
                                       f"Medium risk: {len(summary.get('medium_risk_files', []))}, " +
                                       f"Low risk: {len(summary.get('low_risk_files', []))}")
                
                self.update_progress(100)
                self.update_status("Malware analysis completed")
                messagebox.showinfo("Success", "Malware analysis completed successfully!")
                
            except Exception as e:
                self.log_message(f"Malware analysis error: {str(e)}", "ERROR")
                messagebox.showerror("Error", f"Malware analysis failed: {str(e)}")
            finally:
                self.update_progress(0)
                self.update_status("Ready")
        
        threading.Thread(target=analyze_thread, daemon=True).start()
    
    def _add_analysis_result_to_tree(self, result: Dict[str, Any]):
        """Add analysis result to the results tree."""
        file_name = result.get('file_name', 'Unknown')
        risk_score = result.get('risk_score', 0)
        threat_type = result.get('threat_classification', {}).get('threat_type', 'Unknown')
        
        # Determine status based on risk score
        if risk_score >= 70:
            status = "HIGH RISK"
        elif risk_score >= 40:
            status = "MEDIUM RISK"
        else:
            status = "LOW RISK"
        
        self.results_tree.insert("", "end", values=(file_name, f"{risk_score}/100", threat_type, status))
    
    def generate_report(self):
        """Handle report generation in a separate thread."""
        def generate_thread():
            try:
                self.update_status("Generating report...")
                self.update_progress(20)
                self.log_message("Starting report generation...")
                
                # Create incident data
                incident_data = self.report_generator.create_incident_template()
                
                # Fill in form data
                incident_data['incident_id'] = self.incident_id_var.get() or f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                incident_data['incident_type'] = self.incident_type_var.get()
                incident_data['severity'] = self.severity_var.get()
                incident_data['status'] = self.status_combo_var.get()
                incident_data['executive_summary'] = self.summary_text.get("1.0", tk.END).strip()
                incident_data['discovery_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Add data from previous operations
                if 'log_collection' in self.operation_results:
                    incident_data['log_analysis'] = self.operation_results['log_collection'].get('analysis_results', {})
                
                self.update_progress(60)
                
                # Generate report
                report_file = self.report_generator.generate_incident_report(
                    incident_data=incident_data,
                    format_type=self.report_format_var.get()
                )
                
                self.update_progress(100)
                
                if report_file and os.path.exists(report_file):
                    self.log_message(f"Report generated successfully: {report_file}", "SUCCESS")
                    self.update_status("Report generated")
                    messagebox.showinfo("Success", f"Report generated successfully!\n\nFile: {report_file}")
                else:
                    self.log_message("Report generation failed", "ERROR")
                    messagebox.showerror("Error", "Report generation failed")
                
            except Exception as e:
                self.log_message(f"Report generation error: {str(e)}", "ERROR")
                messagebox.showerror("Error", f"Report generation failed: {str(e)}")
            finally:
                self.update_progress(0)
                self.update_status("Ready")
        
        threading.Thread(target=generate_thread, daemon=True).start()
    
    def refresh_status(self):
        """Refresh system status display."""
        try:
            self.system_status_text.delete("1.0", tk.END)
            
            status_info = []
            status_info.append("=== Al-Mirsad System Status ===\n")
            status_info.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Network isolation status
            isolation_status = self.network_isolator.get_isolation_status()
            status_info.append("Network Isolation Status:\n")
            if isolation_status:
                status_info.append("  STATUS: ACTIVE (System is isolated)\n")
                for system, rule in isolation_status.items():
                    status_info.append(f"  {system}: {rule}\n")
            else:
                status_info.append("  STATUS: INACTIVE (Normal network access)\n")
            
            status_info.append("\n")
            
            # Output directories status
            directories = [
                ('Log Collection Output', self.log_collector.output_dir),
                ('Malware Analysis Output', self.malware_analyzer.output_dir),
                ('Report Generation Output', self.report_generator.output_dir)
            ]
            
            status_info.append("Output Directories:\n")
            for name, path in directories:
                if os.path.exists(path):
                    file_count = len([f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))])
                    status_info.append(f"  {name}: {path} ({file_count} files)\n")
                else:
                    status_info.append(f"  {name}: {path} (not created yet)\n")
            
            status_info.append("\n")
            
            # Recent operations
            status_info.append("Recent Operations:\n")
            if self.operation_results:
                for operation, results in self.operation_results.items():
                    status_info.append(f"  {operation}: Completed\n")
            else:
                status_info.append("  No operations performed yet\n")
            
            # Display status
            self.system_status_text.insert("1.0", "".join(status_info))
            self.log_message("System status refreshed")
            
        except Exception as e:
            self.log_message(f"Error refreshing status: {str(e)}", "ERROR")
    
    def run(self):
        """Run the GUI application."""
        # Initial status refresh
        self.refresh_status()
        
        # Start the main loop
        self.root.mainloop()


def main():
    """Main entry point for the GUI."""
    try:
        app = AlMirsadGUI()
        app.run()
    except Exception as e:
        print(f"Error starting GUI: {str(e)}")
        return 1
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
