#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Log Collection Module for Al-Mirsad
وحدة جمع السجلات لأداة المرصاد

This module handles collecting system logs from remote hosts via SSH or local system.
تتعامل هذه الوحدة مع جمع سجلات النظام من المضيفات البعيدة عبر SSH أو النظام المحلي.
"""

import os
import datetime
import logging
import subprocess
import platform
from typing import Dict, List, Optional, Tuple
import paramiko
from paramiko import SSHClient, AutoAddPolicy


class LogCollector:
    """
    Log collection class for gathering system logs from local and remote systems.
    فئة جمع السجلات لجمع سجلات النظام من الأنظمة المحلية والبعيدة.
    """
    
    def __init__(self, output_dir: str = "collected_logs"):
        """
        Initialize the LogCollector.
        
        Args:
            output_dir (str): Directory to store collected logs
        """
        self.output_dir = output_dir
        self.logger = self._setup_logger()
        self._ensure_output_dir()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging for the module."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _ensure_output_dir(self):
        """Ensure output directory exists."""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            self.logger.info(f"Created output directory: {self.output_dir}")
    
    def collect_local_logs(self, log_types: List[str] = None) -> Dict[str, str]:
        """
        Collect logs from the local system.
        جمع السجلات من النظام المحلي.
        
        Args:
            log_types (List[str]): Types of logs to collect
            
        Returns:
            Dict[str, str]: Dictionary mapping log type to file path
        """
        if log_types is None:
            log_types = ['system', 'security', 'application']
        
        collected_logs = {}
        system_type = platform.system().lower()
        
        self.logger.info(f"Collecting local logs for {system_type} system")
        
        try:
            if system_type == 'windows':
                collected_logs = self._collect_windows_logs(log_types)
            elif system_type in ['linux', 'darwin']:
                collected_logs = self._collect_unix_logs(log_types)
            else:
                self.logger.warning(f"Unsupported system type: {system_type}")
                
        except Exception as e:
            self.logger.error(f"Error collecting local logs: {str(e)}")
            
        return collected_logs
    
    def collect_remote_logs(self, host: str, username: str, password: str = None,
                          key_path: str = None, log_types: List[str] = None,
                          port: int = 22) -> Dict[str, str]:
        """
        Collect logs from a remote system via SSH.
        جمع السجلات من نظام بعيد عبر SSH.
        
        Args:
            host (str): Remote host IP or hostname
            username (str): SSH username
            password (str): SSH password (optional if using key)
            key_path (str): Path to SSH private key (optional)
            log_types (List[str]): Types of logs to collect
            port (int): SSH port (default: 22)
            
        Returns:
            Dict[str, str]: Dictionary mapping log type to file path
        """
        if log_types is None:
            log_types = ['system', 'security', 'application']
        
        collected_logs = {}
        
        try:
            # Establish SSH connection
            ssh_client = self._create_ssh_connection(host, username, password, key_path, port)
            
            # Detect remote system type
            stdin, stdout, stderr = ssh_client.exec_command('uname -s')
            system_type = stdout.read().decode().strip().lower()
            
            self.logger.info(f"Collecting remote logs from {host} ({system_type})")
            
            if system_type == 'linux':
                collected_logs = self._collect_remote_linux_logs(ssh_client, host, log_types)
            else:
                self.logger.warning(f"Remote system type {system_type} not fully supported")
                
            ssh_client.close()
            
        except Exception as e:
            self.logger.error(f"Error collecting remote logs from {host}: {str(e)}")
            
        return collected_logs
    
    def _create_ssh_connection(self, host: str, username: str, password: str = None,
                             key_path: str = None, port: int = 22) -> SSHClient:
        """Create SSH connection to remote host."""
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            if key_path and os.path.exists(key_path):
                ssh_client.connect(host, port=port, username=username, key_filename=key_path)
            elif password:
                ssh_client.connect(host, port=port, username=username, password=password)
            else:
                raise ValueError("Either password or key_path must be provided")
                
            self.logger.info(f"SSH connection established to {host}")
            return ssh_client
            
        except Exception as e:
            self.logger.error(f"Failed to establish SSH connection to {host}: {str(e)}")
            raise
    
    def _collect_windows_logs(self, log_types: List[str]) -> Dict[str, str]:
        """Collect Windows event logs."""
        collected_logs = {}
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        log_mapping = {
            'system': 'System',
            'security': 'Security',
            'application': 'Application'
        }
        
        for log_type in log_types:
            if log_type in log_mapping:
                try:
                    output_file = os.path.join(
                        self.output_dir, 
                        f"windows_{log_type}_{timestamp}.evtx"
                    )
                    
                    # Use wevtutil to export Windows event logs
                    cmd = f'wevtutil epl {log_mapping[log_type]} "{output_file}"'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        collected_logs[log_type] = output_file
                        self.logger.info(f"Collected Windows {log_type} log to {output_file}")
                    else:
                        self.logger.error(f"Failed to collect Windows {log_type} log: {result.stderr}")
                        
                except Exception as e:
                    self.logger.error(f"Error collecting Windows {log_type} log: {str(e)}")
        
        return collected_logs
    
    def _collect_unix_logs(self, log_types: List[str]) -> Dict[str, str]:
        """Collect Unix/Linux system logs."""
        collected_logs = {}
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        log_paths = {
            'system': ['/var/log/syslog', '/var/log/messages'],
            'security': ['/var/log/auth.log', '/var/log/secure'],
            'application': ['/var/log/daemon.log', '/var/log/user.log']
        }
        
        for log_type in log_types:
            if log_type in log_paths:
                for log_path in log_paths[log_type]:
                    if os.path.exists(log_path):
                        try:
                            output_file = os.path.join(
                                self.output_dir,
                                f"unix_{log_type}_{timestamp}.log"
                            )
                            
                            # Copy log file
                            cmd = f'cp "{log_path}" "{output_file}"'
                            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                            
                            if result.returncode == 0:
                                collected_logs[log_type] = output_file
                                self.logger.info(f"Collected Unix {log_type} log to {output_file}")
                                break
                            else:
                                self.logger.warning(f"Failed to copy {log_path}: {result.stderr}")
                                
                        except Exception as e:
                            self.logger.error(f"Error collecting Unix {log_type} log: {str(e)}")
        
        return collected_logs
    
    def _collect_remote_linux_logs(self, ssh_client: SSHClient, host: str, 
                                 log_types: List[str]) -> Dict[str, str]:
        """Collect logs from remote Linux system."""
        collected_logs = {}
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        log_paths = {
            'system': ['/var/log/syslog', '/var/log/messages'],
            'security': ['/var/log/auth.log', '/var/log/secure'],
            'application': ['/var/log/daemon.log', '/var/log/user.log']
        }
        
        for log_type in log_types:
            if log_type in log_paths:
                for log_path in log_paths[log_type]:
                    try:
                        # Check if log file exists
                        stdin, stdout, stderr = ssh_client.exec_command(f'test -f {log_path} && echo "exists"')
                        if stdout.read().decode().strip() == "exists":
                            # Download the log file
                            output_file = os.path.join(
                                self.output_dir,
                                f"remote_{host}_{log_type}_{timestamp}.log"
                            )
                            
                            sftp = ssh_client.open_sftp()
                            sftp.get(log_path, output_file)
                            sftp.close()
                            
                            collected_logs[log_type] = output_file
                            self.logger.info(f"Downloaded {log_path} from {host} to {output_file}")
                            break
                            
                    except Exception as e:
                        self.logger.warning(f"Failed to download {log_path} from {host}: {str(e)}")
        
        return collected_logs
    
    def analyze_logs(self, log_files: Dict[str, str], keywords: List[str] = None) -> Dict[str, List[str]]:
        """
        Analyze collected logs for suspicious activities.
        تحليل السجلات المجمعة للأنشطة المشبوهة.
        
        Args:
            log_files (Dict[str, str]): Dictionary of log type to file path
            keywords (List[str]): Keywords to search for
            
        Returns:
            Dict[str, List[str]]: Dictionary of log type to list of suspicious entries
        """
        if keywords is None:
            keywords = [
                'failed', 'error', 'unauthorized', 'denied', 'attack',
                'malware', 'virus', 'trojan', 'suspicious', 'breach'
            ]
        
        analysis_results = {}
        
        for log_type, log_file in log_files.items():
            if os.path.exists(log_file):
                try:
                    suspicious_entries = []
                    
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            line_lower = line.lower()
                            for keyword in keywords:
                                if keyword.lower() in line_lower:
                                    suspicious_entries.append(f"Line {line_num}: {line.strip()}")
                                    break
                    
                    analysis_results[log_type] = suspicious_entries
                    self.logger.info(f"Analyzed {log_type} log: found {len(suspicious_entries)} suspicious entries")
                    
                except Exception as e:
                    self.logger.error(f"Error analyzing {log_type} log: {str(e)}")
                    analysis_results[log_type] = []
        
        return analysis_results
