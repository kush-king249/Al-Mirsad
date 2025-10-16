#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Isolation Module for Al-Mirsad
وحدة عزل الشبكة لأداة المرصاد

This module handles network isolation of infected systems by modifying firewall rules.
تتعامل هذه الوحدة مع عزل الأنظمة المصابة عن الشبكة عبر تعديل قواعد جدار الحماية.
"""

import os
import logging
import subprocess
import platform
from typing import Dict, List, Optional, Tuple
import paramiko
from paramiko import SSHClient, AutoAddPolicy


class NetworkIsolator:
    """
    Network isolation class for quarantining infected systems.
    فئة عزل الشبكة لحجر الأنظمة المصابة.
    """
    
    def __init__(self):
        """Initialize the NetworkIsolator."""
        self.logger = self._setup_logger()
        self.isolation_rules = {}  # Track applied isolation rules
    
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
    
    def isolate_local_system(self, central_server_ip: str, 
                           allowed_ports: List[int] = None) -> bool:
        """
        Isolate the local system from the network.
        عزل النظام المحلي عن الشبكة.
        
        Args:
            central_server_ip (str): IP address of the central management server
            allowed_ports (List[int]): Ports to keep open for communication
            
        Returns:
            bool: True if isolation was successful, False otherwise
        """
        if allowed_ports is None:
            allowed_ports = [22, 443, 80]  # SSH, HTTPS, HTTP
        
        system_type = platform.system().lower()
        
        try:
            if system_type == 'windows':
                return self._isolate_windows_system(central_server_ip, allowed_ports)
            elif system_type in ['linux', 'darwin']:
                return self._isolate_unix_system(central_server_ip, allowed_ports)
            else:
                self.logger.error(f"Unsupported system type: {system_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error isolating local system: {str(e)}")
            return False
    
    def isolate_remote_system(self, host: str, username: str, password: str = None,
                            key_path: str = None, central_server_ip: str = None,
                            allowed_ports: List[int] = None, port: int = 22) -> bool:
        """
        Isolate a remote system via SSH.
        عزل نظام بعيد عبر SSH.
        
        Args:
            host (str): Remote host IP or hostname
            username (str): SSH username
            password (str): SSH password (optional if using key)
            key_path (str): Path to SSH private key (optional)
            central_server_ip (str): IP address of the central management server
            allowed_ports (List[int]): Ports to keep open for communication
            port (int): SSH port (default: 22)
            
        Returns:
            bool: True if isolation was successful, False otherwise
        """
        if allowed_ports is None:
            allowed_ports = [22, 443, 80]
        
        if central_server_ip is None:
            central_server_ip = self._get_local_ip()
        
        try:
            # Establish SSH connection
            ssh_client = self._create_ssh_connection(host, username, password, key_path, port)
            
            # Detect remote system type
            stdin, stdout, stderr = ssh_client.exec_command('uname -s')
            system_type = stdout.read().decode().strip().lower()
            
            self.logger.info(f"Isolating remote system {host} ({system_type})")
            
            success = False
            if system_type == 'linux':
                success = self._isolate_remote_linux_system(
                    ssh_client, host, central_server_ip, allowed_ports
                )
            else:
                self.logger.warning(f"Remote system type {system_type} not fully supported")
            
            ssh_client.close()
            return success
            
        except Exception as e:
            self.logger.error(f"Error isolating remote system {host}: {str(e)}")
            return False
    
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
    
    def _isolate_windows_system(self, central_server_ip: str, 
                              allowed_ports: List[int]) -> bool:
        """Isolate Windows system using netsh firewall commands."""
        try:
            # Create isolation rule name
            rule_name = "Al-Mirsad-Isolation"
            
            # Block all outbound traffic first
            cmd_block_out = f'netsh advfirewall firewall add rule name="{rule_name}-BlockOut" dir=out action=block'
            result = subprocess.run(cmd_block_out, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.logger.error(f"Failed to block outbound traffic: {result.stderr}")
                return False
            
            # Block all inbound traffic
            cmd_block_in = f'netsh advfirewall firewall add rule name="{rule_name}-BlockIn" dir=in action=block'
            result = subprocess.run(cmd_block_in, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.logger.error(f"Failed to block inbound traffic: {result.stderr}")
                return False
            
            # Allow communication with central server
            for port in allowed_ports:
                # Allow outbound to central server
                cmd_allow_out = (f'netsh advfirewall firewall add rule name="{rule_name}-AllowOut-{port}" '
                               f'dir=out action=allow protocol=TCP remoteip={central_server_ip} localport={port}')
                subprocess.run(cmd_allow_out, shell=True, capture_output=True, text=True)
                
                # Allow inbound from central server
                cmd_allow_in = (f'netsh advfirewall firewall add rule name="{rule_name}-AllowIn-{port}" '
                              f'dir=in action=allow protocol=TCP remoteip={central_server_ip} localport={port}')
                subprocess.run(cmd_allow_in, shell=True, capture_output=True, text=True)
            
            self.isolation_rules['windows'] = rule_name
            self.logger.info("Windows system isolated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error isolating Windows system: {str(e)}")
            return False
    
    def _isolate_unix_system(self, central_server_ip: str, 
                           allowed_ports: List[int]) -> bool:
        """Isolate Unix/Linux system using iptables."""
        try:
            # Save current iptables rules
            backup_cmd = "iptables-save > /tmp/al-mirsad-iptables-backup"
            subprocess.run(backup_cmd, shell=True, capture_output=True, text=True)
            
            # Flush existing rules
            subprocess.run("iptables -F", shell=True, capture_output=True, text=True)
            subprocess.run("iptables -X", shell=True, capture_output=True, text=True)
            
            # Set default policies to DROP
            subprocess.run("iptables -P INPUT DROP", shell=True, capture_output=True, text=True)
            subprocess.run("iptables -P FORWARD DROP", shell=True, capture_output=True, text=True)
            subprocess.run("iptables -P OUTPUT DROP", shell=True, capture_output=True, text=True)
            
            # Allow loopback traffic
            subprocess.run("iptables -A INPUT -i lo -j ACCEPT", shell=True, capture_output=True, text=True)
            subprocess.run("iptables -A OUTPUT -o lo -j ACCEPT", shell=True, capture_output=True, text=True)
            
            # Allow communication with central server
            for port in allowed_ports:
                # Allow outbound to central server
                cmd_out = f"iptables -A OUTPUT -d {central_server_ip} -p tcp --dport {port} -j ACCEPT"
                subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
                
                # Allow inbound from central server
                cmd_in = f"iptables -A INPUT -s {central_server_ip} -p tcp --sport {port} -j ACCEPT"
                subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
                
                # Allow established connections
                subprocess.run("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT", 
                             shell=True, capture_output=True, text=True)
            
            self.isolation_rules['unix'] = '/tmp/al-mirsad-iptables-backup'
            self.logger.info("Unix system isolated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error isolating Unix system: {str(e)}")
            return False
    
    def _isolate_remote_linux_system(self, ssh_client: SSHClient, host: str,
                                   central_server_ip: str, allowed_ports: List[int]) -> bool:
        """Isolate remote Linux system via SSH."""
        try:
            # Save current iptables rules
            stdin, stdout, stderr = ssh_client.exec_command("iptables-save > /tmp/al-mirsad-iptables-backup")
            
            # Flush existing rules
            ssh_client.exec_command("iptables -F")
            ssh_client.exec_command("iptables -X")
            
            # Set default policies to DROP
            ssh_client.exec_command("iptables -P INPUT DROP")
            ssh_client.exec_command("iptables -P FORWARD DROP")
            ssh_client.exec_command("iptables -P OUTPUT DROP")
            
            # Allow loopback traffic
            ssh_client.exec_command("iptables -A INPUT -i lo -j ACCEPT")
            ssh_client.exec_command("iptables -A OUTPUT -o lo -j ACCEPT")
            
            # Allow communication with central server
            for port in allowed_ports:
                # Allow outbound to central server
                cmd_out = f"iptables -A OUTPUT -d {central_server_ip} -p tcp --dport {port} -j ACCEPT"
                ssh_client.exec_command(cmd_out)
                
                # Allow inbound from central server
                cmd_in = f"iptables -A INPUT -s {central_server_ip} -p tcp --sport {port} -j ACCEPT"
                ssh_client.exec_command(cmd_in)
            
            # Allow established connections
            ssh_client.exec_command("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
            
            self.isolation_rules[host] = '/tmp/al-mirsad-iptables-backup'
            self.logger.info(f"Remote Linux system {host} isolated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error isolating remote Linux system {host}: {str(e)}")
            return False
    
    def restore_network_access(self, host: str = None, username: str = None,
                             password: str = None, key_path: str = None,
                             port: int = 22) -> bool:
        """
        Restore network access by removing isolation rules.
        استعادة الوصول للشبكة عبر إزالة قواعد العزل.
        
        Args:
            host (str): Remote host IP (None for local system)
            username (str): SSH username for remote system
            password (str): SSH password for remote system
            key_path (str): SSH key path for remote system
            port (int): SSH port for remote system
            
        Returns:
            bool: True if restoration was successful, False otherwise
        """
        try:
            if host is None:
                # Restore local system
                return self._restore_local_system()
            else:
                # Restore remote system
                return self._restore_remote_system(host, username, password, key_path, port)
                
        except Exception as e:
            self.logger.error(f"Error restoring network access: {str(e)}")
            return False
    
    def _restore_local_system(self) -> bool:
        """Restore local system network access."""
        system_type = platform.system().lower()
        
        try:
            if system_type == 'windows':
                return self._restore_windows_system()
            elif system_type in ['linux', 'darwin']:
                return self._restore_unix_system()
            else:
                self.logger.error(f"Unsupported system type: {system_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error restoring local system: {str(e)}")
            return False
    
    def _restore_windows_system(self) -> bool:
        """Restore Windows system by removing firewall rules."""
        try:
            if 'windows' in self.isolation_rules:
                rule_name = self.isolation_rules['windows']
                
                # Remove all Al-Mirsad isolation rules
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}" dir=out'
                subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}" dir=in'
                subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                # Remove specific port rules
                for direction in ['out', 'in']:
                    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}-Allow{direction.capitalize()}" dir={direction}'
                    subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                del self.isolation_rules['windows']
                self.logger.info("Windows system network access restored")
                return True
            else:
                self.logger.warning("No Windows isolation rules found to restore")
                return False
                
        except Exception as e:
            self.logger.error(f"Error restoring Windows system: {str(e)}")
            return False
    
    def _restore_unix_system(self) -> bool:
        """Restore Unix system by restoring iptables backup."""
        try:
            if 'unix' in self.isolation_rules:
                backup_file = self.isolation_rules['unix']
                
                if os.path.exists(backup_file):
                    cmd = f"iptables-restore < {backup_file}"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        os.remove(backup_file)
                        del self.isolation_rules['unix']
                        self.logger.info("Unix system network access restored")
                        return True
                    else:
                        self.logger.error(f"Failed to restore iptables: {result.stderr}")
                        return False
                else:
                    self.logger.error(f"Backup file not found: {backup_file}")
                    return False
            else:
                self.logger.warning("No Unix isolation rules found to restore")
                return False
                
        except Exception as e:
            self.logger.error(f"Error restoring Unix system: {str(e)}")
            return False
    
    def _restore_remote_system(self, host: str, username: str, password: str = None,
                             key_path: str = None, port: int = 22) -> bool:
        """Restore remote system network access."""
        try:
            ssh_client = self._create_ssh_connection(host, username, password, key_path, port)
            
            if host in self.isolation_rules:
                backup_file = self.isolation_rules[host]
                
                # Restore iptables from backup
                stdin, stdout, stderr = ssh_client.exec_command(f"iptables-restore < {backup_file}")
                
                # Remove backup file
                ssh_client.exec_command(f"rm -f {backup_file}")
                
                del self.isolation_rules[host]
                ssh_client.close()
                
                self.logger.info(f"Remote system {host} network access restored")
                return True
            else:
                self.logger.warning(f"No isolation rules found for {host}")
                ssh_client.close()
                return False
                
        except Exception as e:
            self.logger.error(f"Error restoring remote system {host}: {str(e)}")
            return False
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def get_isolation_status(self) -> Dict[str, str]:
        """
        Get current isolation status.
        الحصول على حالة العزل الحالية.
        
        Returns:
            Dict[str, str]: Dictionary of isolated systems and their status
        """
        return self.isolation_rules.copy()
