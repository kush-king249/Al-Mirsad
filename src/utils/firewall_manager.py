#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Firewall Management Module for Al-Mirsad
وحدة إدارة جدار الحماية لأداة المرصاد

This module handles firewall rule management for network isolation.
تتعامل هذه الوحدة مع إدارة قواعد جدار الحماية لعزل الشبكة.
"""

import os
import logging
import subprocess
import platform
import json
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime


class FirewallManager:
    """
    Firewall management class for handling firewall rules across different platforms.
    فئة إدارة جدار الحماية للتعامل مع قواعد جدار الحماية عبر منصات مختلفة.
    """
    
    def __init__(self, backup_dir: str = "firewall_backups"):
        """
        Initialize the FirewallManager.
        
        Args:
            backup_dir (str): Directory to store firewall rule backups
        """
        self.backup_dir = backup_dir
        self.logger = self._setup_logger()
        self.system_type = platform.system().lower()
        self._ensure_backup_dir()
        
        # Track applied rules for rollback
        self.applied_rules = {}
    
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
    
    def _ensure_backup_dir(self):
        """Ensure backup directory exists."""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
            self.logger.info(f"Created backup directory: {self.backup_dir}")
    
    def backup_current_rules(self, backup_name: str = None) -> str:
        """
        Backup current firewall rules.
        نسخ احتياطي لقواعد جدار الحماية الحالية.
        
        Args:
            backup_name (str): Name for the backup (optional)
            
        Returns:
            str: Path to backup file
        """
        if backup_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"firewall_backup_{timestamp}"
        
        backup_file = os.path.join(self.backup_dir, f"{backup_name}.json")
        
        try:
            if self.system_type == 'windows':
                rules = self._backup_windows_rules()
            elif self.system_type == 'linux':
                rules = self._backup_linux_rules()
            elif self.system_type == 'darwin':
                rules = self._backup_macos_rules()
            else:
                self.logger.error(f"Unsupported system type: {self.system_type}")
                return ""
            
            # Save backup to file
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'system_type': self.system_type,
                'rules': rules
            }
            
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Firewall rules backed up to: {backup_file}")
            return backup_file
            
        except Exception as e:
            self.logger.error(f"Error backing up firewall rules: {str(e)}")
            return ""
    
    def _backup_windows_rules(self) -> List[Dict[str, Any]]:
        """Backup Windows firewall rules."""
        rules = []
        
        try:
            # Export Windows Firewall rules
            cmd = 'netsh advfirewall export "temp_firewall_backup.wfw"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Read the exported file
                if os.path.exists("temp_firewall_backup.wfw"):
                    with open("temp_firewall_backup.wfw", 'rb') as f:
                        rules.append({
                            'type': 'windows_export',
                            'data': f.read().hex()  # Store as hex string
                        })
                    os.remove("temp_firewall_backup.wfw")
            
            # Also get text representation of rules
            cmd = 'netsh advfirewall firewall show rule name=all'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                rules.append({
                    'type': 'windows_text',
                    'data': result.stdout
                })
            
            self.logger.info("Windows firewall rules backed up")
            
        except Exception as e:
            self.logger.error(f"Error backing up Windows firewall rules: {str(e)}")
        
        return rules
    
    def _backup_linux_rules(self) -> List[Dict[str, Any]]:
        """Backup Linux iptables rules."""
        rules = []
        
        try:
            # Backup iptables rules
            cmd = 'iptables-save'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                rules.append({
                    'type': 'iptables',
                    'data': result.stdout
                })\n            \n            # Also try ip6tables if available\n            cmd = 'ip6tables-save'\n            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n            \n            if result.returncode == 0:\n                rules.append({\n                    'type': 'ip6tables',\n                    'data': result.stdout\n                })\n            \n            # Check for ufw if available\n            cmd = 'ufw status numbered'\n            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n            \n            if result.returncode == 0:\n                rules.append({\n                    'type': 'ufw',\n                    'data': result.stdout\n                })\n            \n            self.logger.info(\"Linux firewall rules backed up\")\n            \n        except Exception as e:\n            self.logger.error(f\"Error backing up Linux firewall rules: {str(e)}\")\n        \n        return rules\n    \n    def _backup_macos_rules(self) -> List[Dict[str, Any]]:\n        \"\"\"Backup macOS firewall rules.\"\"\"\n        rules = []\n        \n        try:\n            # Get pfctl rules\n            cmd = 'pfctl -sr'\n            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n            \n            if result.returncode == 0:\n                rules.append({\n                    'type': 'pfctl',\n                    'data': result.stdout\n                })\n            \n            # Get application firewall status\n            cmd = '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate'\n            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n            \n            if result.returncode == 0:\n                rules.append({\n                    'type': 'application_firewall',\n                    'data': result.stdout\n                })\n            \n            self.logger.info(\"macOS firewall rules backed up\")\n            \n        except Exception as e:\n            self.logger.error(f\"Error backing up macOS firewall rules: {str(e)}\")\n        \n        return rules\n    \n    def restore_rules(self, backup_file: str) -> bool:\n        \"\"\"\n        Restore firewall rules from backup.\n        استعادة قواعد جدار الحماية من النسخة الاحتياطية.\n        \n        Args:\n            backup_file (str): Path to backup file\n            \n        Returns:\n            bool: True if restoration was successful, False otherwise\n        \"\"\"\n        try:\n            if not os.path.exists(backup_file):\n                self.logger.error(f\"Backup file not found: {backup_file}\")\n                return False\n            \n            with open(backup_file, 'r', encoding='utf-8') as f:\n                backup_data = json.load(f)\n            \n            rules = backup_data.get('rules', [])\n            system_type = backup_data.get('system_type', '')\n            \n            if system_type != self.system_type:\n                self.logger.error(f\"Backup is for {system_type}, current system is {self.system_type}\")\n                return False\n            \n            if self.system_type == 'windows':\n                return self._restore_windows_rules(rules)\n            elif self.system_type == 'linux':\n                return self._restore_linux_rules(rules)\n            elif self.system_type == 'darwin':\n                return self._restore_macos_rules(rules)\n            else:\n                self.logger.error(f\"Unsupported system type: {self.system_type}\")\n                return False\n                \n        except Exception as e:\n            self.logger.error(f\"Error restoring firewall rules: {str(e)}\")\n            return False\n    \n    def _restore_windows_rules(self, rules: List[Dict[str, Any]]) -> bool:\n        \"\"\"Restore Windows firewall rules.\"\"\"\n        try:\n            for rule in rules:\n                if rule['type'] == 'windows_export':\n                    # Restore from exported file\n                    temp_file = \"temp_restore.wfw\"\n                    \n                    with open(temp_file, 'wb') as f:\n                        f.write(bytes.fromhex(rule['data']))\n                    \n                    cmd = f'netsh advfirewall import \"{temp_file}\"'\n                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n                    \n                    os.remove(temp_file)\n                    \n                    if result.returncode == 0:\n                        self.logger.info(\"Windows firewall rules restored\")\n                        return True\n                    else:\n                        self.logger.error(f\"Failed to restore Windows rules: {result.stderr}\")\n            \n            return False\n            \n        except Exception as e:\n            self.logger.error(f\"Error restoring Windows firewall rules: {str(e)}\")\n            return False\n    \n    def _restore_linux_rules(self, rules: List[Dict[str, Any]]) -> bool:\n        \"\"\"Restore Linux iptables rules.\"\"\"\n        try:\n            for rule in rules:\n                if rule['type'] == 'iptables':\n                    # Restore iptables rules\n                    temp_file = \"/tmp/iptables_restore.rules\"\n                    \n                    with open(temp_file, 'w') as f:\n                        f.write(rule['data'])\n                    \n                    cmd = f'iptables-restore < {temp_file}'\n                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n                    \n                    os.remove(temp_file)\n                    \n                    if result.returncode == 0:\n                        self.logger.info(\"iptables rules restored\")\n                    else:\n                        self.logger.error(f\"Failed to restore iptables rules: {result.stderr}\")\n                \n                elif rule['type'] == 'ip6tables':\n                    # Restore ip6tables rules\n                    temp_file = \"/tmp/ip6tables_restore.rules\"\n                    \n                    with open(temp_file, 'w') as f:\n                        f.write(rule['data'])\n                    \n                    cmd = f'ip6tables-restore < {temp_file}'\n                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n                    \n                    os.remove(temp_file)\n                    \n                    if result.returncode == 0:\n                        self.logger.info(\"ip6tables rules restored\")\n                    else:\n                        self.logger.error(f\"Failed to restore ip6tables rules: {result.stderr}\")\n            \n            return True\n            \n        except Exception as e:\n            self.logger.error(f\"Error restoring Linux firewall rules: {str(e)}\")\n            return False\n    \n    def _restore_macos_rules(self, rules: List[Dict[str, Any]]) -> bool:\n        \"\"\"Restore macOS firewall rules.\"\"\"\n        try:\n            # Note: macOS firewall restoration is complex and may require manual intervention\n            self.logger.warning(\"macOS firewall restoration requires manual configuration\")\n            \n            for rule in rules:\n                if rule['type'] == 'pfctl':\n                    self.logger.info(\"pfctl rules available for manual restoration:\")\n                    self.logger.info(rule['data'])\n                elif rule['type'] == 'application_firewall':\n                    self.logger.info(\"Application firewall state:\")\n                    self.logger.info(rule['data'])\n            \n            return True\n            \n        except Exception as e:\n            self.logger.error(f\"Error restoring macOS firewall rules: {str(e)}\")\n            return False\n    \n    def add_isolation_rules(self, central_server_ip: str, \n                          allowed_ports: List[int] = None,\n                          rule_name: str = \"Al-Mirsad-Isolation\") -> bool:\n        \"\"\"\n        Add network isolation rules.\n        إضافة قواعد عزل الشبكة.\n        \n        Args:\n            central_server_ip (str): IP address of the central management server\n            allowed_ports (List[int]): Ports to keep open for communication\n            rule_name (str): Name for the isolation rules\n            \n        Returns:\n            bool: True if rules were added successfully, False otherwise\n        \"\"\"\n        if allowed_ports is None:\n            allowed_ports = [22, 443, 80]  # SSH, HTTPS, HTTP\n        \n        try:\n            # Backup current rules first\n            backup_file = self.backup_current_rules(f\"{rule_name}_backup\")\n            \n            if self.system_type == 'windows':\n                success = self._add_windows_isolation_rules(central_server_ip, allowed_ports, rule_name)\n            elif self.system_type == 'linux':\n                success = self._add_linux_isolation_rules(central_server_ip, allowed_ports, rule_name)\n            elif self.system_type == 'darwin':\n                success = self._add_macos_isolation_rules(central_server_ip, allowed_ports, rule_name)\n            else:\n                self.logger.error(f\"Unsupported system type: {self.system_type}\")\n                return False\n            \n            if success:\n                self.applied_rules[rule_name] = {\n                    'backup_file': backup_file,\n                    'central_server_ip': central_server_ip,\n                    'allowed_ports': allowed_ports,\n                    'timestamp': datetime.now().isoformat()\n                }\n                self.logger.info(f\"Isolation rules '{rule_name}' applied successfully\")\n            \n            return success\n            \n        except Exception as e:\n            self.logger.error(f\"Error adding isolation rules: {str(e)}\")\n            return False\n    \n    def _add_windows_isolation_rules(self, central_server_ip: str, \n                                   allowed_ports: List[int], rule_name: str) -> bool:\n        \"\"\"Add Windows isolation rules.\"\"\"\n        try:\n            # Block all outbound traffic\n            cmd = f'netsh advfirewall firewall add rule name=\"{rule_name}-BlockOut\" dir=out action=block'\n            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n            \n            if result.returncode != 0:\n                self.logger.error(f\"Failed to add outbound block rule: {result.stderr}\")\n                return False\n            \n            # Block all inbound traffic\n            cmd = f'netsh advfirewall firewall add rule name=\"{rule_name}-BlockIn\" dir=in action=block'\n            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n            \n            if result.returncode != 0:\n                self.logger.error(f\"Failed to add inbound block rule: {result.stderr}\")\n                return False\n            \n            # Allow communication with central server\n            for port in allowed_ports:\n                # Allow outbound to central server\n                cmd = (f'netsh advfirewall firewall add rule name=\"{rule_name}-AllowOut-{port}\" '\n                      f'dir=out action=allow protocol=TCP remoteip={central_server_ip} localport={port}')\n                subprocess.run(cmd, shell=True, capture_output=True, text=True)\n                \n                # Allow inbound from central server\n                cmd = (f'netsh advfirewall firewall add rule name=\"{rule_name}-AllowIn-{port}\" '\n                      f'dir=in action=allow protocol=TCP remoteip={central_server_ip} localport={port}')\n                subprocess.run(cmd, shell=True, capture_output=True, text=True)\n            \n            self.logger.info(\"Windows isolation rules added\")\n            return True\n            \n        except Exception as e:\n            self.logger.error(f\"Error adding Windows isolation rules: {str(e)}\")\n            return False\n    \n    def _add_linux_isolation_rules(self, central_server_ip: str, \n                                 allowed_ports: List[int], rule_name: str) -> bool:\n        \"\"\"Add Linux iptables isolation rules.\"\"\"\n        try:\n            # Flush existing rules (backup was already created)\n            subprocess.run(\"iptables -F\", shell=True, capture_output=True, text=True)\n            subprocess.run(\"iptables -X\", shell=True, capture_output=True, text=True)\n            \n            # Set default policies to DROP\n            subprocess.run(\"iptables -P INPUT DROP\", shell=True, capture_output=True, text=True)\n            subprocess.run(\"iptables -P FORWARD DROP\", shell=True, capture_output=True, text=True)\n            subprocess.run(\"iptables -P OUTPUT DROP\", shell=True, capture_output=True, text=True)\n            \n            # Allow loopback traffic\n            subprocess.run(\"iptables -A INPUT -i lo -j ACCEPT\", shell=True, capture_output=True, text=True)\n            subprocess.run(\"iptables -A OUTPUT -o lo -j ACCEPT\", shell=True, capture_output=True, text=True)\n            \n            # Allow communication with central server\n            for port in allowed_ports:\n                # Allow outbound to central server\n                cmd = f\"iptables -A OUTPUT -d {central_server_ip} -p tcp --dport {port} -j ACCEPT\"\n                subprocess.run(cmd, shell=True, capture_output=True, text=True)\n                \n                # Allow inbound from central server\n                cmd = f\"iptables -A INPUT -s {central_server_ip} -p tcp --sport {port} -j ACCEPT\"\n                subprocess.run(cmd, shell=True, capture_output=True, text=True)\n            \n            # Allow established connections\n            subprocess.run(\"iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\", \n                         shell=True, capture_output=True, text=True)\n            \n            self.logger.info(\"Linux isolation rules added\")\n            return True\n            \n        except Exception as e:\n            self.logger.error(f\"Error adding Linux isolation rules: {str(e)}\")\n            return False\n    \n    def _add_macos_isolation_rules(self, central_server_ip: str, \n                                 allowed_ports: List[int], rule_name: str) -> bool:\n        \"\"\"Add macOS isolation rules.\"\"\"\n        try:\n            # Note: macOS firewall configuration is complex and may require manual setup\n            self.logger.warning(\"macOS isolation requires manual firewall configuration\")\n            \n            # Enable application firewall\n            cmd = '/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'\n            subprocess.run(cmd, shell=True, capture_output=True, text=True)\n            \n            # Set to block all incoming connections\n            cmd = '/usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on'\n            subprocess.run(cmd, shell=True, capture_output=True, text=True)\n            \n            self.logger.info(\"macOS basic isolation enabled (manual configuration may be required)\")\n            return True\n            \n        except Exception as e:\n            self.logger.error(f\"Error adding macOS isolation rules: {str(e)}\")\n            return False\n    \n    def remove_isolation_rules(self, rule_name: str = \"Al-Mirsad-Isolation\") -> bool:\n        \"\"\"\n        Remove isolation rules and restore previous state.\n        إزالة قواعد العزل واستعادة الحالة السابقة.\n        \n        Args:\n            rule_name (str): Name of the isolation rules to remove\n            \n        Returns:\n            bool: True if rules were removed successfully, False otherwise\n        \"\"\"\n        try:\n            if rule_name not in self.applied_rules:\n                self.logger.warning(f\"No isolation rules found with name: {rule_name}\")\n                return False\n            \n            rule_info = self.applied_rules[rule_name]\n            backup_file = rule_info['backup_file']\n            \n            # Restore from backup\n            if os.path.exists(backup_file):\n                success = self.restore_rules(backup_file)\n                if success:\n                    del self.applied_rules[rule_name]\n                    self.logger.info(f\"Isolation rules '{rule_name}' removed and previous state restored\")\n                    return True\n                else:\n                    self.logger.error(f\"Failed to restore from backup: {backup_file}\")\n                    return False\n            else:\n                self.logger.error(f\"Backup file not found: {backup_file}\")\n                return False\n                \n        except Exception as e:\n            self.logger.error(f\"Error removing isolation rules: {str(e)}\")\n            return False\n    \n    def get_current_rules_status(self) -> Dict[str, Any]:\n        \"\"\"\n        Get current firewall rules status.\n        الحصول على حالة قواعد جدار الحماية الحالية.\n        \n        Returns:\n            Dict[str, Any]: Current rules status\n        \"\"\"\n        status = {\n            'system_type': self.system_type,\n            'applied_isolation_rules': list(self.applied_rules.keys()),\n            'backup_files': [],\n            'current_rules_summary': {}\n        }\n        \n        try:\n            # Get backup files\n            if os.path.exists(self.backup_dir):\n                status['backup_files'] = [\n                    f for f in os.listdir(self.backup_dir) \n                    if f.endswith('.json')\n                ]\n            \n            # Get current rules summary\n            if self.system_type == 'windows':\n                cmd = 'netsh advfirewall firewall show rule name=all | findstr \"Rule Name\"'\n                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n                if result.returncode == 0:\n                    rules = result.stdout.strip().split('\\n')\n                    status['current_rules_summary']['total_rules'] = len(rules)\n                    status['current_rules_summary']['sample_rules'] = rules[:5]\n            \n            elif self.system_type == 'linux':\n                cmd = 'iptables -L --line-numbers'\n                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n                if result.returncode == 0:\n                    status['current_rules_summary']['iptables'] = result.stdout\n            \n        except Exception as e:\n            self.logger.error(f\"Error getting rules status: {str(e)}\")\n        \n        return status\n    \n    def list_applied_rules(self) -> Dict[str, Dict[str, Any]]:\n        \"\"\"\n        List all currently applied isolation rules.\n        قائمة بجميع قواعد العزل المطبقة حالياً.\n        \n        Returns:\n            Dict[str, Dict[str, Any]]: Applied rules information\n        \"\"\"\n        return self.applied_rules.copy()"
