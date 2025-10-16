#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main CLI Interface for Al-Mirsad
واجهة سطر الأوامر الرئيسية لأداة المرصاد

Command-line interface for Al-Mirsad incident response automation tool.
واجهة سطر الأوامر لأداة المرصاد لأتمتة الاستجابة للحوادث.
"""

import os
import sys
import argparse
import logging
import json
from typing import Dict, List, Optional, Any
import colorama
from colorama import Fore, Back, Style

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.log_collector import LogCollector
from core.network_isolator import NetworkIsolator
from core.malware_analyzer import MalwareAnalyzer
from core.report_generator import ReportGenerator


class AlMirsadCLI:
    """
    Main CLI class for Al-Mirsad incident response tool.
    فئة واجهة سطر الأوامر الرئيسية لأداة المرصاد للاستجابة للحوادث.
    """
    
    def __init__(self):
        """Initialize the CLI."""
        colorama.init(autoreset=True)
        self.logger = self._setup_logger()
        
        # Initialize core modules
        self.log_collector = LogCollector()
        self.network_isolator = NetworkIsolator()
        self.malware_analyzer = MalwareAnalyzer()
        self.report_generator = ReportGenerator()
        
        self.print_banner()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging for the CLI."""
        logger = logging.getLogger('al_mirsad_cli')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def print_banner(self):
        """Print the application banner."""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                        {Fore.YELLOW}Al-Mirsad المرصاد{Fore.CYAN}                         ║
║              {Fore.WHITE}Incident Response Automation Tool{Fore.CYAN}              ║
║                  {Fore.WHITE}أداة أتمتة الاستجابة للحوادث{Fore.CYAN}                  ║
║                                                              ║
║  {Fore.GREEN}Author: Hassan Mohamed Hassan Ahmed{Fore.CYAN}                    ║
║  {Fore.GREEN}GitHub: kush-king249{Fore.CYAN}                                   ║
║  {Fore.GREEN}Version: 1.0.0{Fore.CYAN}                                        ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def print_success(self, message: str):
        """Print success message."""
        print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")
    
    def print_error(self, message: str):
        """Print error message."""
        print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")
    
    def print_warning(self, message: str):
        """Print warning message."""
        print(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")
    
    def print_info(self, message: str):
        """Print info message."""
        print(f"{Fore.BLUE}ℹ {message}{Style.RESET_ALL}")
    
    def collect_logs_command(self, args):
        """Handle log collection command."""
        self.print_info("Starting log collection...")
        
        try:
            if args.remote:
                # Remote log collection
                if not args.host or not args.username:
                    self.print_error("Remote log collection requires --host and --username")
                    return False
                
                collected_logs = self.log_collector.collect_remote_logs(
                    host=args.host,
                    username=args.username,
                    password=args.password,
                    key_path=args.key_path,
                    log_types=args.log_types,
                    port=args.port
                )
            else:
                # Local log collection
                collected_logs = self.log_collector.collect_local_logs(
                    log_types=args.log_types
                )
            
            if collected_logs:
                self.print_success(f"Collected {len(collected_logs)} log types:")
                for log_type, file_path in collected_logs.items():
                    print(f"  {Fore.CYAN}{log_type}: {Fore.WHITE}{file_path}")
                
                # Analyze logs if requested
                if args.analyze:
                    self.print_info("Analyzing collected logs...")
                    analysis_results = self.log_collector.analyze_logs(
                        collected_logs, 
                        keywords=args.keywords
                    )
                    
                    for log_type, suspicious_entries in analysis_results.items():
                        if suspicious_entries:
                            self.print_warning(f"Found {len(suspicious_entries)} suspicious entries in {log_type} logs")
                            if args.verbose:
                                for entry in suspicious_entries[:5]:  # Show first 5
                                    print(f"    {entry}")
                        else:
                            self.print_success(f"No suspicious entries found in {log_type} logs")
                
                return True
            else:
                self.print_error("No logs were collected")
                return False
                
        except Exception as e:
            self.print_error(f"Log collection failed: {str(e)}")
            return False
    
    def isolate_network_command(self, args):
        """Handle network isolation command."""
        self.print_info("Starting network isolation...")
        
        try:
            if args.remote:
                # Remote network isolation
                if not args.host or not args.username:
                    self.print_error("Remote isolation requires --host and --username")
                    return False
                
                success = self.network_isolator.isolate_remote_system(
                    host=args.host,
                    username=args.username,
                    password=args.password,
                    key_path=args.key_path,
                    central_server_ip=args.central_server,
                    allowed_ports=args.allowed_ports,
                    port=args.port
                )
            else:
                # Local network isolation
                if not args.central_server:
                    self.print_error("Local isolation requires --central-server IP")
                    return False
                
                success = self.network_isolator.isolate_local_system(
                    central_server_ip=args.central_server,
                    allowed_ports=args.allowed_ports
                )
            
            if success:
                self.print_success("Network isolation applied successfully")
                self.print_warning("System is now isolated from the network")
                self.print_info("Use --restore option to remove isolation")
                return True
            else:
                self.print_error("Network isolation failed")
                return False
                
        except Exception as e:
            self.print_error(f"Network isolation failed: {str(e)}")
            return False
    
    def restore_network_command(self, args):
        """Handle network restoration command."""
        self.print_info("Restoring network access...")
        
        try:
            success = self.network_isolator.restore_network_access(
                host=args.host if args.remote else None,
                username=args.username,
                password=args.password,
                key_path=args.key_path,
                port=args.port
            )
            
            if success:
                self.print_success("Network access restored successfully")
                return True
            else:
                self.print_error("Network restoration failed")
                return False
                
        except Exception as e:
            self.print_error(f"Network restoration failed: {str(e)}")
            return False
    
    def analyze_malware_command(self, args):
        """Handle malware analysis command."""
        self.print_info(f"Starting malware analysis of: {args.file}")
        
        try:
            if not os.path.exists(args.file):
                self.print_error(f"File not found: {args.file}")
                return False
            
            # Analyze single file or directory
            if os.path.isfile(args.file):
                analysis_result = self.malware_analyzer.analyze_file(
                    args.file, 
                    deep_analysis=args.deep
                )
                
                if analysis_result:
                    self._display_analysis_result(analysis_result)
                    return True
                else:
                    self.print_error("Malware analysis failed")
                    return False
            
            elif os.path.isdir(args.file):
                analysis_results = self.malware_analyzer.analyze_directory(
                    args.file,
                    file_extensions=args.extensions
                )
                
                if analysis_results:
                    self.print_success(f"Analyzed {len(analysis_results)} files")
                    
                    # Generate summary
                    summary = self.malware_analyzer.generate_summary_report(analysis_results)
                    self._display_summary_report(summary)
                    
                    if args.verbose:
                        for result in analysis_results:
                            print(f"\n{Fore.CYAN}{'='*60}")
                            self._display_analysis_result(result)
                    
                    return True
                else:
                    self.print_error("No files were analyzed")
                    return False
            
        except Exception as e:
            self.print_error(f"Malware analysis failed: {str(e)}")
            return False
    
    def _display_analysis_result(self, result: Dict[str, Any]):
        """Display malware analysis result."""
        file_name = result.get('file_name', 'Unknown')
        risk_score = result.get('risk_score', 0)
        
        print(f"\n{Fore.CYAN}File: {Fore.WHITE}{file_name}")
        print(f"{Fore.CYAN}Size: {Fore.WHITE}{result.get('file_size', 0)} bytes")
        
        # Risk score with color coding
        if risk_score >= 70:
            color = Fore.RED
            risk_level = "HIGH"
        elif risk_score >= 40:
            color = Fore.YELLOW
            risk_level = "MEDIUM"
        else:
            color = Fore.GREEN
            risk_level = "LOW"
        
        print(f"{Fore.CYAN}Risk Score: {color}{risk_score}/100 ({risk_level})")
        
        # Threat classification
        threat = result.get('threat_classification', {})
        if threat.get('threat_type') != 'Unknown':
            print(f"{Fore.CYAN}Threat Type: {Fore.WHITE}{threat.get('threat_type')}")
            print(f"{Fore.CYAN}Confidence: {Fore.WHITE}{threat.get('confidence', 0):.2f}")
        
        # Hash information
        hashes = result.get('hash_analysis', {})
        if hashes:
            print(f"{Fore.CYAN}MD5: {Fore.WHITE}{hashes.get('md5', 'N/A')}")
            print(f"{Fore.CYAN}SHA256: {Fore.WHITE}{hashes.get('sha256', 'N/A')}")
        
        # Indicators
        indicators = threat.get('indicators', [])
        if indicators:
            print(f"{Fore.CYAN}Indicators:")
            for indicator in indicators[:5]:  # Show first 5
                print(f"  {Fore.YELLOW}• {indicator}")
    
    def _display_summary_report(self, summary: Dict[str, Any]):
        """Display malware analysis summary report."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}MALWARE ANALYSIS SUMMARY")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"{Fore.CYAN}Total Files Analyzed: {Fore.WHITE}{summary.get('total_files_analyzed', 0)}")
        print(f"{Fore.RED}High Risk Files: {Fore.WHITE}{len(summary.get('high_risk_files', []))}")
        print(f"{Fore.YELLOW}Medium Risk Files: {Fore.WHITE}{len(summary.get('medium_risk_files', []))}")
        print(f"{Fore.GREEN}Low Risk Files: {Fore.WHITE}{len(summary.get('low_risk_files', []))}")
        print(f"{Fore.CYAN}Average Risk Score: {Fore.WHITE}{summary.get('average_risk_score', 0):.1f}")
        
        # Threat types found
        threat_types = summary.get('threat_types_found', {})
        if threat_types:
            print(f"\n{Fore.CYAN}Threat Types Found:")
            for threat_type, count in threat_types.items():
                print(f"  {Fore.YELLOW}{threat_type}: {Fore.WHITE}{count}")
        
        # Recommendations
        recommendations = summary.get('recommendations', [])
        if recommendations:
            print(f"\n{Fore.CYAN}Recommendations:")
            for rec in recommendations:
                print(f"  {Fore.GREEN}• {rec}")
    
    def generate_report_command(self, args):
        """Handle report generation command."""
        self.print_info("Generating incident report...")
        
        try:
            # Create incident data structure
            incident_data = self._create_incident_data(args)
            
            # Generate report
            report_file = self.report_generator.generate_incident_report(
                incident_data=incident_data,
                format_type=args.format
            )
            
            if report_file and os.path.exists(report_file):
                self.print_success(f"Report generated: {report_file}")
                return True
            else:
                self.print_error("Report generation failed")
                return False
                
        except Exception as e:
            self.print_error(f"Report generation failed: {str(e)}")
            return False
    
    def _create_incident_data(self, args) -> Dict[str, Any]:
        """Create incident data structure from arguments."""
        incident_data = self.report_generator.create_incident_template()
        
        # Fill in provided data
        if args.incident_id:
            incident_data['incident_id'] = args.incident_id
        if args.incident_type:
            incident_data['incident_type'] = args.incident_type
        if args.severity:
            incident_data['severity'] = args.severity
        if args.summary:
            incident_data['executive_summary'] = args.summary
        
        # Add data from other modules if available
        # This would be populated from actual analysis results in a real scenario
        
        return incident_data
    
    def status_command(self, args):
        """Handle status command."""
        self.print_info("Al-Mirsad System Status")
        print(f"{Fore.CYAN}{'='*50}")
        
        try:
            # Network isolation status
            isolation_status = self.network_isolator.get_isolation_status()
            if isolation_status:
                self.print_warning("Network isolation is ACTIVE")
                for system, rule in isolation_status.items():
                    print(f"  {Fore.YELLOW}{system}: {Fore.WHITE}{rule}")
            else:
                self.print_success("No network isolation active")
            
            # Check output directories
            directories = [
                ('Log Collection', self.log_collector.output_dir),
                ('Malware Analysis', self.malware_analyzer.output_dir),
                ('Reports', self.report_generator.output_dir)
            ]
            
            print(f"\n{Fore.CYAN}Output Directories:")
            for name, path in directories:
                if os.path.exists(path):
                    file_count = len([f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))])
                    print(f"  {Fore.GREEN}{name}: {Fore.WHITE}{path} ({file_count} files)")
                else:
                    print(f"  {Fore.YELLOW}{name}: {Fore.WHITE}{path} (not created)")
            
            return True
            
        except Exception as e:
            self.print_error(f"Status check failed: {str(e)}")
            return False
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create command line argument parser."""
        parser = argparse.ArgumentParser(
            description='Al-Mirsad - Incident Response Automation Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Collect local logs
  al-mirsad collect-logs --log-types system security --analyze
  
  # Collect remote logs via SSH
  al-mirsad collect-logs --remote --host 192.168.1.100 --username admin --password secret
  
  # Isolate local system
  al-mirsad isolate --central-server 192.168.1.50
  
  # Isolate remote system
  al-mirsad isolate --remote --host 192.168.1.100 --username admin --central-server 192.168.1.50
  
  # Restore network access
  al-mirsad restore
  
  # Analyze malware
  al-mirsad analyze /path/to/suspicious/file --deep
  
  # Generate report
  al-mirsad report --incident-id INC-001 --format docx
  
  # Check status
  al-mirsad status
            """
        )
        
        # Global options
        parser.add_argument('--verbose', '-v', action='store_true',
                          help='Enable verbose output')
        parser.add_argument('--quiet', '-q', action='store_true',
                          help='Suppress output except errors')
        
        # Create subparsers
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Log collection command
        logs_parser = subparsers.add_parser('collect-logs', help='Collect system logs')
        logs_parser.add_argument('--remote', action='store_true',
                               help='Collect logs from remote system')
        logs_parser.add_argument('--host', help='Remote host IP or hostname')
        logs_parser.add_argument('--username', help='SSH username')
        logs_parser.add_argument('--password', help='SSH password')
        logs_parser.add_argument('--key-path', help='Path to SSH private key')
        logs_parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
        logs_parser.add_argument('--log-types', nargs='+', 
                               choices=['system', 'security', 'application'],
                               default=['system', 'security', 'application'],
                               help='Types of logs to collect')
        logs_parser.add_argument('--analyze', action='store_true',
                               help='Analyze collected logs for suspicious activities')
        logs_parser.add_argument('--keywords', nargs='+',
                               help='Custom keywords to search for in logs')
        
        # Network isolation command
        isolate_parser = subparsers.add_parser('isolate', help='Isolate system from network')
        isolate_parser.add_argument('--remote', action='store_true',
                                  help='Isolate remote system')
        isolate_parser.add_argument('--host', help='Remote host IP or hostname')
        isolate_parser.add_argument('--username', help='SSH username')
        isolate_parser.add_argument('--password', help='SSH password')
        isolate_parser.add_argument('--key-path', help='Path to SSH private key')
        isolate_parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
        isolate_parser.add_argument('--central-server', required=True,
                                  help='IP address of central management server')
        isolate_parser.add_argument('--allowed-ports', nargs='+', type=int,
                                  default=[22, 443, 80],
                                  help='Ports to keep open (default: 22 443 80)')
        
        # Network restoration command
        restore_parser = subparsers.add_parser('restore', help='Restore network access')
        restore_parser.add_argument('--remote', action='store_true',
                                  help='Restore remote system')
        restore_parser.add_argument('--host', help='Remote host IP or hostname')
        restore_parser.add_argument('--username', help='SSH username')
        restore_parser.add_argument('--password', help='SSH password')
        restore_parser.add_argument('--key-path', help='Path to SSH private key')
        restore_parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
        
        # Malware analysis command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze suspicious files')
        analyze_parser.add_argument('file', help='File or directory to analyze')
        analyze_parser.add_argument('--deep', action='store_true',
                                  help='Perform deep analysis including behavioral analysis')
        analyze_parser.add_argument('--extensions', nargs='+',
                                  default=['.exe', '.dll', '.bat', '.ps1', '.scr', '.com'],
                                  help='File extensions to analyze (for directories)')
        
        # Report generation command
        report_parser = subparsers.add_parser('report', help='Generate incident report')
        report_parser.add_argument('--incident-id', help='Incident ID')
        report_parser.add_argument('--incident-type', help='Type of incident')
        report_parser.add_argument('--severity', choices=['High', 'Medium', 'Low'],
                                 help='Incident severity')
        report_parser.add_argument('--summary', help='Executive summary')
        report_parser.add_argument('--format', choices=['docx', 'pdf', 'json'],
                                 default='docx', help='Report format (default: docx)')
        
        # Status command
        subparsers.add_parser('status', help='Show system status')
        
        return parser
    
    def run(self, args=None):
        """Run the CLI application."""
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)
        
        if not parsed_args.command:
            parser.print_help()
            return 1
        
        # Set logging level based on verbosity
        if parsed_args.quiet:
            self.logger.setLevel(logging.ERROR)
        elif parsed_args.verbose:
            self.logger.setLevel(logging.DEBUG)
        
        try:
            # Execute command
            if parsed_args.command == 'collect-logs':
                success = self.collect_logs_command(parsed_args)
            elif parsed_args.command == 'isolate':
                success = self.isolate_network_command(parsed_args)
            elif parsed_args.command == 'restore':
                success = self.restore_network_command(parsed_args)
            elif parsed_args.command == 'analyze':
                success = self.analyze_malware_command(parsed_args)
            elif parsed_args.command == 'report':
                success = self.generate_report_command(parsed_args)
            elif parsed_args.command == 'status':
                success = self.status_command(parsed_args)
            else:
                self.print_error(f"Unknown command: {parsed_args.command}")
                return 1
            
            return 0 if success else 1
            
        except KeyboardInterrupt:
            self.print_warning("Operation cancelled by user")
            return 130
        except Exception as e:
            self.print_error(f"Unexpected error: {str(e)}")
            if parsed_args.verbose:
                import traceback
                traceback.print_exc()
            return 1


def main():
    """Main entry point for the CLI."""
    cli = AlMirsadCLI()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())
