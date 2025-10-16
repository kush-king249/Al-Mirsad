# Al-Mirsad (المرصاد) - Incident Response Automation Tool

![Al-Mirsad Logo](docs/al-mirsad-logo.png)

## Overview

Al-Mirsad is a comprehensive incident response automation tool designed to help cybersecurity teams handle incidents efficiently and effectively. The tool provides a set of core functionalities covering various stages of the incident response lifecycle, from information gathering to malware analysis and report generation.

Al-Mirsad is developed with two interfaces: a Command-Line Interface (CLI) for advanced users and scheduled tasks, and a user-friendly Graphical User Interface (GUI) for operators who prefer visual interaction.

## Key Features

*   **Log Collection:**
    *   Collects logs from local and remote systems (via SSH).
    *   Supports various log types (system, security, application).
    *   Analyzes collected logs for suspicious activities using customizable keywords.

*   **Network Isolation:**
    *   Isolates compromised systems from the network to prevent further attack spread (locally and remotely via SSH).
    *   Ability to specify central server IPs and allowed ports to maintain essential connectivity.
    *   Functionality to restore network access after incident remediation.

*   **Malware Analysis:**
    *   Analyzes individual files or entire directories for malware.
    *   Performs deep (behavioral) analysis to detect sophisticated threats.
    *   Identifies threat types, risk scores, and key Indicators of Compromise (IOCs).

*   **Report Generation:**
    *   Generates comprehensive incident reports in various formats (DOCX, PDF, JSON).
    *   Includes incident information, executive summary, analysis results, and recommendations.
    *   Customizable report templates to meet different needs.

*   **Command-Line Interface (CLI):**
    *   Powerful and flexible commands for automating tasks and quick execution.
    *   Supports all tool functionalities via the command line.

*   **Graphical User Interface (GUI):**
    *   User-friendly and intuitive interface for visual interaction with the tool.
    *   Displays progress and results in real-time.

## Methodology

Al-Mirsad follows a structured incident response methodology, inspired by industry best practices such as the NIST Incident Response Framework. Each function is divided into independent modules to ensure flexibility and scalability.

1.  **Preparation:** Necessary environment and tools are set up in advance (tool installation).
2.  **Identification:** Logs are collected and analyzed to determine if a security incident has occurred.
3.  **Containment:** Compromised systems are isolated to prevent further damage.
4.  **Eradication:** Malware is analyzed, and threats are removed.
5.  **Recovery:** Affected systems are restored to their normal state (network access restoration).
6.  **Lessons Learned:** Detailed reports are generated to document the incident and facilitate continuous improvement.

## System Requirements

*   Python 3.8 or later.
*   Linux, Windows, or macOS operating system.
*   For remote functionalities: SSH must be available on target systems.

## Installation

Follow these steps to install Al-Mirsad:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/kush-king249/Al-Mirsad.git
    cd Al-Mirsad
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # For Linux/macOS
    # venv\Scripts\activate  # For Windows
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Install Tkinter (for GUI only):**
    If you plan to use the Graphical User Interface (GUI) on Linux, you might need to install `python3-tk`:
    ```bash
    sudo apt-get update
    sudo apt-get install -y python3-tk
    ```

## Usage

### Command-Line Interface (CLI)

You can run the tool using `python3 src/cli/main_cli.py <command> [options]`.

**Examples:**

*   **Collect local logs and analyze them:**
    ```bash
    python3 src/cli/main_cli.py collect-logs --log-types system security --analyze --keywords malware,attack
    ```

*   **Collect logs from a remote system (via SSH):**
    ```bash
    python3 src/cli/main_cli.py collect-logs --remote --host 192.168.1.100 --username admin --password your_password --log-types system
    ```

*   **Isolate a local system:**
    ```bash
    python3 src/cli/main_cli.py isolate --central-server 192.168.1.50 --allowed-ports 22 443
    ```

*   **Restore network access for a remote system:**
    ```bash
    python3 src/cli/main_cli.py restore --remote --host 192.168.1.100 --username admin --password your_password
    ```

*   **Deep analyze a suspicious file:**
    ```bash
    python3 src/cli/main_cli.py analyze /path/to/suspicious_file.exe --deep
    ```

*   **Analyze an entire directory for specific files:**
    ```bash
    python3 src/cli/main_cli.py analyze /path/to/suspicious_directory --extensions .exe .dll
    ```

*   **Generate an incident report (DOCX):**
    ```bash
    python3 src/cli/main_cli.py report --incident-id INC-2023-007 --incident-type Malware --severity High --summary "Detected and contained a sophisticated malware attack." --format docx
    ```

*   **View system status:**
    ```bash
    python3 src/cli/main_cli.py status
    ```

### Graphical User Interface (GUI)

To run the GUI, use the following command:

```bash
python3 src/gui/main_gui.py
```

A graphical window will appear, allowing you to interact with Al-Mirsad's functionalities through buttons and input fields.

## Documentation

For comprehensive documentation on the methodology used, details of each module, and installation and operation steps, please refer to the `تقرير_المشروع_العربي.md` file.

## Contributors

*   **Author:** Hassan Mohamed Hassan Ahmed
*   **GitHub:** [kush-king249](https://github.com/kush-king249)

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

