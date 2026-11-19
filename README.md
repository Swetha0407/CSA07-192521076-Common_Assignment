# Network Security and Firewall Monitoring System

## 1. Project Overview

The **Network Security and Firewall Monitoring System** is a Python-based web application developed using Flask. It demonstrates how network traffic can be monitored, evaluated against firewall rules, and classified as allowed or blocked.

The application provides a centralized dashboard through which users can inspect network traffic, manage firewall rules, evaluate network connections, and monitor security alerts.

The system uses a rule-based firewall evaluation engine with a first-match rule processing mechanism. Network traffic is evaluated based on source IP address, destination IP address, destination port, and transport protocol.

This project demonstrates fundamental concepts of network security, firewall policies, traffic monitoring, and security event analysis through an interactive web interface.

## 2. Objectives

The primary objectives of this project are:

- To develop a web-based network security monitoring application.
- To implement a rule-based firewall evaluation mechanism.
- To classify network traffic as ALLOWED or BLOCKED.
- To provide an interface for creating, viewing, and managing firewall rules.
- To simulate network traffic and analyze its behavior.
- To identify potentially suspicious network activities.
- To maintain records of traffic events and security alerts.
- To demonstrate the role of firewall policies in network protection.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core application development |
| Flask | Web application framework |
| HTML5 | Webpage structure |
| CSS3 | Dashboard styling |
| JavaScript | Client-side interactions |
| JSON | Storage of firewall rules and traffic events |
| Scapy | Optional network packet capture |
| Pytest | Unit testing |

## 4. System Architecture

The application follows a modular architecture in which each component performs a specific responsibility.

### Architecture Flow

```text
              USER
                |
                v
       FLASK WEB INTERFACE
                |
                v
       APPLICATION ROUTES
                |
       +--------+---------+
       |        |         |
       v        v         v
    Traffic   Firewall  Security
    Manager   Engine    Alerts
       |        |         |
       +--------+---------+
                |
                v
          JSON STORAGE
                |
                v
       EVENTS AND RULES
```

### Main Components

**1. Web Interface**

Provides the dashboard and pages for traffic monitoring, firewall rule management, security alerts, and packet monitoring.

**2. Flask Application (`app.py`)**

Handles HTTP requests, application routes, user interactions, and communication between the frontend and backend.

**3. Firewall Engine (`firewall_engine.py`)**

Evaluates network traffic against configured firewall rules and determines whether a connection should be allowed or blocked.

**4. Storage Module (`storage.py`)**

Handles persistent storage and retrieval of firewall rules and traffic events using JSON files.

**5. Security Monitoring**

Analyzes recorded traffic events and identifies activities that match the application's suspicious-traffic conditions.

## 5. Project Directory Structure

```text
CSA07-192521076-Common_Assignment/
│
├── app.py
├── firewall_engine.py
├── storage.py
├── requirements.txt
├── README.md
├── run.sh
├── BUILD_TEST_RESULTS.txt
├── .gitignore
│
├── data/
│   ├── rules.json
│   └── events.json
│
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── traffic.html
│   ├── rules.html
│   ├── alerts.html
│   └── monitor.html
│
├── static/
│   ├── style.css
│   └── app.js
│
└── tests/
    └── test_firewall.py
```

## 6. Features and Modules

### 6.1 Security Dashboard

The dashboard provides an overview of the application's network monitoring activities.

It displays:

- Total traffic events.
- Number of allowed connections.
- Number of blocked connections.
- Security alerts.
- Recent network activity.
- Firewall rule information.

### 6.2 Firewall Rule Management

The application allows users to configure firewall rules based on network parameters.

Each rule can contain:

| Parameter | Description |
|---|---|
| Rule Name | Identifies the firewall rule |
| Source IP | Specifies the originating IP address or CIDR range |
| Destination IP | Specifies the destination IP address or CIDR range |
| Destination Port | Specifies the destination service port |
| Protocol | TCP, UDP, or ANY |
| Action | ALLOW or BLOCK |

The firewall engine evaluates rules in their configured order. The first matching rule determines the action.

If no rule matches the traffic, the system applies its default-deny policy.

### 6.3 Network Traffic Monitoring

The traffic monitoring module displays recorded network events.

Each event contains information such as:

- Source IP address.
- Destination IP address.
- Destination port.
- Network protocol.
- Firewall decision.
- Event timestamp.

Users can inspect traffic records and identify which connections were permitted or denied.

### 6.4 Traffic Simulation

The application includes a traffic simulator to generate sample network connections.

The simulated traffic contains different IP addresses, protocols, and destination ports. Each generated connection is passed through the firewall engine.

The results demonstrate how different firewall rules affect network traffic.

### 6.5 Manual Traffic Evaluation

Users can manually enter network connection details to evaluate a particular traffic flow.

The firewall engine checks the entered parameters against the configured rules and returns the corresponding decision.

### 6.6 Security Alerts

The alert module identifies selected potentially suspicious traffic patterns.

The demonstration includes conditions involving sensitive service ports such as:

- Port 23 – Telnet
- Port 445 – SMB
- Port 3389 – Remote Desktop Protocol

It also identifies traffic using protocols outside the expected TCP and UDP categories.

Detected events are recorded for inspection through the security alerts page.

### 6.7 Packet Monitoring

The monitoring module provides an optional packet-capture integration using Scapy.

When Scapy is installed and the environment supports packet capture, the application can observe network packets and evaluate their information using the monitoring logic.

Packet capture may require elevated privileges and access to a supported network interface.

## 7. Firewall Evaluation Logic

The firewall engine uses a rule-based decision-making approach.

### Evaluation Process

1. Receive the network traffic details.
2. Extract the source IP address.
3. Extract the destination IP address.
4. Identify the destination port.
5. Identify the transport protocol.
6. Compare the traffic against configured firewall rules.
7. Apply the action of the first matching rule.
8. If no rule matches, apply the default-deny policy.
9. Record the resulting traffic event.

### Example Firewall Rules

| Rule | Destination Port | Protocol | Action |
|---|---:|---|---|
| Allow HTTP | 80 | TCP | ALLOW |
| Allow HTTPS | 443 | TCP | ALLOW |
| Block Telnet | 23 | ANY | BLOCK |
| Default Rule | Any unmatched | ANY | BLOCK |

**Example:**

If a TCP connection attempts to access destination port 443, it can match the HTTPS rule and receive an ALLOW decision.

If a connection attempts to access a port without a matching allow rule, it receives a BLOCK decision under the default-deny policy.

## 8. Installation and Execution

### Prerequisites

- Windows 11 or Linux.
- Ubuntu through WSL (for the demonstrated environment).
- Python 3.
- pip.
- A modern web browser.
- Internet connectivity for initial package installation.

### Step 1: Open the Project Directory

Open the WSL Ubuntu terminal and execute:

```bash
cd /mnt/d/github/CSA07-192521076-Common_Assignment
```

### Step 2: Create a Virtual Environment

If a virtual environment has not already been created:

```bash
python3 -m venv .venv
```

### Step 3: Activate the Virtual Environment

```bash
source .venv/bin/activate
```

### Step 4: Install Flask

The Flask dashboard can run without Scapy:

```bash
pip install Flask
```

Scapy is optional and is required only for the packet-capture functionality:

```bash
pip install scapy
```

If package downloads fail because of network or DNS problems, retry when internet connectivity is available.

### Step 5: Run the Application

Make sure the terminal is inside the project directory and execute:

```bash
python app.py
```

### Step 6: Open the Dashboard

Open the following URL in your web browser:

```text
http://127.0.0.1:5000
```

The application dashboard should now be accessible.

To stop the application, press:

```text
CTRL + C
```

## 9. Application Routes

| Route | Function |
|---|---|
| `/` | Main security dashboard |
| `/traffic` | View network traffic events |
| `/rules` | Manage firewall rules |
| `/alerts` | View security alerts |
| `/monitor` | Access packet monitoring |
| `/api/evaluate` | Evaluate a network traffic flow |
| `/api/simulate` | Generate simulated traffic |
| `/api/sniff` | Access optional packet-capture functionality |
| `/health` | Check application availability |

## 10. Testing and Validation

The project includes automated unit tests to validate the firewall evaluation logic.

The test file is located at:

```text
tests/test_firewall.py
```

To execute the tests, run:

```bash
python -m unittest discover -s tests -v
```

The tests validate important firewall operations, including rule evaluation and traffic decisions.

The project was also checked for Python syntax errors using:

```bash
python -m compileall .
```

### Suggested Manual Test Cases

| Test Case | Input | Expected Result |
|---|---|---|
| HTTPS Traffic | TCP, Port 443 | ALLOW |
| Telnet Traffic | TCP, Port 23 | BLOCK |
| Unknown Port | Unmatched destination port | BLOCK |
| Allowed HTTP Traffic | TCP, Port 80, matching source range | ALLOW |
| Traffic Simulation | Generate sample traffic | Events recorded |
| Security Monitoring | Traffic involving monitored ports | Alert generated where applicable |

Actual results should be verified using the running application.

## 11. Data Storage

The application uses JSON files for persistent data storage.

**`data/rules.json`**

Stores configured firewall rules.

**`data/events.json`**

Stores recorded traffic events and associated information.

This approach provides a lightweight storage mechanism without requiring an external database server.

## 12. Security Considerations and Limitations

This project is an educational network security monitoring application.

The following limitations should be considered:

1. The firewall engine performs application-level traffic classification. It does not directly modify operating-system firewall rules.
2. ALLOW and BLOCK decisions represent the application's evaluation results; they do not automatically permit or drop actual network packets.
3. The traffic simulator generates demonstration traffic rather than capturing real external network traffic.
4. Security alerts are based on predefined demonstration conditions and do not represent a complete intrusion detection system.
5. Scapy packet capture is optional and depends on network interface access and system permissions.
6. JSON storage is suitable for this demonstration but is not designed for large-scale production environments.

A production deployment would require operating-system firewall integration, stronger access controls, secure data storage, comprehensive packet inspection, and more advanced intrusion detection mechanisms.

## 13. Future Enhancements

The system can be extended through the following improvements:

- Integration with Linux `iptables` or `nftables` for actual packet filtering.
- Real-time traffic visualization.
- Advanced intrusion detection using machine learning.
- User authentication and role-based access control.
- Database integration using SQLite or PostgreSQL.
- Exporting traffic logs and security reports.
- Advanced traffic filtering and search.
- Improved alert severity classification.
- Support for additional network protocols.

## 14. Conclusion

The Network Security and Firewall Monitoring System demonstrates the implementation of a rule-based firewall evaluation mechanism through a Flask web application.

It combines traffic simulation, firewall rule management, event logging, and security alert monitoring into a single interface.

The project provides practical exposure to network security concepts and demonstrates how firewall policies can be used to evaluate network connections and identify potentially suspicious activities.

Through its modular architecture, the application can also serve as a foundation for future enhancements involving real-time packet filtering, intrusion detection, and advanced network security monitoring.

---

## 15. Author and Project Information

**Project Title:** Network Security and Firewall Monitoring System

**Register Number:** 192521076

**Project Type:** Python Flask Web Application

**Domain:** Computer Networks and Network Security

**Repository:** CSA07-192521076-Common_Assignment

**Language:** Python

**Framework:** Flask