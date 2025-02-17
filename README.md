🛡️ Honeypot Project: Simulating Cyber Attacks

🔍 Project Description

This project uses honeypots to simulate vulnerable systems to attract attackers and observe their tactics in real time. By collecting and analyzing attack data, the project helps understand malicious methodologies and develop proactive defense strategies.

🎯 Project Objectives

Deploy and configure honeypots: Using Dionaea, Cowrie, and Honeyd to simulate vulnerable systems and observe attackers' tactics, techniques, and procedures (TTPs).
Isolate attackers from the real network to prevent any impact on critical systems while allowing them to interact with simulated vulnerable resources.
Enhance honeypot security using Seccomp, AppArmor, and SELinux to limit potential malicious actions.
Visualize attack data by integrating logs into the ELK stack (Elasticsearch, Logstash, Kibana) for in-depth and intuitive analysis.

⚙️ Key Features
Dionaea: Captures exploits targeting network service vulnerabilities to analyze malware.
Cowrie: An interactive SSH/Telnet honeypot to observe attackers' commands and behaviors.
Honeyd: Simulates multiple operating systems to attract various types of attacks.
Seccomp & AppArmor: Enhances security by limiting system calls and enforcing strict access control policies.
ELK Stack: Collects, indexes, and visualizes attack data for real-time analysis.

📊 Visualization and Analysis
Data collected is processed with ELK Stack to generate interactive dashboards, including:

Attack Frequency: Graphs showing the frequency of attacks by protocol and service.
Credential Analysis: Tables and pie charts summarizing commonly used usernames and passwords.
Attacker Behavior: Visualization of commands executed by attackers to analyze their methodologies.

🛠️ Tools Used
Honeypots: Dionaea, Cowrie, Honeyd
Security: Seccomp, AppArmor, SELinux
Visualization: Elasticsearch, Logstash, Kibana (ELK Stack)
Operating System: Ubuntu 18.04
