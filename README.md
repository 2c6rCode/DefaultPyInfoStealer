# Project KeySync v2: Threat Simulation & Detection Blueprint

##  Project Overview
**KeySync v2 (Simulation)** is an educational security research repository designed to demonstrate the behavioral mechanics of modern information-stealing software. 

By analyzing the data-gathering patterns commonly deployed by malicious actors—such as system profiling, browser profile targeting, and programmatic key-monitoring—this project provides security engineering teams, blue teams, and incident responders with a controlled environment to generate attack telemetry, test host-based visibility, and validate endpoint alerts.

>  **CRITICAL POLICY COMPLIANCE & SAFETY NOTICE**
> In strict compliance with the **GitHub Active Malware or Exploits Policy**, this repository does NOT contain active malware, functional exploits, or weaponized distribution logic. 
> 
> * **100% Defanged:** All malicious exfiltration paths, dynamic credential decryption routines (DPAPI), and persistence implants have been completely removed or replaced with safe, localized loopback logs (`print()` counters).
> * **No Actionable Code:** The source code cannot be compiled or weaponized out-of-the-box to target or damage production environments.
> * **Purpose-Driven:** This project exists solely for authorized defensive engineering, signature writing, and academic analysis.

##  Educational & Defensive Objectives
1. **Telemetry Mapping:** Allows engineers to safely execute the simulation script on a test host to observe system logs (such as Windows Event IDs 4688 and Sysmon Process Creation events).
2. **Signature Verification:** Provides a practical baseline for writing and verifying static detection definitions, such as YARA rules or EDR behaviors.
3. **Mitigation Testing:** Demonstrates how simple host-hardening configurations (like blocking execution from `%TEMP%` paths) can completely neutralize threat vectors.
