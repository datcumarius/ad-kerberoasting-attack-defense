# 🛡️ Active Directory LAB: Kerberoasting Attack & Defense

<p align="left">
    Exploiting Active Directory via Kerberoasting, detecting threats with Microsoft Sentinel, and implementing Hardening measures.
    <br />
  </p>
<div align="center">
  <a href="https://github.com/NUMELE-TAU/ad-kerberoasting-attack-defense">
    <img width="1327" height="672" alt="banner5" src="https://github.com/user-attachments/assets/13e9d4ca-515d-4156-a4f5-12aab43d627b" />
  </a>

  
</div>

<div align="center">
  <img src="https://img.shields.io/badge/Platform-Microsoft%20Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Azure" />
  <img src="https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white" alt="Sentinel" />
  <img src="https://img.shields.io/badge/OS-Windows%20Server-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows Server" />
  <img src="https://img.shields.io/badge/Attacker-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali" />
  <img src="https://img.shields.io/badge/Protocol-Active%20Directory-737373?style=for-the-badge&logo=activedirectory&logoColor=white" alt="AD" />
</div>

---

## 🛡️ Project Overview

This project simulates a realistic **Internal Network Breach** scenario within a controlled Cloud environment. The objective was to build a vulnerable Active Directory infrastructure, execute a modern identity-based attack (**Kerberoasting**), and then detect and remediate the threat using **Microsoft Sentinel**.

**The Cyber Kill Chain simulated in this lab:**
1.  **Build:** Deploying a segmented corporate network with Active Directory Domain Services.
2.  **Attack (Red Team):** Exploiting Service Principal Names (SPNs) to extract and crack service account credentials.
3.  **Detect (Blue Team):** Engineering KQL queries in Sentinel to identify specific Kerberos encryption anomalies (RC4).
4.  **Respond (Blue Team):** Containing the compromised user and hardening the Kerberos policy (AES Enforcement).

---

## 🏗️ PHASE 1: Infrastructure & Configuration (The Build)

I designed a segmented Azure Virtual Network to simulate a corporate environment with distinct zones for Servers and Clients.

### 1. Network Topology
[--INSERT NETWORK CONFIGURATION PICTURE--]
*Figure 1: High-level architecture showing the isolation between the Domain Controller and the Attacker Machine.*

### 2. Cloud Resources (Azure)
The environment consists of a Domain Controller (Windows Server 2019) and an Attacker Machine (Kali Linux), interconnected via a VNet.

<img width="1918" height="885" alt="azure_resources_overview" src="https://github.com/user-attachments/assets/0e156ade-d0cc-4c21-8940-8caf201006d7" />

*Figure 2: The Azure Resource Group containing Compute and Networking components.*

### 3. Active Directory Structure
I promoted the Windows Server to a Domain Controller and organized the directory with specific Organizational Units (OUs) for Employees and Admin staff.

<img width="947" height="667" alt="AD_configuration" src="https://github.com/user-attachments/assets/a1bbd9db-8f6f-4769-bcd8-aaa2fa5177ef" />

*Figure 3: AD User structure showing the target service account.*

### 4. The Vulnerability Root Cause (SPN)
To simulate a vulnerable service account (legacy SQL setup), I manually registered a Service Principal Name (SPN) for the `sql-service` account. This allows any authenticated user to request a Kerberos ticket for this service.

<img width="757" height="332" alt="sqlserver_creation" src="https://github.com/user-attachments/assets/03612c10-831f-4091-aeb7-1519e1cfe178" />

*Figure 4: Verifying the SPN registration, which makes the account susceptible to Kerberoasting.*

---

## ⚔️ PHASE 2: The Attack Execution (Red Team)

Assuming the role of an attacker with initial access (a compromised standard user, `bob.john`), I proceeded to escalate privileges.

### 5. Network Reconnaissance
Since the attacker is internal, I mapped the Domain Controller's IP address to the domain name to facilitate Kerberos communication.

<img width="992" height="483" alt="etchosts" src="https://github.com/user-attachments/assets/58febc7f-0053-43b3-9c65-ef9d185b2e49" />

*Figure 5: DNS Mapping configuration on the attacker machine.*

### 6. The Extraction (Kerberoasting)
Using the `Impacket` toolsuite, I requested a TGS (Ticket Granting Service) ticket for the `sql-service`. Because the account has an SPN, Active Directory issued the ticket encrypted with the service account's password hash.

<img width="1897" height="1007" alt="impacket_attack" src="https://github.com/user-attachments/assets/703f5063-5025-4cfc-8e0f-f429bc4def6f" />

*Figure 6: Extracting the Kerberos TGS Hash.*

### 7. Cracking the Hash
I took the stolen hash offline and used **John the Ripper** with a targeted wordlist to brute-force the NTLM hash, successfully revealing the cleartext password.

<img width="963" height="643" alt="password_cracked" src="https://github.com/user-attachments/assets/0902df9e-7be0-49ce-b326-eb7d74a83253" />

*Figure 7: Successful offline cracking of the service account password.*

---

## 🕵️‍♂️ PHASE 3: Detection & Engineering (Blue Team)

With the attack complete, I switched roles to the Security Operations Center (SOC) analyst to identify the breach using **Microsoft Sentinel**.

### 8. Log Ingestion Pipeline
I configured the Azure Monitor Agent (AMA) to forward all Windows Security Events from the Domain Controller to the Log Analytics Workspace.

<img width="1918" height="872" alt="windows_security_events" src="https://github.com/user-attachments/assets/8d6aca07-30b7-4875-9f92-81326316288f" />

*Figure 8: Verifying active log ingestion from the DC.*

### 9. Raw Log Analysis
Investigating the raw logs confirmed that the Domain Controller logged the ticket request events.

<img width="1918" height="870" alt="sentinel_logs" src="https://github.com/user-attachments/assets/e4d91339-b0e6-4dec-b3a1-90443f3ac8c5" />

*Figure 9: Initial visibility into Security Events.*

### 10. Threat Hunting (The "Smoking Gun")
To filter out normal noise and pinpoint the attack, I wrote a specific KQL query looking for **Event ID 4769** combined with **Ticket Encryption Type 0x17** (RC4). Modern systems typically use AES; a request for RC4 is a strong indicator of Kerberoasting tools.

<img width="1460" height="822" alt="advanced_logs" src="https://github.com/user-attachments/assets/d16cb246-36ae-4261-870a-7125d852f4d9" />

*Figure 10: KQL Query detecting the specific signature of the attack (RC4 Encryption Request).*

---

## 🛡️ PHASE 4: Incident Response & Hardening

Upon detecting the compromised credentials, I initiated the incident response procedure.

### 11. Containment: Isolating the Attacker
Since the attacker utilized `bob.john`'s account for initial access, I immediately disabled the account to prevent lateral movement.

<img width="931" height="452" alt="account_disabled" src="https://github.com/user-attachments/assets/eafd8b24-ec6d-410c-9edb-ec07d71cc45d" />

*Figure 11: Disabling the compromised user account.*

### 12. Remediation: Securing the Service Account
I reset the password for the targeted `sql-service` account, rendering the stolen hash useless.

<img width="437" height="220" alt="password_changed" src="https://github.com/user-attachments/assets/fd04e673-2695-4798-96f5-26eb14c44a9f" />

*Figure 12: Resetting the service account password.*

### 13. Hardening: Enforcing AES Encryption
To prevent future Kerberoasting attacks from easily requesting RC4 tickets, I modified the **Default Domain Policy (GPO)**. I explicitly disabled RC4 encryption for Kerberos and enforced AES-128/AES-256.

<img width="977" height="698" alt="encryption_config2" src="https://github.com/user-attachments/assets/b0be851c-85ce-4252-b2fb-3a4795cc6c5a" />

*Figure 13: Configuring Group Policy to deprecate RC4 and enforce AES encryption.*

---

<details>
<summary>🧠 Click to see the KQL Detection Query</summary>

```kusto
SecurityEvent
| where EventID == 4769
| where EventData contains "0x17"
| parse EventData with * 'TargetUserName">' TargetUserName '<' *
| parse EventData with * 'ServiceName">' ServiceName '<' *
| parse EventData with * 'IpAddress">' IpAddress '<' *
| parse EventData with * 'TicketEncryptionType">' TicketEncryptionType '<' *
| project TimeGenerated, TargetUserName, ServiceName, TicketEncryptionType, IpAddress
```
</details>

---

## 💡 Conclusion

This lab successfully demonstrated how a seemingly minor configuration (an SPN) can lead to a critical credential compromise. It highlighted the importance of:
1.  **Strong Password Policies** for Service Accounts.
2.  **Disabling RC4** encryption in Active Directory (Hardening).
3.  **Real-time SIEM Monitoring** to detect anomalies.
