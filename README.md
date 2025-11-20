# 🛡️ Active Directory LAB: Kerberoasting Attack & Defense
## Project Overview

This project simulates a realistic **Internal Network Breach** scenario within a controlled Azure environment. The objective was to build a vulnerable Active Directory infrastructure, execute a modern identity-based attack (**Kerberoasting**), and then detect and remediate the threat using **Microsoft Sentinel (SIEM)**.

This lab demonstrates the full lifecycle of a cyber threat:
1.  **Build:** Deploying a segmented corporate network with Active Directory Domain Services.
2.  **Attack (Red Team):** Exploiting Service Principal Names (SPNs) to extract and crack service account credentials.
3.  **Detect (Blue Team):** Engineering KQL queries in Sentinel to identify specific Kerberos encryption anomalies (RC4).
4.  **Respond:** Mitigating the threat through account remediation.

---

## 🏗️ PHASE 1: Infrastructure & Configuration (The Build)

I designed a segmented Azure Virtual Network to simulate a corporate environment with distinct zones for Servers and Clients.

### 1. Cloud Infrastructure (Azure)
The environment consists of a Domain Controller (Windows Server 2019) and an Attacker Machine (Kali Linux), isolated in different subnets but connected via a Virtual Network.

<img width="1918" height="885" alt="azure_resources_overview" src="https://github.com/user-attachments/assets/e0dbebd5-6f44-49fc-ae94-bab7697a39dd" />
*Figure 1: The Azure Resource Group containing the DC, Kali, and Networking components.*

### 2. Active Directory Structure
I promoted the Windows Server to a Domain Controller and organized the directory with specific Organizational Units (OUs) for Employees and Admin staff, creating realistic targets.

<img width="947" height="667" alt="AD_configuration" src="https://github.com/user-attachments/assets/4e159b98-1d07-4148-a0b2-b8f72e53eb46" />
*Figure 2: AD User structure showing the target service account.*

### 3. The Vulnerability Root Cause (SPN)
To simulate a vulnerable service account (often found in legacy SQL/IIS setups), I manually registered a Service Principal Name (SPN) for the `sql-service` account. This allows any authenticated user to request a Kerberos ticket for this specific service.

<img width="757" height="332" alt="sqlserver_creation" src="https://github.com/user-attachments/assets/984a5918-e9c7-432c-8365-82f5403075f6" />

*Figure 3: Verifying the SPN registration, which makes the account susceptible to Kerberoasting.*

---

## ⚔️ PHASE 2: The Attack Execution (Red Team)

Assuming the role of an attacker with initial access (a compromised standard user, `bob.john`), I proceeded to escalate privileges.

### 4. Network Reconnaissance
Since the attacker is internal, I mapped the Domain Controller's IP address to the domain name to facilitate Kerberos communication.

<img width="992" height="483" alt="etchosts" src="https://github.com/user-attachments/assets/43e5869f-d30c-4c89-a541-25022e96d751" />
*Figure 4: DNS Spoofing/Mapping on the attacker machine.*

### 5. The Extraction (Kerberoasting)
Using the `Impacket` toolsuite, I requested a TGS (Ticket Granting Service) ticket for the `sql-service`. Because the account has an SPN, Active Directory issued the ticket encrypted with the service account's password hash.

<img width="1897" height="1007" alt="impacket_attack" src="https://github.com/user-attachments/assets/225596b4-0ba6-44c0-9702-23f8d4f42305" />
*Figure 5: Extracting the Kerberos TGS Hash.*

### 6. Cracking the Hash
I took the stolen hash offline and used **John the Ripper** with a targeted wordlist to brute-force the NTLM hash, successfully revealing the cleartext password.

<img width="963" height="643" alt="password_cracked" src="https://github.com/user-attachments/assets/b8bcdba9-33be-4fe6-a101-1cdaaad140f9" />
*Figure 6: Successful offline cracking of the service account password.*

---

## 🕵️‍♂️ PHASE 3: Detection & Engineering (Blue Team)

With the attack complete, I switched roles to the Security Operations Center (SOC) analyst to identify the breach using **Microsoft Sentinel**.

### 7. Log Ingestion Pipeline
I configured the Azure Monitor Agent (AMA) to forward all Windows Security Events from the Domain Controller to the Log Analytics Workspace.

<img width="1918" height="872" alt="windows_security_events" src="https://github.com/user-attachments/assets/91ee6f3e-b115-47bf-9dc9-67a4110e6bb6" />
*Figure 7: Verifying active log ingestion from the DC.*

### 8. Raw Log Analysis
Investigating the raw logs confirmed that the Domain Controller logged the ticket request events.

<img width="1918" height="870" alt="sentinel_logs" src="https://github.com/user-attachments/assets/74262cb5-025a-416f-85a0-58d870e9beb4" />
*Figure 8: Initial visibility into Security Events.*

### 9. Threat Hunting (The "Smoking Gun")
To filter out normal noise and pinpoint the attack, I wrote a specific KQL query looking for **Event ID 4769** combined with **Ticket Encryption Type 0x17** (RC4). Modern systems typically use AES; a request for RC4 is a strong indicator of Kerberoasting tools.

<img width="1460" height="822" alt="advanced_logs" src="https://github.com/user-attachments/assets/4f8d82af-707d-45b1-9275-61c5eb851f34" />
*Figure 9: KQL Query detecting the specific signature of the attack (RC4 Encryption Request).*

**The KQL Query Used:**
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

## 🛡️ PHASE 4: Incident Response & Hardening

Upon detecting the attack pattern, I initiated a full Incident Response cycle to contain the threat and harden the environment against future attempts.

### 10. Containment: Isolating the Compromised User
Since the attacker utilized `bob.john`'s account for initial access/reconnaissance, I immediately disabled the account to prevent lateral movement.

<img width="931" height="452" alt="account_disabled" src="https://github.com/user-attachments/assets/1eab5f8a-0acf-4730-8306-14c13e7ab66a" />

*Figure 10: Disabling the compromised user account in Active Directory.*

### 11. Remediation: Securing the Service Account
I reset the password for the targeted `sql-service` account, rendering the stolen hash useless.

<img width="437" height="220" alt="password_changed" src="https://github.com/user-attachments/assets/e41df3fb-84f3-4361-93e6-b4a0531036fb" />

*Figure 11: Resetting the service account password.*

### 12. Hardening: Disabling Weak Encryption (AES Enforcement)
To prevent future Kerberoasting attacks from easily requesting RC4 tickets, I modified the **Default Domain Policy (GPO)**. I explicitly disabled RC4 encryption for Kerberos and enforced AES-128/AES-256, significantly increasing the difficulty of cracking any future tickets.

<img width="977" height="698" alt="encryption_config2" src="https://github.com/user-attachments/assets/d0d0d329-0877-4005-b161-166b16fa289b" />
*Figure 12: Configuring Group Policy to deprecate RC4 and enforce AES encryption.*

---

## 💡 Conclusion

This lab successfully demonstrated how a seemingly minor configuration (an SPN) can lead to a critical credential compromise. It highlighted the importance of:
1.  **Strong Password Policies** for Service Accounts.
2.  **Disabling RC4** encryption in Active Directory (Hardening).
3.  **Real-time SIEM Monitoring** to detect encryption anomalies.
