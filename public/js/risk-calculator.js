// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Security Risk Assessment Calculator — interactive risk matrix, ALE calculator, risk register, CVSS v3.1 calculator

export var THREAT_SCENARIOS = [
  {name:"Ransomware attack",category:"technical",likelihood:4,impact:5,existing_controls:["Endpoint protection","Offline backups","Network segmentation"],residual_risk:"high",ale:{sle:500000,aro:0.3}},
  {name:"Phishing campaign",category:"human",likelihood:5,impact:3,existing_controls:["Email filtering","Security awareness training","MFA"],residual_risk:"medium",ale:{sle:75000,aro:2.0}},
  {name:"SQL injection",category:"technical",likelihood:4,impact:4,existing_controls:["WAF","Parameterized queries","Input validation"],residual_risk:"medium",ale:{sle:200000,aro:0.5}},
  {name:"Insider data theft",category:"human",likelihood:3,impact:5,existing_controls:["DLP","Access reviews","Activity monitoring"],residual_risk:"high",ale:{sle:1000000,aro:0.1}},
  {name:"DDoS attack",category:"technical",likelihood:4,impact:3,existing_controls:["CDN","Rate limiting","DDoS protection service"],residual_risk:"medium",ale:{sle:50000,aro:1.5}},
  {name:"Cloud misconfiguration",category:"technical",likelihood:4,impact:4,existing_controls:["CSPM","Infrastructure as code","Config audits"],residual_risk:"medium",ale:{sle:300000,aro:0.4}},
  {name:"Supply chain compromise",category:"technical",likelihood:2,impact:5,existing_controls:["SBOM","Dependency scanning","Vendor assessment"],residual_risk:"high",ale:{sle:2000000,aro:0.05}},
  {name:"Physical break-in",category:"environmental",likelihood:2,impact:4,existing_controls:["CCTV","Access cards","Security guards"],residual_risk:"low",ale:{sle:100000,aro:0.1}},
  {name:"Power outage",category:"natural",likelihood:3,impact:2,existing_controls:["UPS","Generator","Cloud failover"],residual_risk:"low",ale:{sle:25000,aro:1.0}},
  {name:"Zero-day exploitation",category:"technical",likelihood:2,impact:5,existing_controls:["EDR","Network monitoring","Threat intel"],residual_risk:"high",ale:{sle:1500000,aro:0.08}},
  {name:"Credential stuffing",category:"technical",likelihood:5,impact:3,existing_controls:["MFA","Rate limiting","Breach monitoring"],residual_risk:"medium",ale:{sle:80000,aro:3.0}},
  {name:"Social engineering call",category:"human",likelihood:4,impact:3,existing_controls:["Verification procedures","Training","Call recording"],residual_risk:"medium",ale:{sle:60000,aro:1.0}},
  {name:"Earthquake/flood damage",category:"natural",likelihood:1,impact:5,existing_controls:["DR site","Cloud backup","Insurance"],residual_risk:"medium",ale:{sle:5000000,aro:0.02}},
  {name:"Third-party data breach",category:"human",likelihood:3,impact:4,existing_controls:["Vendor assessment","Contract clauses","Data minimization"],residual_risk:"medium",ale:{sle:400000,aro:0.2}},
  {name:"API abuse",category:"technical",likelihood:4,impact:3,existing_controls:["API gateway","Rate limiting","Authentication"],residual_risk:"medium",ale:{sle:100000,aro:0.8}},
  {name:"Privilege escalation",category:"technical",likelihood:3,impact:5,existing_controls:["Least privilege","PAM","Monitoring"],residual_risk:"high",ale:{sle:500000,aro:0.2}},
  {name:"DNS hijacking",category:"technical",likelihood:2,impact:4,existing_controls:["DNSSEC","Registry lock","Monitoring"],residual_risk:"medium",ale:{sle:250000,aro:0.1}},
  {name:"Malicious USB device",category:"human",likelihood:3,impact:3,existing_controls:["USB policy","Endpoint control","Training"],residual_risk:"low",ale:{sle:50000,aro:0.3}},
  {name:"Container escape",category:"technical",likelihood:2,impact:4,existing_controls:["Pod security","Network policies","Runtime security"],residual_risk:"medium",ale:{sle:300000,aro:0.1}},
  {name:"Business email compromise",category:"human",likelihood:4,impact:4,existing_controls:["DMARC","Approval workflows","Training"],residual_risk:"high",ale:{sle:150000,aro:0.8}},
  {name:"Cryptojacking",category:"technical",likelihood:3,impact:2,existing_controls:["EDR","Resource monitoring","Container scanning"],residual_risk:"low",ale:{sle:30000,aro:0.5}},
  {name:"Wireless network attack",category:"technical",likelihood:3,impact:3,existing_controls:["WPA3","802.1X","WIDS"],residual_risk:"medium",ale:{sle:75000,aro:0.3}},
  {name:"Data exfiltration via cloud storage",category:"human",likelihood:3,impact:4,existing_controls:["CASB","DLP","Access logging"],residual_risk:"medium",ale:{sle:500000,aro:0.15}},
  {name:"Firmware tampering",category:"technical",likelihood:1,impact:5,existing_controls:["Secure boot","TPM","Firmware updates"],residual_risk:"medium",ale:{sle:800000,aro:0.02}},
  {name:"CI/CD pipeline compromise",category:"technical",likelihood:3,impact:5,existing_controls:["Pipeline hardening","Code signing","Secrets management"],residual_risk:"high",ale:{sle:1000000,aro:0.1}},
  {name:"Session hijacking",category:"technical",likelihood:3,impact:3,existing_controls:["HTTPS","Secure cookies","Session timeout"],residual_risk:"low",ale:{sle:40000,aro:0.5}},
  {name:"Rogue employee access",category:"human",likelihood:2,impact:4,existing_controls:["Background checks","Access reviews","Termination procedures"],residual_risk:"medium",ale:{sle:300000,aro:0.1}},
  {name:"SSL/TLS vulnerability",category:"technical",likelihood:2,impact:3,existing_controls:["Certificate management","TLS 1.3","HSTS"],residual_risk:"low",ale:{sle:100000,aro:0.15}},
  {name:"Log tampering",category:"technical",likelihood:2,impact:3,existing_controls:["Centralized logging","WORM storage","Integrity monitoring"],residual_risk:"low",ale:{sle:60000,aro:0.2}},
  {name:"Shadow IT discovery",category:"human",likelihood:4,impact:2,existing_controls:["CASB","Network discovery","Policy enforcement"],residual_risk:"medium",ale:{sle:40000,aro:1.5}},
  {name:"MFA bypass",category:"technical",likelihood:2,impact:4,existing_controls:["Hardware tokens","Phishing-resistant MFA","Risk-based auth"],residual_risk:"medium",ale:{sle:200000,aro:0.1}},
  {name:"Watering hole attack",category:"human",likelihood:2,impact:4,existing_controls:["Web proxy","Browser isolation","Threat intel"],residual_risk:"medium",ale:{sle:250000,aro:0.08}},
  {name:"Server-side request forgery",category:"technical",likelihood:3,impact:4,existing_controls:["Input validation","Network segmentation","Allowlists"],residual_risk:"medium",ale:{sle:200000,aro:0.3}},
  {name:"Cross-site scripting (stored)",category:"technical",likelihood:4,impact:3,existing_controls:["Output encoding","CSP","Input sanitization"],residual_risk:"medium",ale:{sle:80000,aro:0.8}},
  {name:"Regulatory non-compliance fine",category:"human",likelihood:3,impact:4,existing_controls:["GRC platform","Audits","Policy management"],residual_risk:"medium",ale:{sle:500000,aro:0.2}}
];

var RISK_LABELS = ["","Rare","Unlikely","Possible","Likely","Almost Certain"];
var IMPACT_LABELS = ["","Negligible","Minor","Moderate","Major","Catastrophic"];
var RISK_COLORS = {1:"#22c55e",2:"#84cc16",3:"#eab308",4:"#f97316",5:"#ef4444"};
var TREATMENT = [{name:"Accept",desc:"Acknowledge the risk and do nothing"},{name:"Mitigate",desc:"Implement controls to reduce likelihood/impact"},{name:"Transfer",desc:"Shift risk to third party (insurance, outsourcing)"},{name:"Avoid",desc:"Eliminate the activity causing the risk"}];
var FRAMEWORKS = {high:["NIST CSF PR.DS","ISO 27001 A.8","PCI DSS 3.4","SOC 2 CC6"],medium:["NIST CSF DE.CM","ISO 27001 A.12","CIS Control 8"],low:["NIST CSF ID.RA","ISO 27001 A.5"]};

// CVSS v3.1 metric definitions
var CVSS_METRICS = [
  {key:"AV",name:"Attack Vector",desc:"How the vulnerability is exploited",options:[{label:"Network",abbr:"N",val:0.85},{label:"Adjacent",abbr:"A",val:0.62},{label:"Local",abbr:"L",val:0.55},{label:"Physical",abbr:"P",val:0.20}]},
  {key:"AC",name:"Attack Complexity",desc:"Conditions beyond the attacker's control",options:[{label:"Low",abbr:"L",val:0.77},{label:"High",abbr:"H",val:0.44}]},
  {key:"PR",name:"Privileges Required",desc:"Level of privileges needed before exploitation",options:[{label:"None",abbr:"N",valU:0.85,valC:0.85},{label:"Low",abbr:"L",valU:0.62,valC:0.68},{label:"High",abbr:"H",valU:0.27,valC:0.50}]},
  {key:"UI",name:"User Interaction",desc:"Whether a user other than the attacker must participate",options:[{label:"None",abbr:"N",val:0.85},{label:"Required",abbr:"R",val:0.62}]},
  {key:"S",name:"Scope",desc:"Whether the vulnerability impacts resources beyond its security scope",options:[{label:"Unchanged",abbr:"U"},{label:"Changed",abbr:"C"}]},
  {key:"C",name:"Confidentiality",desc:"Impact to the confidentiality of information",options:[{label:"None",abbr:"N",val:0},{label:"Low",abbr:"L",val:0.22},{label:"High",abbr:"H",val:0.56}]},
  {key:"I",name:"Integrity",desc:"Impact to the integrity of information",options:[{label:"None",abbr:"N",val:0},{label:"Low",abbr:"L",val:0.22},{label:"High",abbr:"H",val:0.56}]},
  {key:"A",name:"Availability",desc:"Impact to the availability of the system",options:[{label:"None",abbr:"N",val:0},{label:"Low",abbr:"L",val:0.22},{label:"High",abbr:"H",val:0.56}]}
];

var CVE_EXAMPLES = [
  {cve:"CVE-2021-44228",name:"Log4Shell (Apache Log4j)",score:10.0,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",severity:"Critical",desc:"Remote code execution via JNDI lookup in log messages. Affected millions of Java applications worldwide."},
  {cve:"CVE-2017-0144",name:"EternalBlue (SMBv1)",score:9.8,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",severity:"Critical",desc:"SMBv1 remote code execution used in WannaCry and NotPetya ransomware attacks."},
  {cve:"CVE-2021-34527",name:"PrintNightmare",score:8.8,vector:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",severity:"High",desc:"Windows Print Spooler RCE allowing privilege escalation and remote code execution."},
  {cve:"CVE-2023-23397",name:"Outlook Elevation of Privilege",score:9.8,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",severity:"Critical",desc:"NTLM relay via Outlook calendar invite; no user interaction required."},
  {cve:"CVE-2021-3156",name:"Baron Samedit (sudo)",score:7.8,vector:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",severity:"High",desc:"Heap-based buffer overflow in sudo allowing any local user to gain root privileges."},
  {cve:"CVE-2022-0847",name:"Dirty Pipe (Linux Kernel)",score:7.8,vector:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",severity:"High",desc:"Linux kernel pipe buffer flag manipulation allowing overwrite of read-only files."},
  {cve:"CVE-2023-44487",name:"HTTP/2 Rapid Reset",score:7.5,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",severity:"High",desc:"DDoS amplification via rapid HTTP/2 stream reset. Used in record-breaking DDoS attacks."},
  {cve:"CVE-2022-22965",name:"Spring4Shell",score:9.8,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",severity:"Critical",desc:"RCE in Spring Framework via data binding to Java ClassLoader."},
  {cve:"CVE-2023-32784",name:"KeePass Memory Dump",score:7.5,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",severity:"High",desc:"Master password recovery from KeePass process memory dump."},
  {cve:"CVE-2024-3094",name:"XZ Utils Backdoor",score:10.0,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",severity:"Critical",desc:"Supply chain backdoor in XZ Utils targeting OpenSSH authentication."},
  {cve:"CVE-2023-38408",name:"OpenSSH Agent Forwarding",score:9.8,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",severity:"Critical",desc:"Remote code execution through forwarded ssh-agent via PKCS#11 provider loading."},
  {cve:"CVE-2022-41040",name:"ProxyNotShell (Exchange)",score:8.8,vector:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",severity:"High",desc:"SSRF in Microsoft Exchange allowing authenticated RCE."},
  {cve:"CVE-2021-21972",name:"VMware vCenter RCE",score:9.8,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",severity:"Critical",desc:"Unauthenticated file upload leading to RCE in VMware vCenter Server."},
  {cve:"CVE-2023-27350",name:"PaperCut NG/MF RCE",score:9.8,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",severity:"Critical",desc:"Authentication bypass and RCE in PaperCut print management software."},
  {cve:"CVE-2020-1472",name:"ZeroLogon",score:10.0,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",severity:"Critical",desc:"Netlogon elevation of privilege allowing unauthenticated domain controller takeover."},
  {cve:"CVE-2023-36884",name:"Office HTML RCE",score:8.8,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",severity:"High",desc:"Windows HTML RCE via specially crafted Office documents; exploited by RomCom."},
  {cve:"CVE-2022-27925",name:"Zimbra RCE",score:7.2,vector:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",severity:"High",desc:"Authenticated RCE in Zimbra Collaboration via mboximport functionality."},
  {cve:"CVE-2024-21762",name:"FortiOS Out-of-Bound Write",score:9.8,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",severity:"Critical",desc:"Unauthenticated RCE in FortiOS SSL VPN, actively exploited in the wild."},
  {cve:"CVE-2021-40444",name:"MSHTML RCE",score:7.8,vector:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",severity:"High",desc:"RCE via ActiveX control in MSHTML engine through crafted Office documents."},
  {cve:"CVE-2023-4966",name:"Citrix Bleed",score:7.5,vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",severity:"High",desc:"Sensitive session-token disclosure in Citrix NetScaler enabling session hijacking."}
];

export function renderRiskCalculator(container) {
  var esc = function(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); };
  var activeView = "matrix";
  var sortField = "risk";
  var sortDir = "desc";
  var filterCat = "all";

  // CVSS state
  var cvssSelections = {AV:null,AC:null,PR:null,UI:null,S:null,C:null,I:null,A:null};

  function riskScore(t){return t.likelihood * t.impact}
  function riskLevel(s){return s>=15?"critical":s>=10?"high":s>=5?"medium":"low"}
  function riskColor(s){return s>=15?"#ef4444":s>=10?"#f97316":s>=5?"#eab308":"#22c55e"}
  function fmt$(n){return n>=1000000?"$"+((n/1000000).toFixed(1))+"M":n>=1000?"$"+((n/1000).toFixed(0))+"K":"$"+n}

  function cvssRoundup(val) {
    var up = Math.ceil(val * 10) / 10;
    return up;
  }

  function calcCVSS() {
    var sel = cvssSelections;
    if (sel.AV === null || sel.AC === null || sel.PR === null || sel.UI === null ||
        sel.S === null || sel.C === null || sel.I === null || sel.A === null) {
      return null;
    }

    var avMetric = CVSS_METRICS[0].options[sel.AV];
    var acMetric = CVSS_METRICS[1].options[sel.AC];
    var prMetric = CVSS_METRICS[2].options[sel.PR];
    var uiMetric = CVSS_METRICS[3].options[sel.UI];
    var sMetric = CVSS_METRICS[4].options[sel.S];
    var cMetric = CVSS_METRICS[5].options[sel.C];
    var iMetric = CVSS_METRICS[6].options[sel.I];
    var aMetric = CVSS_METRICS[7].options[sel.A];

    var scopeChanged = sMetric.abbr === "C";
    var avVal = avMetric.val;
    var acVal = acMetric.val;
    var prVal = scopeChanged ? prMetric.valC : prMetric.valU;
    var uiVal = uiMetric.val;
    var cVal = cMetric.val;
    var iVal = iMetric.val;
    var aVal = aMetric.val;

    var iss = 1 - ((1 - cVal) * (1 - iVal) * (1 - aVal));
    var impact;
    if (!scopeChanged) {
      impact = 6.42 * iss;
    } else {
      impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    }

    var exploitability = 8.22 * avVal * acVal * prVal * uiVal;

    var baseScore;
    if (impact <= 0) {
      baseScore = 0;
    } else if (!scopeChanged) {
      baseScore = cvssRoundup(Math.min(impact + exploitability, 10));
    } else {
      baseScore = cvssRoundup(Math.min(1.08 * (impact + exploitability), 10));
    }

    var vectorStr = "CVSS:3.1/AV:" + avMetric.abbr + "/AC:" + acMetric.abbr +
      "/PR:" + prMetric.abbr + "/UI:" + uiMetric.abbr + "/S:" + sMetric.abbr +
      "/C:" + cMetric.abbr + "/I:" + iMetric.abbr + "/A:" + aMetric.abbr;

    return {score: baseScore, vector: vectorStr, impact: impact, exploitability: exploitability, iss: iss};
  }

  function severityLabel(s) {
    if (s === 0) return "None";
    if (s <= 3.9) return "Low";
    if (s <= 6.9) return "Medium";
    if (s <= 8.9) return "High";
    return "Critical";
  }

  function severityColor(s) {
    if (s === 0) return "#6b7280";
    if (s <= 3.9) return "#22c55e";
    if (s <= 6.9) return "#eab308";
    if (s <= 8.9) return "#f97316";
    return "#ef4444";
  }

  function render(){
    var tabList = ["matrix","register","ale","stats","cvss"];
    var tabLabels = {matrix:"Matrix",register:"Register",ale:"ALE",stats:"Stats",cvss:"CVSS v3.1"};
    var tabsHtml = "";
    for (var ti = 0; ti < tabList.length; ti++) {
      var tv = tabList[ti];
      tabsHtml += '<div class="rc-tab' + (activeView === tv ? " active" : "") + '" data-v="' + tv + '">' + tabLabels[tv] + '</div>';
    }

    container.innerHTML =
      '<style>' +
        '.rc{font-family:system-ui,sans-serif;color:var(--txt,#c8d6e5);max-width:1200px;margin:0 auto;padding:24px}' +
        '.rc h2{color:var(--acc,#00d4ff);margin:0 0 6px}' +
        '.rc-tabs{display:flex;gap:4px;margin:20px 0;border-bottom:1px solid var(--border,#21262d)}' +
        '.rc-tab{padding:8px 18px;cursor:pointer;border-bottom:2px solid transparent;font-size:.85rem;color:var(--mut,#6b7280)}' +
        '.rc-tab:hover{color:var(--txt)}' +
        '.rc-tab.active{color:var(--acc,#00d4ff);border-bottom-color:var(--acc,#00d4ff)}' +
        '.rc-matrix{display:grid;grid-template-columns:auto repeat(5,1fr);gap:2px;margin:20px 0}' +
        '.rc-cell{padding:10px;text-align:center;font-size:.75rem;border-radius:4px;min-height:40px;display:flex;align-items:center;justify-content:center;flex-direction:column}' +
        '.rc-cell.header{background:transparent;color:var(--mut,#6b7280);font-weight:700;font-size:.7rem}' +
        '.rc-cell.data{cursor:pointer;transition:transform .15s}' +
        '.rc-cell.data:hover{transform:scale(1.05)}' +
        '.rc-filter{display:flex;gap:12px;margin:16px 0;align-items:center}' +
        '.rc-filter select{padding:6px 12px;background:var(--surface,#0d1117);border:1px solid var(--border,#21262d);border-radius:6px;color:inherit;font-size:.85rem}' +
        '.rc-tbl{width:100%;border-collapse:collapse;font-size:.82rem}' +
        '.rc-tbl th{text-align:left;padding:8px 12px;border-bottom:1px solid var(--border,#21262d);cursor:pointer;user-select:none;color:var(--acc,#00d4ff);font-size:.75rem}' +
        '.rc-tbl th:hover{text-decoration:underline}' +
        '.rc-tbl td{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04)}' +
        '.rc-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:700}' +
        '.rc-ale{background:var(--surface,#0d1117);border:1px solid var(--border,#21262d);border-radius:10px;padding:20px;margin:20px 0}' +
        '.rc-stat{display:flex;gap:20px;flex-wrap:wrap;margin:16px 0}' +
        '.rc-stat-card{background:var(--surface,#0d1117);border:1px solid var(--border,#21262d);border-radius:8px;padding:16px;min-width:180px;flex:1}' +
        '.rc-stat-card h4{margin:0;font-size:.75rem;color:var(--mut,#6b7280);text-transform:uppercase}' +
        '.rc-stat-card .val{font-size:1.8rem;font-weight:800;margin:6px 0 0}' +
        '.cvss-metric{background:var(--surface,#0d1117);border:1px solid var(--border,#21262d);border-radius:8px;padding:14px;margin-bottom:10px}' +
        '.cvss-metric-name{font-weight:600;font-size:.88rem;margin-bottom:2px}' +
        '.cvss-metric-desc{font-size:.72rem;color:var(--mut,#6b7280);margin-bottom:8px}' +
        '.cvss-btns{display:flex;gap:4px;flex-wrap:wrap}' +
        '.cvss-btn{padding:6px 14px;border:1px solid var(--border,#21262d);border-radius:4px;background:var(--card,#161b22);color:var(--txt,#c8d6e5);cursor:pointer;font-size:.78rem;font-family:inherit;transition:all .12s}' +
        '.cvss-btn:hover{border-color:var(--acc,#00d4ff)}' +
        '.cvss-btn.sel{background:var(--acc,#00d4ff);color:#0d1117;border-color:var(--acc,#00d4ff);font-weight:700}' +
        '.cvss-gauge{height:28px;border-radius:6px;background:var(--border,#21262d);position:relative;overflow:hidden;margin:12px 0}' +
        '.cvss-gauge-fill{height:100%;border-radius:6px;transition:width .3s}' +
        '.cvss-gauge-label{position:absolute;top:0;left:0;right:0;bottom:0;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.9rem}' +
        '.cvss-vector{font-family:monospace;font-size:.82rem;background:var(--surface,#0d1117);border:1px solid var(--border,#21262d);border-radius:6px;padding:10px 14px;margin:8px 0;word-break:break-all}' +
        '.cvss-result{display:flex;gap:16px;margin-top:16px;flex-wrap:wrap}' +
        '.cvss-result-card{background:var(--surface,#0d1117);border:1px solid var(--border,#21262d);border-radius:8px;padding:16px;flex:1;min-width:160px;text-align:center}' +
        '.cvss-result-card .big{font-size:2.4rem;font-weight:800}' +
        '.cvss-result-card .lbl{font-size:.72rem;color:var(--mut,#6b7280);text-transform:uppercase;margin-top:4px}' +
        '.cvss-examples{margin-top:20px}' +
        '.cvss-ex-card{background:var(--surface,#0d1117);border:1px solid var(--border,#21262d);border-radius:6px;padding:12px;margin-bottom:6px;display:flex;gap:12px;align-items:center}' +
        '.cvss-ex-score{font-size:1.1rem;font-weight:800;min-width:50px;text-align:center}' +
        '.cvss-ex-info{flex:1}' +
        '.cvss-ex-cve{font-family:monospace;font-size:.75rem;color:var(--acc,#00d4ff)}' +
        '.cvss-ex-name{font-weight:600;font-size:.85rem;margin-top:2px}' +
        '.cvss-ex-desc{font-size:.75rem;color:var(--mut,#6b7280);margin-top:2px;line-height:1.4}' +
        '.cvss-ex-vec{font-family:monospace;font-size:.65rem;color:var(--mut,#6b7280);margin-top:2px}' +
        '.cvss-sev-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:700}' +
        '.cvss-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}' +
        '@media(max-width:800px){.cvss-grid{grid-template-columns:1fr}}' +
        '.cvss-filter-row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}' +
        '.cvss-filter-btn{padding:4px 12px;border:1px solid var(--border,#21262d);border-radius:4px;background:none;color:var(--txt,#c8d6e5);cursor:pointer;font-size:.72rem;font-family:inherit}' +
        '.cvss-filter-btn.active{background:var(--acc,#00d4ff);color:#0d1117;border-color:var(--acc,#00d4ff)}' +
      '</style>' +
      '<div class="rc">' +
        '<h2>Risk Assessment Calculator</h2>' +
        '<p style="color:var(--mut,#6b7280);font-size:.85rem;margin:0 0 8px">' + THREAT_SCENARIOS.length + ' threat scenarios -- ALE calculator -- risk register -- CVSS v3.1 calculator</p>' +
        '<div class="rc-tabs">' + tabsHtml + '</div>' +
        '<div id="rc-view"></div>' +
      '</div>';

    container.querySelectorAll(".rc-tab").forEach(function(t) {
      t.addEventListener("click", function() { activeView = t.dataset.v; render(); });
    });
    var view = container.querySelector("#rc-view");
    if (activeView === "matrix") renderMatrix(view);
    else if (activeView === "register") renderRegister(view);
    else if (activeView === "ale") renderALE(view);
    else if (activeView === "cvss") renderCVSSCalc(view);
    else renderStats(view);
  }

  function renderMatrix(el){
    var html = '<h3 style="font-size:1rem;margin:0 0 12px">Risk Matrix (Likelihood x Impact)</h3><div class="rc-matrix">';
    html += '<div class="rc-cell header"></div>';
    for(var i=1;i<=5;i++) html += '<div class="rc-cell header">' + esc(IMPACT_LABELS[i]) + '</div>';
    for(var l=5;l>=1;l--){
      html += '<div class="rc-cell header">' + esc(RISK_LABELS[l]) + '</div>';
      for(var i2=1;i2<=5;i2++){
        var score = l*i2;
        var threats = THREAT_SCENARIOS.filter(function(t){return t.likelihood===l&&t.impact===i2});
        var bg = riskColor(score);
        html += '<div class="rc-cell data" style="background:' + bg + '22;border:1px solid ' + bg + '44;color:' + bg + '" title="' + esc(threats.map(function(t){return t.name}).join(", ")||"No threats") + '">' + score + (threats.length ? '<span style="font-size:.65rem;margin-top:2px">(' + threats.length + ')</span>' : "") + '</div>';
      }
    }
    html += '</div>';
    html += '<p style="font-size:.8rem;color:var(--mut)">Hover over cells to see assigned threats. Scores: <span style="color:#ef4444">15-25 Critical</span> -- <span style="color:#f97316">10-14 High</span> -- <span style="color:#eab308">5-9 Medium</span> -- <span style="color:#22c55e">1-4 Low</span></p>';
    el.innerHTML = html;
  }

  function renderRegister(el){
    var cats = ["all"];
    var catSet = {};
    THREAT_SCENARIOS.forEach(function(t) { if (!catSet[t.category]) { catSet[t.category] = true; cats.push(t.category); } });
    var sorted = THREAT_SCENARIOS.slice();
    if(filterCat!=="all") sorted = sorted.filter(function(t){return t.category===filterCat});
    sorted.sort(function(a,b){
      var va,vb;
      if(sortField==="risk"){va=riskScore(a);vb=riskScore(b)}
      else if(sortField==="name"){va=a.name;vb=b.name}
      else if(sortField==="ale"){va=a.ale.sle*a.ale.aro;vb=b.ale.sle*b.ale.aro}
      else{va=a[sortField];vb=b[sortField]}
      if(typeof va==="string") return sortDir==="asc"?va.localeCompare(vb):vb.localeCompare(va);
      return sortDir==="asc"?va-vb:vb-va;
    });
    var catOpts = "";
    for (var ci = 0; ci < cats.length; ci++) {
      catOpts += '<option value="' + cats[ci] + '"' + (filterCat === cats[ci] ? " selected" : "") + '>' + cats[ci] + '</option>';
    }
    var rows = "";
    for (var ri = 0; ri < sorted.length; ri++) {
      var t = sorted[ri];
      var s = riskScore(t);
      rows += '<tr><td>' + esc(t.name) + '</td><td>' + esc(t.category) + '</td><td>' + t.likelihood + ' (' + RISK_LABELS[t.likelihood] + ')</td><td>' + t.impact + ' (' + IMPACT_LABELS[t.impact] + ')</td><td><span class="rc-badge" style="background:' + riskColor(s) + '22;color:' + riskColor(s) + '">' + s + ' ' + riskLevel(s) + '</span></td><td>' + fmt$(t.ale.sle*t.ale.aro) + '/yr</td><td style="font-size:.75rem">' + t.existing_controls.join(", ") + '</td></tr>';
    }
    el.innerHTML =
      '<div class="rc-filter"><label style="font-size:.85rem">Category:</label><select id="rc-cat">' + catOpts + '</select><span style="font-size:.8rem;color:var(--mut)">' + sorted.length + ' threats</span></div>' +
      '<table class="rc-tbl"><thead><tr>' +
        '<th data-s="name">Threat</th><th data-s="category">Category</th><th data-s="likelihood">Likelihood</th><th data-s="impact">Impact</th><th data-s="risk">Risk</th><th data-s="ale">ALE</th><th>Controls</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table>';
    el.querySelector("#rc-cat").addEventListener("change",function(e){filterCat=e.target.value;render()});
    el.querySelectorAll("th[data-s]").forEach(function(th){th.addEventListener("click",function(){if(sortField===th.dataset.s)sortDir=sortDir==="asc"?"desc":"asc";else{sortField=th.dataset.s;sortDir="desc"}render()})});
  }

  function renderALE(el){
    var sorted = THREAT_SCENARIOS.slice().sort(function(a,b){return (b.ale.sle*b.ale.aro)-(a.ale.sle*a.ale.aro)});
    var totalALE = sorted.reduce(function(s,t){return s+t.ale.sle*t.ale.aro},0);
    var aleRows = "";
    var count = Math.min(sorted.length, 20);
    for (var ai = 0; ai < count; ai++) {
      var t = sorted[ai];
      var ale = t.ale.sle * t.ale.aro;
      var pct = ((ale / totalALE) * 100).toFixed(1);
      aleRows += '<tr><td>' + esc(t.name) + '</td><td>' + fmt$(t.ale.sle) + '</td><td>' + t.ale.aro + '</td><td style="font-weight:700;color:' + riskColor(ale>100000?15:ale>30000?10:5) + '">' + fmt$(ale) + '</td><td><div style="display:flex;align-items:center;gap:8px"><div style="width:80px;height:8px;background:var(--border,#21262d);border-radius:4px;overflow:hidden"><div style="width:' + pct + '%;height:100%;background:var(--acc,#00d4ff);border-radius:4px"></div></div>' + pct + '%</div></td></tr>';
    }
    el.innerHTML =
      '<div class="rc-ale">' +
        '<h3 style="margin:0 0 12px;font-size:1rem">Annual Loss Expectancy Calculator</h3>' +
        '<p style="font-size:.85rem;color:var(--mut)">ALE = SLE x ARO (Single Loss Expectancy x Annual Rate of Occurrence)</p>' +
        '<div class="rc-stat"><div class="rc-stat-card"><h4>Total ALE</h4><div class="val" style="color:#ef4444">' + fmt$(totalALE) + '</div></div><div class="rc-stat-card"><h4>Threats Assessed</h4><div class="val" style="color:var(--acc,#00d4ff)">' + THREAT_SCENARIOS.length + '</div></div><div class="rc-stat-card"><h4>Top Risk</h4><div class="val" style="color:#f97316;font-size:1rem">' + esc(sorted[0].name) + '</div></div></div>' +
        '<table class="rc-tbl" style="margin-top:16px"><thead><tr><th>Threat</th><th>SLE</th><th>ARO</th><th>ALE</th><th>% of Total</th></tr></thead><tbody>' + aleRows + '</tbody></table>' +
      '</div>';
  }

  function renderStats(el){
    var byCat = {};
    THREAT_SCENARIOS.forEach(function(t){byCat[t.category]=(byCat[t.category]||0)+1});
    var byLevel = {critical:0,high:0,medium:0,low:0};
    THREAT_SCENARIOS.forEach(function(t){byLevel[riskLevel(riskScore(t))]++});
    var totalALE = THREAT_SCENARIOS.reduce(function(s,t){return s+t.ale.sle*t.ale.aro},0);
    var catBars = "";
    var catKeys = Object.keys(byCat);
    for (var ci = 0; ci < catKeys.length; ci++) {
      var cat = catKeys[ci];
      var count = byCat[cat];
      catBars += '<div style="display:flex;align-items:center;gap:12px;margin:6px 0"><span style="width:120px;font-size:.85rem">' + esc(cat) + '</span><div style="flex:1;height:20px;background:var(--border,#21262d);border-radius:4px;overflow:hidden"><div style="width:' + ((count/THREAT_SCENARIOS.length)*100) + '%;height:100%;background:var(--acc,#00d4ff);border-radius:4px"></div></div><span style="font-size:.85rem;width:30px;text-align:right">' + count + '</span></div>';
    }
    var treatmentCards = "";
    for (var ti = 0; ti < TREATMENT.length; ti++) {
      var tr = TREATMENT[ti];
      treatmentCards += '<div style="background:var(--surface,#0d1117);border:1px solid var(--border,#21262d);border-radius:8px;padding:14px"><h4 style="margin:0 0 6px;color:var(--acc,#00d4ff);font-size:.9rem">' + esc(tr.name) + '</h4><p style="margin:0;font-size:.82rem;color:var(--mut,#6b7280)">' + esc(tr.desc) + '</p></div>';
    }
    el.innerHTML =
      '<div class="rc-stat">' +
        '<div class="rc-stat-card"><h4>Total Threats</h4><div class="val" style="color:var(--acc)">' + THREAT_SCENARIOS.length + '</div></div>' +
        '<div class="rc-stat-card"><h4>Critical</h4><div class="val" style="color:#ef4444">' + byLevel.critical + '</div></div>' +
        '<div class="rc-stat-card"><h4>High</h4><div class="val" style="color:#f97316">' + byLevel.high + '</div></div>' +
        '<div class="rc-stat-card"><h4>Medium</h4><div class="val" style="color:#eab308">' + byLevel.medium + '</div></div>' +
        '<div class="rc-stat-card"><h4>Low</h4><div class="val" style="color:#22c55e">' + byLevel.low + '</div></div>' +
        '<div class="rc-stat-card"><h4>Total ALE</h4><div class="val" style="color:#ef4444">' + fmt$(totalALE) + '</div></div>' +
      '</div>' +
      '<h3 style="font-size:1rem;margin:20px 0 12px">By Category</h3>' + catBars +
      '<h3 style="font-size:1rem;margin:20px 0 12px">Risk Treatment Options</h3>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px">' + treatmentCards + '</div>';
  }

  function renderCVSSCalc(el) {
    var result = calcCVSS();
    var metricsHtml = "";
    for (var mi = 0; mi < CVSS_METRICS.length; mi++) {
      var metric = CVSS_METRICS[mi];
      var btns = "";
      for (var oi = 0; oi < metric.options.length; oi++) {
        var opt = metric.options[oi];
        var selected = cvssSelections[metric.key] === oi;
        btns += '<button class="cvss-btn' + (selected ? " sel" : "") + '" data-metric="' + metric.key + '" data-idx="' + oi + '">' + esc(opt.label) + ' (' + esc(opt.abbr) + ')</button>';
      }
      metricsHtml += '<div class="cvss-metric">' +
        '<div class="cvss-metric-name">' + esc(metric.name) + ' (' + esc(metric.key) + ')</div>' +
        '<div class="cvss-metric-desc">' + esc(metric.desc) + '</div>' +
        '<div class="cvss-btns">' + btns + '</div>' +
      '</div>';
    }

    var scoreDisplay = "";
    if (result) {
      var sc = result.score;
      var sevLabel = severityLabel(sc);
      var sevCol = severityColor(sc);
      var pctWidth = (sc / 10) * 100;
      scoreDisplay =
        '<div style="margin-top:16px">' +
          '<h3 style="font-size:1rem;margin:0 0 10px">Base Score</h3>' +
          '<div class="cvss-gauge">' +
            '<div class="cvss-gauge-fill" style="width:' + pctWidth + '%;background:' + sevCol + '"></div>' +
            '<div class="cvss-gauge-label" style="color:#fff">' + sc.toFixed(1) + ' ' + sevLabel + '</div>' +
          '</div>' +
          '<div class="cvss-vector" style="color:var(--acc,#00d4ff)">' + esc(result.vector) + '</div>' +
          '<div class="cvss-result">' +
            '<div class="cvss-result-card"><div class="big" style="color:' + sevCol + '">' + sc.toFixed(1) + '</div><div class="lbl">Base Score</div></div>' +
            '<div class="cvss-result-card"><div class="big" style="color:' + sevCol + '">' + sevLabel + '</div><div class="lbl">Severity</div></div>' +
            '<div class="cvss-result-card"><div class="big" style="color:var(--acc,#00d4ff)">' + result.impact.toFixed(1) + '</div><div class="lbl">Impact</div></div>' +
            '<div class="cvss-result-card"><div class="big" style="color:var(--acc,#00d4ff)">' + result.exploitability.toFixed(1) + '</div><div class="lbl">Exploitability</div></div>' +
          '</div>' +
        '</div>';

      // Severity scale visualization
      scoreDisplay += '<div style="margin-top:16px"><h3 style="font-size:1rem;margin:0 0 10px">Severity Scale</h3>' +
        '<div style="display:flex;height:32px;border-radius:6px;overflow:hidden;font-size:.7rem;font-weight:600;margin-bottom:4px">' +
          '<div style="flex:0.1;background:#6b728044;display:flex;align-items:center;justify-content:center;color:#6b7280' + (sc === 0 ? ';outline:2px solid #fff' : '') + '">0</div>' +
          '<div style="flex:3.9;background:#22c55e44;display:flex;align-items:center;justify-content:center;color:#22c55e' + (sc > 0 && sc <= 3.9 ? ';outline:2px solid #fff' : '') + '">Low</div>' +
          '<div style="flex:3;background:#eab30844;display:flex;align-items:center;justify-content:center;color:#eab308' + (sc >= 4 && sc <= 6.9 ? ';outline:2px solid #fff' : '') + '">Medium</div>' +
          '<div style="flex:2;background:#f9731644;display:flex;align-items:center;justify-content:center;color:#f97316' + (sc >= 7 && sc <= 8.9 ? ';outline:2px solid #fff' : '') + '">High</div>' +
          '<div style="flex:1;background:#ef444444;display:flex;align-items:center;justify-content:center;color:#ef4444' + (sc >= 9 ? ';outline:2px solid #fff' : '') + '">Crit</div>' +
        '</div>' +
        '<div style="position:relative;height:12px;margin-top:4px"><div style="position:absolute;left:' + pctWidth + '%;transform:translateX(-50%);width:0;height:0;border-left:6px solid transparent;border-right:6px solid transparent;border-bottom:8px solid ' + sevCol + '"></div></div>' +
      '</div>';
    } else {
      scoreDisplay = '<div style="margin-top:16px;padding:24px;text-align:center;color:var(--mut,#6b7280);background:var(--surface,#0d1117);border:1px solid var(--border,#21262d);border-radius:8px">Select all 8 metrics above to calculate the CVSS v3.1 Base Score</div>';
    }

    // CVE examples section
    var sevFilter = "all";
    var examplesHtml = '<div class="cvss-examples">' +
      '<h3 style="font-size:1rem;margin:0 0 10px">Historical CVE Examples</h3>' +
      '<div style="display:grid;gap:6px">';
    for (var ei = 0; ei < CVE_EXAMPLES.length; ei++) {
      var ex = CVE_EXAMPLES[ei];
      var exCol = severityColor(ex.score);
      examplesHtml += '<div class="cvss-ex-card">' +
        '<div class="cvss-ex-score" style="color:' + exCol + '">' + ex.score.toFixed(1) + '</div>' +
        '<div class="cvss-ex-info">' +
          '<div style="display:flex;align-items:center;gap:6px">' +
            '<span class="cvss-ex-cve">' + esc(ex.cve) + '</span>' +
            '<span class="cvss-sev-badge" style="background:' + exCol + '22;color:' + exCol + '">' + esc(ex.severity) + '</span>' +
          '</div>' +
          '<div class="cvss-ex-name">' + esc(ex.name) + '</div>' +
          '<div class="cvss-ex-desc">' + esc(ex.desc) + '</div>' +
          '<div class="cvss-ex-vec">' + esc(ex.vector) + '</div>' +
        '</div>' +
      '</div>';
    }
    examplesHtml += '</div></div>';

    el.innerHTML =
      '<div class="cvss-grid">' +
        '<div>' +
          '<h3 style="font-size:1rem;margin:0 0 12px">CVSS v3.1 Base Score Calculator</h3>' +
          '<p style="font-size:.78rem;color:var(--mut,#6b7280);margin:0 0 12px">Select values for all 8 base metrics to calculate the CVSS v3.1 score using the official formula.</p>' +
          metricsHtml +
        '</div>' +
        '<div>' + scoreDisplay + examplesHtml + '</div>' +
      '</div>';

    el.querySelectorAll(".cvss-btn").forEach(function(btn) {
      btn.addEventListener("click", function() {
        cvssSelections[btn.dataset.metric] = parseInt(btn.dataset.idx);
        render();
      });
    });
  }

  render();
}
