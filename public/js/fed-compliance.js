const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);

// ═══════════════════════════════════════════════════════════════════════════════
// NIST 800-53 Rev5 Controls (subset — representative across all families)
// ═══════════════════════════════════════════════════════════════════════════════
const NIST_CONTROLS = [
  { id:'AC-1', family:'Access Control', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate access control policy and procedures.' },
  { id:'AC-2', family:'Access Control', title:'Account Management', baseline:'L', desc:'Define and document account types; create, enable, modify, disable, and remove accounts in accordance with policy.' },
  { id:'AC-3', family:'Access Control', title:'Access Enforcement', baseline:'L', desc:'Enforce approved authorizations for logical access to information and system resources.' },
  { id:'AC-4', family:'Access Control', title:'Information Flow Enforcement', baseline:'M', desc:'Enforce approved authorizations for controlling the flow of information within the system and between systems.' },
  { id:'AC-5', family:'Access Control', title:'Separation of Duties', baseline:'M', desc:'Separate duties of individuals to reduce risk of malicious activity without collusion.' },
  { id:'AC-6', family:'Access Control', title:'Least Privilege', baseline:'M', desc:'Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.' },
  { id:'AC-7', family:'Access Control', title:'Unsuccessful Logon Attempts', baseline:'L', desc:'Enforce a limit of consecutive invalid logon attempts and automatically lock/delay after threshold.' },
  { id:'AC-8', family:'Access Control', title:'System Use Notification', baseline:'L', desc:'Display an approved system use notification message before granting access.' },
  { id:'AC-11', family:'Access Control', title:'Device Lock', baseline:'M', desc:'Prevent further access to the system by initiating a device lock after a period of inactivity.' },
  { id:'AC-12', family:'Access Control', title:'Session Termination', baseline:'M', desc:'Automatically terminate a user session after conditions defined by the organization.' },
  { id:'AC-14', family:'Access Control', title:'Permitted Actions Without Identification', baseline:'L', desc:'Identify user actions that can be performed without identification or authentication.' },
  { id:'AC-17', family:'Access Control', title:'Remote Access', baseline:'L', desc:'Establish usage restrictions, configuration requirements, and implementation guidance for each type of remote access.' },
  { id:'AC-18', family:'Access Control', title:'Wireless Access', baseline:'L', desc:'Establish usage restrictions, configuration requirements, and implementation guidance for wireless access.' },
  { id:'AC-19', family:'Access Control', title:'Access Control for Mobile Devices', baseline:'L', desc:'Establish usage restrictions and implementation guidance for organization-controlled mobile devices.' },
  { id:'AC-20', family:'Access Control', title:'Use of External Systems', baseline:'L', desc:'Establish terms and conditions for authorized individuals to access the system from external systems.' },
  { id:'AC-22', family:'Access Control', title:'Publicly Accessible Content', baseline:'L', desc:'Designate individuals authorized to post information onto publicly accessible systems.' },
  { id:'AU-1', family:'Audit and Accountability', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate audit and accountability policy and procedures.' },
  { id:'AU-2', family:'Audit and Accountability', title:'Event Logging', baseline:'L', desc:'Identify events that the system is capable of logging in support of the audit function.' },
  { id:'AU-3', family:'Audit and Accountability', title:'Content of Audit Records', baseline:'L', desc:'Ensure audit records contain information about what, when, where, source, outcome, and identity.' },
  { id:'AU-4', family:'Audit and Accountability', title:'Audit Log Storage Capacity', baseline:'L', desc:'Allocate audit log storage capacity and configure auditing to reduce the likelihood of capacity being exceeded.' },
  { id:'AU-5', family:'Audit and Accountability', title:'Response to Audit Logging Process Failures', baseline:'L', desc:'Alert personnel or roles in event of an audit logging process failure and take defined additional actions.' },
  { id:'AU-6', family:'Audit and Accountability', title:'Audit Record Review, Analysis, and Reporting', baseline:'L', desc:'Review and analyze system audit records for indications of inappropriate or unusual activity.' },
  { id:'AU-8', family:'Audit and Accountability', title:'Time Stamps', baseline:'L', desc:'Use internal system clocks to generate time stamps for audit records.' },
  { id:'AU-9', family:'Audit and Accountability', title:'Protection of Audit Information', baseline:'L', desc:'Protect audit information and audit logging tools from unauthorized access, modification, and deletion.' },
  { id:'AU-11', family:'Audit and Accountability', title:'Audit Record Retention', baseline:'L', desc:'Retain audit records for a defined time period to support after-the-fact investigations.' },
  { id:'AU-12', family:'Audit and Accountability', title:'Audit Record Generation', baseline:'L', desc:'Provide audit record generation capability for the event types the system is capable of auditing.' },
  { id:'AT-1', family:'Awareness and Training', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate awareness and training policy and procedures.' },
  { id:'AT-2', family:'Awareness and Training', title:'Literacy Training and Awareness', baseline:'L', desc:'Provide security and privacy literacy training to system users.' },
  { id:'AT-3', family:'Awareness and Training', title:'Role-Based Training', baseline:'L', desc:'Provide role-based security and privacy training to personnel with assigned security roles.' },
  { id:'AT-4', family:'Awareness and Training', title:'Training Records', baseline:'L', desc:'Document and monitor individual information security and privacy training activities.' },
  { id:'CA-1', family:'Assessment, Authorization, and Monitoring', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate assessment, authorization, and monitoring policy.' },
  { id:'CA-2', family:'Assessment, Authorization, and Monitoring', title:'Control Assessments', baseline:'L', desc:'Assess the controls in the system and its environment of operation.' },
  { id:'CA-3', family:'Assessment, Authorization, and Monitoring', title:'Information Exchange', baseline:'L', desc:'Approve and manage the exchange of information between the system and other systems.' },
  { id:'CA-5', family:'Assessment, Authorization, and Monitoring', title:'Plan of Action and Milestones', baseline:'L', desc:'Develop a plan of action and milestones for the system to document planned remedial actions.' },
  { id:'CA-6', family:'Assessment, Authorization, and Monitoring', title:'Authorization', baseline:'L', desc:'Assign a senior official to authorize the system before commencing operations.' },
  { id:'CA-7', family:'Assessment, Authorization, and Monitoring', title:'Continuous Monitoring', baseline:'L', desc:'Develop a system-level continuous monitoring strategy and implement continuous monitoring.' },
  { id:'CA-9', family:'Assessment, Authorization, and Monitoring', title:'Internal System Connections', baseline:'L', desc:'Authorize internal connections of system components and monitor the connections.' },
  { id:'CM-1', family:'Configuration Management', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate configuration management policy and procedures.' },
  { id:'CM-2', family:'Configuration Management', title:'Baseline Configuration', baseline:'L', desc:'Develop, document, and maintain a current baseline configuration of the system.' },
  { id:'CM-3', family:'Configuration Management', title:'Configuration Change Control', baseline:'M', desc:'Determine and document types of changes to the system that are configuration-controlled.' },
  { id:'CM-4', family:'Configuration Management', title:'Impact Analyses', baseline:'M', desc:'Analyze changes to the system to determine potential security and privacy impacts prior to change implementation.' },
  { id:'CM-5', family:'Configuration Management', title:'Access Restrictions for Change', baseline:'M', desc:'Define, document, approve, and enforce physical and logical access restrictions for changes to the system.' },
  { id:'CM-6', family:'Configuration Management', title:'Configuration Settings', baseline:'L', desc:'Establish and document configuration settings for components using the most restrictive mode consistent with requirements.' },
  { id:'CM-7', family:'Configuration Management', title:'Least Functionality', baseline:'L', desc:'Configure the system to provide only mission-essential capabilities.' },
  { id:'CM-8', family:'Configuration Management', title:'System Component Inventory', baseline:'L', desc:'Develop and document an inventory of system components that accurately reflects the system.' },
  { id:'CM-10', family:'Configuration Management', title:'Software Usage Restrictions', baseline:'L', desc:'Use software and associated documentation in accordance with contract agreements and copyright laws.' },
  { id:'CM-11', family:'Configuration Management', title:'User-Installed Software', baseline:'L', desc:'Establish and enforce policies governing the installation of software by users.' },
  { id:'CP-1', family:'Contingency Planning', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate contingency planning policy and procedures.' },
  { id:'CP-2', family:'Contingency Planning', title:'Contingency Plan', baseline:'L', desc:'Develop a contingency plan for the system that identifies essential missions and business functions.' },
  { id:'CP-3', family:'Contingency Planning', title:'Contingency Training', baseline:'L', desc:'Provide contingency training to system users consistent with assigned roles and responsibilities.' },
  { id:'CP-4', family:'Contingency Planning', title:'Contingency Plan Testing', baseline:'M', desc:'Test the contingency plan for the system to determine the effectiveness of the plan.' },
  { id:'CP-9', family:'Contingency Planning', title:'System Backup', baseline:'L', desc:'Conduct backups of user-level, system-level, and system documentation information.' },
  { id:'CP-10', family:'Contingency Planning', title:'System Recovery and Reconstitution', baseline:'L', desc:'Provide for the recovery and reconstitution of the system to a known state within a defined time period.' },
  { id:'IA-1', family:'Identification and Authentication', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate identification and authentication policy and procedures.' },
  { id:'IA-2', family:'Identification and Authentication', title:'Identification and Authentication (Organizational Users)', baseline:'L', desc:'Uniquely identify and authenticate organizational users.' },
  { id:'IA-3', family:'Identification and Authentication', title:'Device Identification and Authentication', baseline:'M', desc:'Uniquely identify and authenticate devices before establishing a connection.' },
  { id:'IA-4', family:'Identification and Authentication', title:'Identifier Management', baseline:'L', desc:'Manage system identifiers by receiving authorization and issuing the identifier to the intended individual or device.' },
  { id:'IA-5', family:'Identification and Authentication', title:'Authenticator Management', baseline:'L', desc:'Manage system authenticators by verifying identity before distributing initial authenticator.' },
  { id:'IA-6', family:'Identification and Authentication', title:'Authentication Feedback', baseline:'L', desc:'Obscure feedback of authentication information during the authentication process.' },
  { id:'IA-7', family:'Identification and Authentication', title:'Cryptographic Module Authentication', baseline:'L', desc:'Implement mechanisms for authentication to a cryptographic module that meet applicable requirements.' },
  { id:'IA-8', family:'Identification and Authentication', title:'Identification and Authentication (Non-Organizational Users)', baseline:'L', desc:'Uniquely identify and authenticate non-organizational users or processes.' },
  { id:'IA-11', family:'Identification and Authentication', title:'Re-authentication', baseline:'L', desc:'Require users to re-authenticate when circumstances or situations require re-authentication.' },
  { id:'IR-1', family:'Incident Response', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate incident response policy and procedures.' },
  { id:'IR-2', family:'Incident Response', title:'Incident Response Training', baseline:'L', desc:'Provide incident response training to system users consistent with assigned roles.' },
  { id:'IR-3', family:'Incident Response', title:'Incident Response Testing', baseline:'M', desc:'Test the incident response capability using defined tests.' },
  { id:'IR-4', family:'Incident Response', title:'Incident Handling', baseline:'L', desc:'Implement an incident handling capability for incidents that includes preparation, detection, analysis, containment, eradication, recovery.' },
  { id:'IR-5', family:'Incident Response', title:'Incident Monitoring', baseline:'L', desc:'Track and document incidents.' },
  { id:'IR-6', family:'Incident Response', title:'Incident Reporting', baseline:'L', desc:'Require personnel to report suspected incidents to the organizational incident response capability.' },
  { id:'IR-7', family:'Incident Response', title:'Incident Response Assistance', baseline:'L', desc:'Provide an incident response support resource that offers advice and assistance to users.' },
  { id:'IR-8', family:'Incident Response', title:'Incident Response Plan', baseline:'L', desc:'Develop an incident response plan that provides a roadmap for implementing its incident response capability.' },
  { id:'MA-1', family:'Maintenance', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate maintenance policy and procedures.' },
  { id:'MA-2', family:'Maintenance', title:'Controlled Maintenance', baseline:'L', desc:'Schedule, document, and review records of maintenance and repairs on system components.' },
  { id:'MA-4', family:'Maintenance', title:'Nonlocal Maintenance', baseline:'L', desc:'Approve and monitor nonlocal maintenance and diagnostic activities.' },
  { id:'MA-5', family:'Maintenance', title:'Maintenance Personnel', baseline:'L', desc:'Establish a process for maintenance personnel authorization and maintain a list of authorized personnel.' },
  { id:'MP-1', family:'Media Protection', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate media protection policy and procedures.' },
  { id:'MP-2', family:'Media Protection', title:'Media Access', baseline:'L', desc:'Restrict access to digital and/or non-digital media to authorized individuals.' },
  { id:'MP-6', family:'Media Protection', title:'Media Sanitization', baseline:'L', desc:'Sanitize system media prior to disposal, release, or reuse.' },
  { id:'MP-7', family:'Media Protection', title:'Media Use', baseline:'L', desc:'Restrict the use of certain types of media on systems or system components.' },
  { id:'PE-1', family:'Physical and Environmental Protection', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate physical and environmental protection policy.' },
  { id:'PE-2', family:'Physical and Environmental Protection', title:'Physical Access Authorizations', baseline:'L', desc:'Develop, approve, and maintain a list of individuals with authorized access to the facility.' },
  { id:'PE-3', family:'Physical and Environmental Protection', title:'Physical Access Control', baseline:'L', desc:'Enforce physical access authorizations at entry/exit points to the facility.' },
  { id:'PE-6', family:'Physical and Environmental Protection', title:'Monitoring Physical Access', baseline:'L', desc:'Monitor physical access to the facility where the system resides to detect and respond to incidents.' },
  { id:'PE-8', family:'Physical and Environmental Protection', title:'Visitor Access Records', baseline:'L', desc:'Maintain visitor access records to the facility where the system resides.' },
  { id:'PL-1', family:'Planning', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate planning policy and procedures.' },
  { id:'PL-2', family:'Planning', title:'System Security and Privacy Plans', baseline:'L', desc:'Develop security and privacy plans for the system that describe the controls in place or planned.' },
  { id:'PL-4', family:'Planning', title:'Rules of Behavior', baseline:'L', desc:'Establish and provide to individuals requiring access to the system, the rules that describe their responsibilities.' },
  { id:'PS-1', family:'Personnel Security', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate personnel security policy and procedures.' },
  { id:'PS-2', family:'Personnel Security', title:'Position Risk Designation', baseline:'L', desc:'Assign a risk designation to all organizational positions.' },
  { id:'PS-3', family:'Personnel Security', title:'Personnel Screening', baseline:'L', desc:'Screen individuals prior to authorizing access to the system.' },
  { id:'PS-4', family:'Personnel Security', title:'Personnel Termination', baseline:'L', desc:'Upon termination of employment, disable system access within a defined time period.' },
  { id:'PS-5', family:'Personnel Security', title:'Personnel Transfer', baseline:'L', desc:'Review and confirm ongoing operational need for current access when individuals are reassigned or transferred.' },
  { id:'PS-6', family:'Personnel Security', title:'Access Agreements', baseline:'L', desc:'Ensure that individuals requiring access to organizational information sign access agreements.' },
  { id:'PS-7', family:'Personnel Security', title:'External Personnel Security', baseline:'L', desc:'Establish personnel security requirements for external providers.' },
  { id:'PS-8', family:'Personnel Security', title:'Personnel Sanctions', baseline:'L', desc:'Employ a formal sanctions process for individuals failing to comply with policies and procedures.' },
  { id:'RA-1', family:'Risk Assessment', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate risk assessment policy and procedures.' },
  { id:'RA-2', family:'Risk Assessment', title:'Security Categorization', baseline:'L', desc:'Categorize the system and information processed, stored, and transmitted.' },
  { id:'RA-3', family:'Risk Assessment', title:'Risk Assessment', baseline:'L', desc:'Conduct a risk assessment, including identifying threats and vulnerabilities.' },
  { id:'RA-5', family:'Risk Assessment', title:'Vulnerability Monitoring and Scanning', baseline:'L', desc:'Monitor and scan for vulnerabilities in the system and applications.' },
  { id:'SA-1', family:'System and Services Acquisition', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate system and services acquisition policy.' },
  { id:'SA-2', family:'System and Services Acquisition', title:'Allocation of Resources', baseline:'L', desc:'Determine the high-level information security requirements for the system.' },
  { id:'SA-3', family:'System and Services Acquisition', title:'System Development Life Cycle', baseline:'L', desc:'Manage the system using an SDLC methodology that incorporates information security considerations.' },
  { id:'SA-4', family:'System and Services Acquisition', title:'Acquisition Process', baseline:'L', desc:'Include security and privacy functional requirements in the acquisition contract.' },
  { id:'SA-5', family:'System and Services Acquisition', title:'System Documentation', baseline:'L', desc:'Obtain or develop administrator and user documentation for the system.' },
  { id:'SA-9', family:'System and Services Acquisition', title:'External System Services', baseline:'L', desc:'Require that providers of external system services comply with organizational security requirements.' },
  { id:'SC-1', family:'System and Communications Protection', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate system and communications protection policy.' },
  { id:'SC-5', family:'System and Communications Protection', title:'Denial-of-Service Protection', baseline:'L', desc:'Protect against or limit the effects of denial-of-service attacks.' },
  { id:'SC-7', family:'System and Communications Protection', title:'Boundary Protection', baseline:'L', desc:'Monitor and control communications at the external managed interfaces to the system.' },
  { id:'SC-8', family:'System and Communications Protection', title:'Transmission Confidentiality and Integrity', baseline:'M', desc:'Protect the confidentiality and integrity of transmitted information.' },
  { id:'SC-12', family:'System and Communications Protection', title:'Cryptographic Key Establishment and Management', baseline:'L', desc:'Establish and manage cryptographic keys when cryptography is employed.' },
  { id:'SC-13', family:'System and Communications Protection', title:'Cryptographic Protection', baseline:'L', desc:'Determine the applicability of cryptography and implement required cryptographic mechanisms.' },
  { id:'SC-15', family:'System and Communications Protection', title:'Collaborative Computing Devices and Applications', baseline:'L', desc:'Prohibit remote activation of collaborative computing devices and provide indication of use.' },
  { id:'SC-20', family:'System and Communications Protection', title:'Secure Name/Address Resolution (Authoritative Source)', baseline:'L', desc:'Provide additional data origin and integrity verification artifacts along with authoritative name resolution data.' },
  { id:'SC-21', family:'System and Communications Protection', title:'Secure Name/Address Resolution (Recursive or Caching Resolver)', baseline:'L', desc:'Request and perform data origin authentication and data integrity verification on name/address resolution responses.' },
  { id:'SC-22', family:'System and Communications Protection', title:'Architecture and Provisioning for Name/Address Resolution', baseline:'L', desc:'Ensure the systems performing name/address resolution are fault-tolerant and implement internal/external role separation.' },
  { id:'SC-39', family:'System and Communications Protection', title:'Process Isolation', baseline:'L', desc:'Maintain a separate execution domain for each executing system process.' },
  { id:'SI-1', family:'System and Information Integrity', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate system and information integrity policy.' },
  { id:'SI-2', family:'System and Information Integrity', title:'Flaw Remediation', baseline:'L', desc:'Identify, report, and correct system flaws.' },
  { id:'SI-3', family:'System and Information Integrity', title:'Malicious Code Protection', baseline:'L', desc:'Implement malicious code protection mechanisms at system entry and exit points.' },
  { id:'SI-4', family:'System and Information Integrity', title:'System Monitoring', baseline:'L', desc:'Monitor the system to detect attacks and indicators of potential attacks.' },
  { id:'SI-5', family:'System and Information Integrity', title:'Security Alerts, Advisories, and Directives', baseline:'L', desc:'Receive system security alerts, advisories, and directives from external organizations on an ongoing basis.' },
  { id:'SI-10', family:'System and Information Integrity', title:'Information Input Validation', baseline:'M', desc:'Check the validity of information inputs.' },
  { id:'SI-12', family:'System and Information Integrity', title:'Information Management and Retention', baseline:'L', desc:'Manage and retain information within the system in accordance with applicable laws.' },
  { id:'SR-1', family:'Supply Chain Risk Management', title:'Policy and Procedures', baseline:'L', desc:'Develop, document, and disseminate supply chain risk management policy.' },
  { id:'SR-2', family:'Supply Chain Risk Management', title:'Supply Chain Risk Management Plan', baseline:'L', desc:'Develop a plan for managing supply chain risks associated with the development and procurement of systems.' },
  { id:'SR-3', family:'Supply Chain Risk Management', title:'Supply Chain Controls and Processes', baseline:'L', desc:'Establish a process to identify and address weaknesses or deficiencies in the supply chain.' },
  { id:'SR-5', family:'Supply Chain Risk Management', title:'Acquisition Strategies, Tools, and Methods', baseline:'L', desc:'Employ acquisition strategies, contract tools, and procurement methods to protect against supply chain risks.' },
  { id:'SR-6', family:'Supply Chain Risk Management', title:'Supplier Assessments and Reviews', baseline:'M', desc:'Assess and review the supply chain-related risks associated with suppliers or contractors.' },
  { id:'SR-11', family:'Supply Chain Risk Management', title:'Component Authenticity', baseline:'M', desc:'Develop and implement anti-counterfeit policy and procedures for detection and prevention of counterfeit components.' },
];

// ═══════════════════════════════════════════════════════════════════════════════
// CSF 2.0 Functions and Categories
// ═══════════════════════════════════════════════════════════════════════════════
const CSF_FUNCTIONS = [
  { id:'GV', name:'Govern', color:'#60a5fa', categories:[
    { id:'GV.OC', title:'Organizational Context', desc:'The circumstances surrounding cybersecurity risk management are understood.' },
    { id:'GV.RM', title:'Risk Management Strategy', desc:'The organization\'s priorities, constraints, and risk appetite are established and communicated.' },
    { id:'GV.RR', title:'Roles, Responsibilities, and Authorities', desc:'Cybersecurity roles, responsibilities, and authorities are established.' },
    { id:'GV.PO', title:'Policy', desc:'Organizational cybersecurity policy is established, communicated, and enforced.' },
    { id:'GV.OV', title:'Oversight', desc:'Results of organization-wide cybersecurity risk management activities are used to inform and adjust strategy.' },
    { id:'GV.SC', title:'Cybersecurity Supply Chain Risk Management', desc:'Cyber supply chain risk management processes are established and managed.' }
  ]},
  { id:'ID', name:'Identify', color:'#a78bfa', categories:[
    { id:'ID.AM', title:'Asset Management', desc:'Assets that enable the organization to achieve business purposes are identified and managed.' },
    { id:'ID.RA', title:'Risk Assessment', desc:'The cybersecurity risk to the organization is understood.' },
    { id:'ID.IM', title:'Improvement', desc:'Improvements to organizational cybersecurity risk management are identified.' }
  ]},
  { id:'PR', name:'Protect', color:'#34d399', categories:[
    { id:'PR.AA', title:'Identity Management, Authentication, and Access Control', desc:'Access to assets is limited to authorized users, services, and hardware.' },
    { id:'PR.AT', title:'Awareness and Training', desc:'The organization personnel are provided awareness and training.' },
    { id:'PR.DS', title:'Data Security', desc:'Data are managed consistent with the organization risk strategy.' },
    { id:'PR.PS', title:'Platform Security', desc:'The hardware, software, and services of physical and virtual platforms are managed.' },
    { id:'PR.IR', title:'Technology Infrastructure Resilience', desc:'Security architectures are managed to protect asset confidentiality, integrity, and availability.' }
  ]},
  { id:'DE', name:'Detect', color:'#fbbf24', categories:[
    { id:'DE.CM', title:'Continuous Monitoring', desc:'Assets are monitored to find anomalies, indicators of compromise, and other potentially adverse events.' },
    { id:'DE.AE', title:'Adverse Event Analysis', desc:'Anomalies, indicators of compromise, and other adverse events are analyzed.' }
  ]},
  { id:'RS', name:'Respond', color:'#f87171', categories:[
    { id:'RS.MA', title:'Incident Management', desc:'Responses to detected incidents are managed.' },
    { id:'RS.AN', title:'Incident Analysis', desc:'Investigations are conducted to ensure effective response.' },
    { id:'RS.CO', title:'Incident Response Reporting and Communication', desc:'Response activities are coordinated with internal and external stakeholders.' },
    { id:'RS.MI', title:'Incident Mitigation', desc:'Activities are performed to prevent expansion of an event and mitigate its effects.' }
  ]},
  { id:'RC', name:'Recover', color:'#4ade80', categories:[
    { id:'RC.RP', title:'Incident Recovery Plan Execution', desc:'Restoration activities are performed to ensure operational availability.' },
    { id:'RC.CO', title:'Incident Recovery Communication', desc:'Restoration activities are coordinated with internal and external parties.' }
  ]}
];

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-walk mappings
// ═══════════════════════════════════════════════════════════════════════════════
const CROSSWALK = {
  'AC-1':  { csf:'GV.PO / PR.AA', fedramp:'AC-1', cmmc:'AC.L1-b.1.i', cjis:'5.5', hipaa:'§164.312(a)(1)' },
  'AC-2':  { csf:'PR.AA', fedramp:'AC-2', cmmc:'AC.L1-b.1.ii', cjis:'5.5.2', hipaa:'§164.312(a)(2)(i)' },
  'AC-3':  { csf:'PR.AA', fedramp:'AC-3', cmmc:'AC.L1-b.1.iii', cjis:'5.5.2.1', hipaa:'§164.312(a)(1)' },
  'AC-5':  { csf:'PR.AA', fedramp:'AC-5', cmmc:'AC.L2-3.1.4', cjis:'5.5.1', hipaa:'§164.312(a)(1)' },
  'AC-6':  { csf:'PR.AA', fedramp:'AC-6', cmmc:'AC.L2-3.1.5', cjis:'5.5.2', hipaa:'§164.312(a)(1)' },
  'AC-7':  { csf:'PR.AA', fedramp:'AC-7', cmmc:'AC.L2-3.1.8', cjis:'5.5.3', hipaa:'§164.312(a)(2)(i)' },
  'AC-17': { csf:'PR.AA / PR.PS', fedramp:'AC-17', cmmc:'AC.L2-3.1.12', cjis:'5.5.6', hipaa:'§164.312(e)(1)' },
  'AU-2':  { csf:'DE.CM', fedramp:'AU-2', cmmc:'AU.L2-3.3.1', cjis:'5.4.1', hipaa:'§164.312(b)' },
  'AU-3':  { csf:'DE.CM', fedramp:'AU-3', cmmc:'AU.L2-3.3.2', cjis:'5.4.1.1', hipaa:'§164.312(b)' },
  'AU-6':  { csf:'DE.AE / RS.AN', fedramp:'AU-6', cmmc:'AU.L2-3.3.5', cjis:'5.4.3', hipaa:'§164.312(b)' },
  'AT-2':  { csf:'PR.AT', fedramp:'AT-2', cmmc:'AT.L2-3.2.1', cjis:'5.2.1', hipaa:'§164.308(a)(5)(i)' },
  'AT-3':  { csf:'PR.AT', fedramp:'AT-3', cmmc:'AT.L2-3.2.2', cjis:'5.2.2', hipaa:'§164.308(a)(5)(i)' },
  'CA-2':  { csf:'ID.RA / GV.OV', fedramp:'CA-2', cmmc:'CA.L2-3.12.1', cjis:'5.11', hipaa:'§164.308(a)(8)' },
  'CA-5':  { csf:'ID.IM', fedramp:'CA-5', cmmc:'CA.L2-3.12.2', cjis:'5.11', hipaa:'§164.308(a)(1)(ii)(B)' },
  'CA-7':  { csf:'DE.CM / GV.OV', fedramp:'CA-7', cmmc:'CA.L2-3.12.3', cjis:'5.11', hipaa:'§164.308(a)(8)' },
  'CM-2':  { csf:'PR.PS', fedramp:'CM-2', cmmc:'CM.L2-3.4.1', cjis:'5.7.1', hipaa:'§164.312(a)(2)(iv)' },
  'CM-6':  { csf:'PR.PS', fedramp:'CM-6', cmmc:'CM.L2-3.4.2', cjis:'5.7.1', hipaa:'§164.312(a)(2)(iv)' },
  'CM-7':  { csf:'PR.PS', fedramp:'CM-7', cmmc:'CM.L2-3.4.6', cjis:'5.7.1.1', hipaa:'§164.312(a)(2)(iv)' },
  'CM-8':  { csf:'ID.AM', fedramp:'CM-8', cmmc:'CM.L2-3.4.8', cjis:'5.7.1', hipaa:'§164.310(d)(1)' },
  'CP-2':  { csf:'PR.IR / RC.RP', fedramp:'CP-2', cmmc:'N/A', cjis:'5.11', hipaa:'§164.308(a)(7)(i)' },
  'CP-9':  { csf:'PR.IR', fedramp:'CP-9', cmmc:'N/A', cjis:'5.11.2', hipaa:'§164.308(a)(7)(ii)(A)' },
  'IA-2':  { csf:'PR.AA', fedramp:'IA-2', cmmc:'IA.L1-b.1.vi', cjis:'5.6.2.1', hipaa:'§164.312(d)' },
  'IA-5':  { csf:'PR.AA', fedramp:'IA-5', cmmc:'IA.L2-3.5.7', cjis:'5.6.2.1', hipaa:'§164.312(d)' },
  'IR-1':  { csf:'RS.MA', fedramp:'IR-1', cmmc:'IR.L2-3.6.1', cjis:'5.3', hipaa:'§164.308(a)(6)(i)' },
  'IR-4':  { csf:'RS.MA / RS.MI', fedramp:'IR-4', cmmc:'IR.L2-3.6.1', cjis:'5.3.1', hipaa:'§164.308(a)(6)(ii)' },
  'IR-6':  { csf:'RS.CO', fedramp:'IR-6', cmmc:'IR.L2-3.6.2', cjis:'5.3.2', hipaa:'§164.308(a)(6)(ii)' },
  'IR-8':  { csf:'RS.MA', fedramp:'IR-8', cmmc:'IR.L2-3.6.1', cjis:'5.3', hipaa:'§164.308(a)(6)(i)' },
  'MA-2':  { csf:'PR.PS', fedramp:'MA-2', cmmc:'MA.L2-3.7.1', cjis:'5.8', hipaa:'§164.310(a)(2)(iv)' },
  'MP-2':  { csf:'PR.DS', fedramp:'MP-2', cmmc:'MP.L1-b.1.vii', cjis:'5.9', hipaa:'§164.310(d)(1)' },
  'MP-6':  { csf:'PR.DS', fedramp:'MP-6', cmmc:'MP.L2-3.8.3', cjis:'5.9.2', hipaa:'§164.310(d)(2)(i)' },
  'PE-2':  { csf:'PR.AA', fedramp:'PE-2', cmmc:'PE.L1-b.1.viii', cjis:'5.12.1', hipaa:'§164.310(a)(1)' },
  'PE-3':  { csf:'PR.AA', fedramp:'PE-3', cmmc:'PE.L1-b.1.ix', cjis:'5.12.1.1', hipaa:'§164.310(a)(2)(ii)' },
  'PL-2':  { csf:'GV.RM', fedramp:'PL-2', cmmc:'N/A', cjis:'5.1.1', hipaa:'§164.308(a)(1)(i)' },
  'PS-3':  { csf:'GV.RR', fedramp:'PS-3', cmmc:'PS.L2-3.9.1', cjis:'5.12.6', hipaa:'§164.308(a)(3)(ii)(B)' },
  'RA-3':  { csf:'ID.RA', fedramp:'RA-3', cmmc:'RA.L2-3.11.1', cjis:'5.11', hipaa:'§164.308(a)(1)(ii)(A)' },
  'RA-5':  { csf:'ID.RA / DE.CM', fedramp:'RA-5', cmmc:'RA.L2-3.11.2', cjis:'5.11', hipaa:'§164.308(a)(1)(ii)(A)' },
  'SC-7':  { csf:'PR.IR / PR.PS', fedramp:'SC-7', cmmc:'SC.L1-b.1.x', cjis:'5.10.1', hipaa:'§164.312(e)(1)' },
  'SC-8':  { csf:'PR.DS', fedramp:'SC-8', cmmc:'SC.L2-3.13.8', cjis:'5.10.1.2', hipaa:'§164.312(e)(2)(ii)' },
  'SC-13': { csf:'PR.DS', fedramp:'SC-13', cmmc:'SC.L2-3.13.11', cjis:'5.10.1.3', hipaa:'§164.312(a)(2)(iv)' },
  'SI-2':  { csf:'PR.PS / ID.RA', fedramp:'SI-2', cmmc:'SI.L1-b.1.xii', cjis:'5.10.4', hipaa:'§164.308(a)(5)(ii)(B)' },
  'SI-3':  { csf:'DE.CM', fedramp:'SI-3', cmmc:'SI.L1-b.1.xiii', cjis:'5.10.4.1', hipaa:'§164.308(a)(5)(ii)(B)' },
  'SI-4':  { csf:'DE.CM / DE.AE', fedramp:'SI-4', cmmc:'SI.L2-3.14.6', cjis:'5.10.4.2', hipaa:'§164.312(b)' },
  'SR-1':  { csf:'GV.SC', fedramp:'SR-1', cmmc:'N/A', cjis:'N/A', hipaa:'§164.308(a)(1)(i)' },
};

// ═══════════════════════════════════════════════════════════════════════════════
// CMMC 2.0 Practice Domains
// ═══════════════════════════════════════════════════════════════════════════════
const CMMC_DOMAINS = [
  { abbr:'AC', name:'Access Control', l1:4, l2:22 },
  { abbr:'AT', name:'Awareness & Training', l1:0, l2:3 },
  { abbr:'AU', name:'Audit & Accountability', l1:0, l2:9 },
  { abbr:'CA', name:'Assessment', l1:0, l2:4 },
  { abbr:'CM', name:'Configuration Mgmt', l1:0, l2:9 },
  { abbr:'IA', name:'Identification & Auth', l1:2, l2:11 },
  { abbr:'IR', name:'Incident Response', l1:0, l2:3 },
  { abbr:'MA', name:'Maintenance', l1:0, l2:6 },
  { abbr:'MP', name:'Media Protection', l1:1, l2:9 },
  { abbr:'PE', name:'Physical Protection', l1:4, l2:6 },
  { abbr:'PS', name:'Personnel Security', l1:0, l2:2 },
  { abbr:'RA', name:'Risk Assessment', l1:0, l2:3 },
  { abbr:'SC', name:'Sys & Comm Protection', l1:2, l2:16 },
  { abbr:'SI', name:'Sys & Info Integrity', l1:4, l2:7 },
];

// ATO Package Items
const ATO_ITEMS = [
  { id:'ssp', name:'System Security Plan (SSP)', desc:'Comprehensive document describing the security controls in place or planned for the system.' },
  { id:'ra', name:'Risk Assessment Report', desc:'Identifies threats and vulnerabilities, assesses likelihood and impact, and determines risk levels.' },
  { id:'sar', name:'Security Assessment Report (SAR)', desc:'Results from assessing controls — findings, recommendations, and residual risks.' },
  { id:'poam', name:'Plan of Action & Milestones (POA&M)', desc:'Tracks known weaknesses, planned remediation actions, milestones, and completion dates.' },
  { id:'cp', name:'Contingency Plan', desc:'Recovery strategy for the system in the event of disruption.' },
  { id:'cmp', name:'Configuration Management Plan', desc:'Procedures for managing system changes and maintaining baseline configurations.' },
  { id:'irp', name:'Incident Response Plan', desc:'Defines procedures for detecting, reporting, and responding to security incidents.' },
  { id:'pia', name:'Privacy Impact Assessment (PIA)', desc:'Analysis of how PII is collected, stored, shared, and protected.' },
  { id:'ibm', name:'Interconnection Security Agreements (ISA/MOU)', desc:'Agreements governing how the system connects to external systems securely.' },
  { id:'ua', name:'User Agreement / Rules of Behavior', desc:'Document signed by users acknowledging acceptable use policies.' },
];

// Inheritance model
const INHERITANCE = {
  'On-Premises': { customer: 95, shared: 5, inherited: 0 },
  'IaaS': { customer: 70, shared: 20, inherited: 10 },
  'PaaS': { customer: 45, shared: 30, inherited: 25 },
  'SaaS': { customer: 20, shared: 25, inherited: 55 },
  'Hybrid': { customer: 60, shared: 25, inherited: 15 },
};

const INHERITANCE_FAMILIES = {
  'On-Premises': {
    'Access Control': 'customer', 'Audit and Accountability': 'customer', 'Configuration Management': 'customer',
    'Contingency Planning': 'customer', 'Identification and Authentication': 'customer', 'Incident Response': 'customer',
    'Maintenance': 'customer', 'Media Protection': 'customer', 'Personnel Security': 'customer',
    'Physical and Environmental Protection': 'customer', 'Risk Assessment': 'customer', 'System and Communications Protection': 'customer',
    'System and Information Integrity': 'customer', 'Supply Chain Risk Management': 'customer',
    'Awareness and Training': 'customer', 'Assessment, Authorization, and Monitoring': 'customer', 'Planning': 'customer',
    'System and Services Acquisition': 'customer',
  },
  'IaaS': {
    'Access Control': 'customer', 'Audit and Accountability': 'shared', 'Configuration Management': 'customer',
    'Contingency Planning': 'shared', 'Identification and Authentication': 'customer', 'Incident Response': 'shared',
    'Maintenance': 'inherited', 'Media Protection': 'shared', 'Personnel Security': 'customer',
    'Physical and Environmental Protection': 'inherited', 'Risk Assessment': 'shared', 'System and Communications Protection': 'shared',
    'System and Information Integrity': 'customer', 'Supply Chain Risk Management': 'shared',
    'Awareness and Training': 'customer', 'Assessment, Authorization, and Monitoring': 'shared', 'Planning': 'customer',
    'System and Services Acquisition': 'shared',
  },
  'PaaS': {
    'Access Control': 'shared', 'Audit and Accountability': 'shared', 'Configuration Management': 'shared',
    'Contingency Planning': 'shared', 'Identification and Authentication': 'shared', 'Incident Response': 'shared',
    'Maintenance': 'inherited', 'Media Protection': 'inherited', 'Personnel Security': 'customer',
    'Physical and Environmental Protection': 'inherited', 'Risk Assessment': 'shared', 'System and Communications Protection': 'inherited',
    'System and Information Integrity': 'shared', 'Supply Chain Risk Management': 'shared',
    'Awareness and Training': 'customer', 'Assessment, Authorization, and Monitoring': 'shared', 'Planning': 'customer',
    'System and Services Acquisition': 'shared',
  },
  'SaaS': {
    'Access Control': 'shared', 'Audit and Accountability': 'inherited', 'Configuration Management': 'inherited',
    'Contingency Planning': 'inherited', 'Identification and Authentication': 'shared', 'Incident Response': 'shared',
    'Maintenance': 'inherited', 'Media Protection': 'inherited', 'Personnel Security': 'customer',
    'Physical and Environmental Protection': 'inherited', 'Risk Assessment': 'shared', 'System and Communications Protection': 'inherited',
    'System and Information Integrity': 'inherited', 'Supply Chain Risk Management': 'shared',
    'Awareness and Training': 'customer', 'Assessment, Authorization, and Monitoring': 'shared', 'Planning': 'customer',
    'System and Services Acquisition': 'inherited',
  },
  'Hybrid': {
    'Access Control': 'customer', 'Audit and Accountability': 'shared', 'Configuration Management': 'shared',
    'Contingency Planning': 'shared', 'Identification and Authentication': 'shared', 'Incident Response': 'shared',
    'Maintenance': 'shared', 'Media Protection': 'shared', 'Personnel Security': 'customer',
    'Physical and Environmental Protection': 'shared', 'Risk Assessment': 'shared', 'System and Communications Protection': 'shared',
    'System and Information Integrity': 'shared', 'Supply Chain Risk Management': 'shared',
    'Awareness and Training': 'customer', 'Assessment, Authorization, and Monitoring': 'shared', 'Planning': 'customer',
    'System and Services Acquisition': 'shared',
  },
};

// Evidence types per family
const EVIDENCE_TYPES = [
  'Policy Document', 'Standard Operating Procedure', 'Technical Screenshot', 'Scan Results',
  'Audit Logs', 'Configuration Export', 'Training Records', 'Interview Notes',
  'Architecture Diagram', 'Test Results', 'Certificate / Attestation', 'Vendor Documentation'
];

// ═══════════════════════════════════════════════════════════════════════════════
// STYLES
// ═══════════════════════════════════════════════════════════════════════════════
const STYLE = `
.fc-wrap { font-family: ui-sans-serif,system-ui,-apple-system,sans-serif; color: #e6eefc; max-width: 1200px; margin: 0 auto; }
.fc-header { margin-bottom: 24px; }
.fc-title { font-size: 1.5rem; font-weight: 700; margin: 0 0 4px; }
.fc-subtitle { font-size: .85rem; color: #7a93b8; margin: 0; }
.fc-tabs { display: flex; gap: 2px; border-bottom: 2px solid #1a2a44; margin-bottom: 20px; overflow-x: auto; }
.fc-tab { padding: 10px 16px; font-size: .78rem; font-weight: 600; color: #7a93b8; background: none; border: none; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; white-space: nowrap; font-family: inherit; transition: all .2s; }
.fc-tab:hover { color: #c8d6e5; }
.fc-tab.active { color: #00d4ff; border-bottom-color: #00d4ff; }
.fc-panel { display: none; }
.fc-panel.active { display: block; }
.fc-section { background: #0f1726; border: 1px solid #1a2a44; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.fc-section-title { font-size: .8rem; font-weight: 700; color: #00d4ff; text-transform: uppercase; letter-spacing: .08em; margin: 0 0 12px; font-family: 'JetBrains Mono',ui-monospace,monospace; }
.fc-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
.fc-stat { background: #0f1726; border: 1px solid #1a2a44; border-radius: 8px; padding: 14px; text-align: center; }
.fc-stat-val { font-size: 1.6rem; font-weight: 700; font-family: 'JetBrains Mono',ui-monospace,monospace; }
.fc-stat-label { font-size: .7rem; color: #7a93b8; text-transform: uppercase; letter-spacing: .06em; margin-top: 4px; }
.fc-table { width: 100%; border-collapse: collapse; font-size: .78rem; }
.fc-table th { text-align: left; padding: 8px 10px; color: #7a93b8; font-size: .68rem; text-transform: uppercase; letter-spacing: .06em; border-bottom: 2px solid #1a2a44; font-weight: 700; position: sticky; top: 0; background: #0f1726; z-index: 1; }
.fc-table td { padding: 8px 10px; border-bottom: 1px solid #111828; }
.fc-table tr:hover td { background: #151f34; }
.fc-table code, .fc-mono { font-family: 'JetBrains Mono',ui-monospace,monospace; font-size: .75rem; }
.fc-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .65rem; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.fc-badge-l { background: #16a34a22; color: #4ade80; }
.fc-badge-m { background: #eab30822; color: #fbbf24; }
.fc-badge-h { background: #ef444422; color: #f87171; }
.fc-accordion { margin-bottom: 8px; }
.fc-acc-header { display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: #111828; border: 1px solid #1a2a44; border-radius: 6px; cursor: pointer; user-select: none; transition: background .2s; }
.fc-acc-header:hover { background: #151f34; }
.fc-acc-header.open { border-radius: 6px 6px 0 0; border-bottom-color: transparent; }
.fc-acc-arrow { font-size: 10px; color: #7a93b8; transition: transform .2s; }
.fc-acc-header.open .fc-acc-arrow { transform: rotate(90deg); }
.fc-acc-title { font-size: .82rem; font-weight: 600; flex: 1; }
.fc-acc-count { font-size: .7rem; color: #7a93b8; }
.fc-acc-body { display: none; border: 1px solid #1a2a44; border-top: none; border-radius: 0 0 6px 6px; padding: 12px; background: #0c1020; }
.fc-acc-header.open + .fc-acc-body { display: block; }
.fc-check-row { display: flex; align-items: center; gap: 10px; padding: 6px 8px; border-bottom: 1px solid #111828; font-size: .78rem; }
.fc-check-row:last-child { border-bottom: none; }
.fc-check-row label { flex: 1; display: flex; align-items: center; gap: 8px; cursor: pointer; }
.fc-check-row input[type=checkbox] { accent-color: #00d4ff; width: 16px; height: 16px; }
.fc-ctrl-id { font-family: 'JetBrains Mono',ui-monospace,monospace; color: #00d4ff; font-size: .75rem; min-width: 50px; }
.fc-progress-ring { position: relative; width: 100px; height: 100px; margin: 0 auto; }
.fc-progress-ring svg { transform: rotate(-90deg); }
.fc-progress-ring-val { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; font-weight: 700; font-family: 'JetBrains Mono',ui-monospace,monospace; }
.fc-form-row { display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.fc-form-label { font-size: .75rem; color: #7a93b8; text-transform: uppercase; letter-spacing: .04em; min-width: 120px; }
.fc-input, .fc-select, .fc-textarea { background: #0c1020; border: 1px solid #1a2a44; color: #e6eefc; border-radius: 6px; padding: 8px 12px; font-size: .82rem; font-family: inherit; width: 100%; }
.fc-textarea { min-height: 60px; resize: vertical; }
.fc-select { cursor: pointer; }
.fc-input:focus, .fc-select:focus, .fc-textarea:focus { outline: none; border-color: #00d4ff; box-shadow: 0 0 0 3px rgba(0,212,255,.15); }
.fc-btn { padding: 8px 18px; border: none; border-radius: 6px; font-size: .8rem; font-weight: 600; cursor: pointer; font-family: inherit; transition: all .2s; }
.fc-btn-primary { background: #00d4ff; color: #04121a; }
.fc-btn-primary:hover { background: #33ddff; }
.fc-btn-ghost { background: transparent; border: 1px solid #1a2a44; color: #e6eefc; }
.fc-btn-ghost:hover { border-color: #00d4ff; color: #00d4ff; }
.fc-grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.fc-grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }
.fc-csf-fn { padding: 12px; border-radius: 8px; border-left: 4px solid; margin-bottom: 10px; }
.fc-csf-fn-name { font-size: .82rem; font-weight: 700; margin-bottom: 6px; }
.fc-csf-cat { padding: 6px 10px; background: #0c102088; border-radius: 4px; margin-bottom: 4px; font-size: .75rem; }
.fc-csf-cat-id { font-family: 'JetBrains Mono',ui-monospace,monospace; color: #00d4ff; margin-right: 8px; }
.fc-inherit-bar { height: 24px; display: flex; border-radius: 6px; overflow: hidden; margin: 8px 0; }
.fc-inherit-seg { display: flex; align-items: center; justify-content: center; font-size: .65rem; font-weight: 700; }
.fc-inherit-customer { background: #3b82f6; color: #fff; }
.fc-inherit-shared { background: #eab308; color: #000; }
.fc-inherit-inherited { background: #22c55e; color: #000; }
.fc-ato-item { display: flex; align-items: center; gap: 12px; padding: 12px; background: #111828; border: 1px solid #1a2a44; border-radius: 6px; margin-bottom: 8px; }
.fc-ato-status { min-width: 110px; }
.fc-ato-name { font-weight: 600; font-size: .82rem; }
.fc-ato-desc { font-size: .72rem; color: #7a93b8; margin-top: 2px; }
.fc-status-badge { padding: 3px 10px; border-radius: 4px; font-size: .65rem; font-weight: 700; text-transform: uppercase; display: inline-block; }
.fc-status-complete { background: #16a34a22; color: #4ade80; }
.fc-status-progress { background: #eab30822; color: #fbbf24; }
.fc-status-notstarted { background: #ef444422; color: #f87171; }
.fc-poam-entry { background: #111828; border: 1px solid #1a2a44; border-radius: 8px; padding: 14px; margin-bottom: 12px; }
.fc-evidence-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px; }
.fc-evidence-item { background: #111828; border: 1px solid #1a2a44; border-radius: 6px; padding: 10px; display: flex; align-items: center; gap: 8px; font-size: .75rem; }
.fc-evidence-check { accent-color: #00d4ff; }
.fc-cmmc-domain { display: flex; align-items: center; gap: 12px; padding: 10px; border-bottom: 1px solid #111828; }
.fc-cmmc-abbr { background: #00d4ff22; color: #00d4ff; padding: 4px 10px; border-radius: 4px; font-family: 'JetBrains Mono',ui-monospace,monospace; font-size: .75rem; font-weight: 700; min-width: 36px; text-align: center; }
.fc-cmmc-name { flex: 1; font-size: .82rem; }
.fc-cmmc-counts { display: flex; gap: 12px; font-size: .72rem; color: #7a93b8; }
.fc-cmmc-bar { height: 6px; background: #1a2a44; border-radius: 3px; flex: 1; overflow: hidden; }
.fc-cmmc-fill { height: 100%; background: linear-gradient(90deg, #00d4ff, #7c5cff); border-radius: 3px; }
@media (max-width: 768px) {
  .fc-grid-2, .fc-grid-3 { grid-template-columns: 1fr; }
  .fc-tabs { flex-wrap: nowrap; }
  .fc-stats { grid-template-columns: repeat(2, 1fr); }
}

/* Pro theme */
[data-style=pro] .fc-wrap { color: #18181b; }
[data-style=pro] .fc-subtitle { color: #71717a; }
[data-style=pro] .fc-tab { color: #71717a; }
[data-style=pro] .fc-tab.active { color: #2563eb; border-bottom-color: #2563eb; }
[data-style=pro] .fc-tab:hover { color: #3f3f46; }
[data-style=pro] .fc-section { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .fc-section-title { color: #2563eb; }
[data-style=pro] .fc-stat { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .fc-stat-label { color: #71717a; }
[data-style=pro] .fc-table th { color: #71717a; border-bottom-color: #e5e5e5; background: #fff; }
[data-style=pro] .fc-table td { border-bottom-color: #f4f4f5; }
[data-style=pro] .fc-table tr:hover td { background: #f9fafb; }
[data-style=pro] .fc-ctrl-id, [data-style=pro] .fc-csf-cat-id { color: #2563eb; }
[data-style=pro] .fc-acc-header { background: #f9fafb; border-color: #e5e5e5; }
[data-style=pro] .fc-acc-header:hover { background: #f4f4f5; }
[data-style=pro] .fc-acc-body { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .fc-check-row { border-bottom-color: #f4f4f5; }
[data-style=pro] .fc-input, [data-style=pro] .fc-select, [data-style=pro] .fc-textarea { background: #fff; border-color: #e5e5e5; color: #18181b; }
[data-style=pro] .fc-input:focus, [data-style=pro] .fc-select:focus, [data-style=pro] .fc-textarea:focus { border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,.15); }
[data-style=pro] .fc-btn-primary { background: #2563eb; color: #fff; }
[data-style=pro] .fc-btn-primary:hover { background: #1d4ed8; }
[data-style=pro] .fc-btn-ghost { border-color: #e5e5e5; color: #18181b; }
[data-style=pro] .fc-btn-ghost:hover { border-color: #2563eb; color: #2563eb; }
[data-style=pro] .fc-ato-item { background: #f9fafb; border-color: #e5e5e5; }
[data-style=pro] .fc-poam-entry { background: #f9fafb; border-color: #e5e5e5; }
[data-style=pro] .fc-evidence-item { background: #f9fafb; border-color: #e5e5e5; }
[data-style=pro] .fc-cmmc-abbr { background: #2563eb22; color: #2563eb; }
[data-style=pro] .fc-cmmc-counts { color: #71717a; }
[data-style=pro] .fc-cmmc-domain { border-bottom-color: #f4f4f5; }
[data-style=pro] .fc-tabs { border-bottom-color: #e5e5e5; }
[data-style=pro] .fc-form-label { color: #71717a; }
`;

// ═══════════════════════════════════════════════════════════════════════════════
// RENDER
// ═══════════════════════════════════════════════════════════════════════════════
export function renderFedCompliance(container) {
  if (!document.getElementById('fc-style')) {
    const s = document.createElement('style');
    s.id = 'fc-style';
    s.textContent = STYLE;
    document.head.appendChild(s);
  }

  const families = [...new Set(NIST_CONTROLS.map(c => c.family))];
  const implementedKey = 'fc_implemented';
  let implemented = {};
  try { implemented = JSON.parse(localStorage.getItem(implementedKey)) || {}; } catch (_) {}
  function saveImpl() { try { localStorage.setItem(implementedKey, JSON.stringify(implemented)); } catch (_) {} }

  const atoStatusKey = 'fc_ato_status';
  let atoStatus = {};
  try { atoStatus = JSON.parse(localStorage.getItem(atoStatusKey)) || {}; } catch (_) {}
  function saveAto() { try { localStorage.setItem(atoStatusKey, JSON.stringify(atoStatus)); } catch (_) {} }

  const TABS = [
    ['crosswalk', 'Cross-Walk Matrix'],
    ['families', 'Control Families'],
    ['csf', 'NIST CSF 2.0'],
    ['cmmc', 'CMMC 2.0'],
    ['gap', 'Gap Analysis'],
    ['poam', 'POA&M Generator'],
    ['ato', 'ATO Checklist'],
    ['inherit', 'Inheritance Model'],
    ['evidence', 'Evidence Tracker'],
  ];

  let h = '<div class="fc-wrap">';
  h += '<div class="fc-header">';
  h += '<h1 class="fc-title">Federal Compliance Framework Mapper</h1>';
  h += '<p class="fc-subtitle">Cross-walk NIST 800-53 Rev5, CSF 2.0, FedRAMP, CMMC 2.0, FISMA, CJIS, and HIPAA — with gap analysis, POA&M generation, and ATO tracking</p>';
  h += '</div>';

  // Stats
  h += '<div class="fc-stats">';
  h += '<div class="fc-stat"><div class="fc-stat-val" style="color:#00d4ff">' + NIST_CONTROLS.length + '</div><div class="fc-stat-label">NIST Controls</div></div>';
  h += '<div class="fc-stat"><div class="fc-stat-val" style="color:#a78bfa">' + CSF_FUNCTIONS.reduce((a, f) => a + f.categories.length, 0) + '</div><div class="fc-stat-label">CSF Categories</div></div>';
  h += '<div class="fc-stat"><div class="fc-stat-val" style="color:#34d399">' + families.length + '</div><div class="fc-stat-label">Control Families</div></div>';
  h += '<div class="fc-stat"><div class="fc-stat-val" style="color:#fbbf24">7</div><div class="fc-stat-label">Frameworks</div></div>';
  h += '<div class="fc-stat"><div class="fc-stat-val" style="color:#f87171">' + Object.keys(CROSSWALK).length + '</div><div class="fc-stat-label">Cross-Walk Maps</div></div>';
  h += '</div>';

  // Tabs
  h += '<div class="fc-tabs">';
  TABS.forEach(([id, label], i) => {
    h += '<button class="fc-tab' + (i === 0 ? ' active' : '') + '" data-tab="' + id + '">' + esc(label) + '</button>';
  });
  h += '</div>';

  // ── Panel: Cross-Walk Matrix ──
  h += '<div class="fc-panel active" data-panel="crosswalk">';
  h += '<div class="fc-section"><div class="fc-section-title">NIST 800-53 Rev5 → Framework Cross-Walk</div>';
  h += '<div style="overflow-x:auto"><table class="fc-table"><thead><tr>';
  h += '<th>NIST 800-53</th><th>Title</th><th>CSF 2.0</th><th>FedRAMP</th><th>CMMC 2.0</th><th>CJIS</th><th>HIPAA</th>';
  h += '</tr></thead><tbody>';
  const cwKeys = Object.keys(CROSSWALK);
  cwKeys.forEach(cid => {
    const ctrl = NIST_CONTROLS.find(c => c.id === cid);
    const cw = CROSSWALK[cid];
    h += '<tr>';
    h += '<td><span class="fc-ctrl-id">' + esc(cid) + '</span></td>';
    h += '<td>' + (ctrl ? esc(ctrl.title) : '') + '</td>';
    h += '<td class="fc-mono">' + esc(cw.csf) + '</td>';
    h += '<td class="fc-mono">' + esc(cw.fedramp) + '</td>';
    h += '<td class="fc-mono">' + esc(cw.cmmc) + '</td>';
    h += '<td class="fc-mono">' + esc(cw.cjis) + '</td>';
    h += '<td class="fc-mono">' + esc(cw.hipaa) + '</td>';
    h += '</tr>';
  });
  h += '</tbody></table></div></div></div>';

  // ── Panel: Control Families ──
  h += '<div class="fc-panel" data-panel="families">';
  families.forEach(fam => {
    const controls = NIST_CONTROLS.filter(c => c.family === fam);
    h += '<div class="fc-accordion">';
    h += '<div class="fc-acc-header" data-family="' + esc(fam) + '">';
    h += '<span class="fc-acc-arrow">&#9654;</span>';
    h += '<span class="fc-acc-title">' + esc(fam) + '</span>';
    h += '<span class="fc-acc-count">' + controls.length + ' controls</span>';
    h += '</div>';
    h += '<div class="fc-acc-body">';
    controls.forEach(c => {
      h += '<div class="fc-check-row">';
      h += '<span class="fc-ctrl-id">' + esc(c.id) + '</span>';
      h += '<span style="flex:1">' + esc(c.title) + '</span>';
      h += '<span class="fc-badge fc-badge-' + c.baseline.toLowerCase() + '">' + (c.baseline === 'L' ? 'LOW' : c.baseline === 'M' ? 'MOD' : 'HIGH') + '</span>';
      h += '</div>';
    });
    h += '</div></div>';
  });
  h += '</div>';

  // ── Panel: CSF 2.0 ──
  h += '<div class="fc-panel" data-panel="csf">';
  h += '<div class="fc-section"><div class="fc-section-title">NIST Cybersecurity Framework 2.0 — Functions & Categories</div>';
  CSF_FUNCTIONS.forEach(fn => {
    h += '<div class="fc-csf-fn" style="border-color:' + fn.color + ';background:' + fn.color + '0a">';
    h += '<div class="fc-csf-fn-name" style="color:' + fn.color + '">' + esc(fn.id) + ' — ' + esc(fn.name) + '</div>';
    fn.categories.forEach(cat => {
      h += '<div class="fc-csf-cat"><span class="fc-csf-cat-id">' + esc(cat.id) + '</span>' + esc(cat.title) + ' — <span style="color:#7a93b8">' + esc(cat.desc) + '</span></div>';
    });
    h += '</div>';
  });
  h += '</div></div>';

  // ── Panel: CMMC 2.0 ──
  h += '<div class="fc-panel" data-panel="cmmc">';
  h += '<div class="fc-section"><div class="fc-section-title">CMMC 2.0 Practice Domains</div>';
  h += '<div class="fc-grid-2" style="margin-bottom:16px">';
  h += '<div class="fc-stat"><div class="fc-stat-val" style="color:#4ade80">17</div><div class="fc-stat-label">Level 1 Practices</div></div>';
  h += '<div class="fc-stat"><div class="fc-stat-val" style="color:#fbbf24">110</div><div class="fc-stat-label">Level 2 Practices</div></div>';
  h += '</div>';
  CMMC_DOMAINS.forEach(d => {
    const pct = Math.round((d.l1 + d.l2) / 130 * 100);
    h += '<div class="fc-cmmc-domain">';
    h += '<span class="fc-cmmc-abbr">' + esc(d.abbr) + '</span>';
    h += '<span class="fc-cmmc-name">' + esc(d.name) + '</span>';
    h += '<div class="fc-cmmc-counts"><span>L1: ' + d.l1 + '</span><span>L2: ' + d.l2 + '</span></div>';
    h += '<div class="fc-cmmc-bar" style="width:120px"><div class="fc-cmmc-fill" style="width:' + pct + '%"></div></div>';
    h += '</div>';
  });
  h += '</div></div>';

  // ── Panel: Gap Analysis ──
  h += '<div class="fc-panel" data-panel="gap">';
  h += '<div class="fc-grid-2">';
  h += '<div class="fc-section"><div class="fc-section-title">Compliance Progress</div>';
  h += '<div id="fc-gap-rings" style="display:flex;flex-wrap:wrap;gap:20px;justify-content:center"></div>';
  h += '</div>';
  h += '<div class="fc-section"><div class="fc-section-title">Missing Controls</div>';
  h += '<div id="fc-gap-missing" style="max-height:400px;overflow-y:auto"></div>';
  h += '</div>';
  h += '</div>';
  h += '<div class="fc-section"><div class="fc-section-title">Control Checklist — Mark Implemented</div>';
  families.forEach(fam => {
    const controls = NIST_CONTROLS.filter(c => c.family === fam);
    h += '<div class="fc-accordion">';
    h += '<div class="fc-acc-header" data-family="' + esc(fam) + '-gap">';
    h += '<span class="fc-acc-arrow">&#9654;</span>';
    h += '<span class="fc-acc-title">' + esc(fam) + '</span>';
    h += '<span class="fc-acc-count" id="fc-fam-count-' + esc(fam.replace(/[^a-zA-Z]/g,'')) + '">' + controls.filter(c => implemented[c.id]).length + '/' + controls.length + '</span>';
    h += '</div>';
    h += '<div class="fc-acc-body">';
    controls.forEach(c => {
      h += '<div class="fc-check-row">';
      h += '<label>';
      h += '<input type="checkbox" data-ctrl="' + esc(c.id) + '" data-fam="' + esc(fam.replace(/[^a-zA-Z]/g,'')) + '"' + (implemented[c.id] ? ' checked' : '') + '>';
      h += '<span class="fc-ctrl-id">' + esc(c.id) + '</span>';
      h += esc(c.title);
      h += '</label>';
      h += '</div>';
    });
    h += '</div></div>';
  });
  h += '</div></div>';

  // ── Panel: POA&M Generator ──
  h += '<div class="fc-panel" data-panel="poam">';
  h += '<div class="fc-section"><div class="fc-section-title">Plan of Action & Milestones Generator</div>';
  h += '<p style="font-size:.8rem;color:#7a93b8;margin:0 0 16px">Generate POA&M entries for unimplemented controls. Select a control to create an entry.</p>';
  h += '<div class="fc-form-row">';
  h += '<span class="fc-form-label">Control</span>';
  h += '<select class="fc-select" id="fc-poam-ctrl" style="max-width:300px">';
  NIST_CONTROLS.forEach(c => {
    if (!implemented[c.id]) h += '<option value="' + esc(c.id) + '">' + esc(c.id) + ' — ' + esc(c.title) + '</option>';
  });
  h += '</select>';
  h += '</div>';
  h += '<div class="fc-form-row"><span class="fc-form-label">Priority</span><select class="fc-select" id="fc-poam-priority" style="max-width:200px"><option>Critical</option><option selected>High</option><option>Moderate</option><option>Low</option></select></div>';
  h += '<div class="fc-form-row"><span class="fc-form-label">Scheduled Date</span><input type="date" class="fc-input" id="fc-poam-date" style="max-width:200px" value="2027-03-31"></div>';
  h += '<div class="fc-form-row"><span class="fc-form-label">Weakness</span><textarea class="fc-textarea" id="fc-poam-weakness" placeholder="Describe the weakness or gap..."></textarea></div>';
  h += '<div class="fc-form-row"><span class="fc-form-label">Milestones</span><textarea class="fc-textarea" id="fc-poam-milestones" placeholder="1. Draft policy (30 days)&#10;2. Implement control (60 days)&#10;3. Verify and test (90 days)"></textarea></div>';
  h += '<div class="fc-form-row"><span class="fc-form-label">Resources</span><input class="fc-input" id="fc-poam-resources" placeholder="e.g., ISSO, $15,000 for tooling, 2 FTEs"></div>';
  h += '<button class="fc-btn fc-btn-primary" id="fc-poam-gen">Generate POA&M Entry</button>';
  h += '<div id="fc-poam-output" style="margin-top:16px"></div>';
  h += '</div></div>';

  // ── Panel: ATO Checklist ──
  h += '<div class="fc-panel" data-panel="ato">';
  h += '<div class="fc-section"><div class="fc-section-title">Authority to Operate (ATO) Package Checklist</div>';
  ATO_ITEMS.forEach(item => {
    const st = atoStatus[item.id] || 'notstarted';
    h += '<div class="fc-ato-item">';
    h += '<div class="fc-ato-status"><select class="fc-select" data-ato="' + esc(item.id) + '" style="font-size:.72rem;padding:4px 8px">';
    h += '<option value="notstarted"' + (st === 'notstarted' ? ' selected' : '') + '>Not Started</option>';
    h += '<option value="progress"' + (st === 'progress' ? ' selected' : '') + '>In Progress</option>';
    h += '<option value="complete"' + (st === 'complete' ? ' selected' : '') + '>Complete</option>';
    h += '</select></div>';
    h += '<div style="flex:1"><div class="fc-ato-name">' + esc(item.name) + '</div><div class="fc-ato-desc">' + esc(item.desc) + '</div></div>';
    h += '</div>';
  });
  h += '</div></div>';

  // ── Panel: Inheritance Model ──
  h += '<div class="fc-panel" data-panel="inherit">';
  h += '<div class="fc-section"><div class="fc-section-title">Control Inheritance Model</div>';
  h += '<div class="fc-form-row"><span class="fc-form-label">Deployment Type</span>';
  h += '<select class="fc-select" id="fc-inherit-type" style="max-width:200px">';
  Object.keys(INHERITANCE).forEach(t => h += '<option>' + esc(t) + '</option>');
  h += '</select></div>';
  h += '<div id="fc-inherit-viz"></div>';
  h += '</div></div>';

  // ── Panel: Evidence Tracker ──
  h += '<div class="fc-panel" data-panel="evidence">';
  h += '<div class="fc-section"><div class="fc-section-title">Evidence Collection Tracker</div>';
  h += '<p style="font-size:.8rem;color:#7a93b8;margin:0 0 16px">Track evidence artifacts collected for each control family.</p>';
  families.forEach(fam => {
    h += '<div class="fc-accordion">';
    h += '<div class="fc-acc-header">';
    h += '<span class="fc-acc-arrow">&#9654;</span>';
    h += '<span class="fc-acc-title">' + esc(fam) + '</span>';
    h += '</div>';
    h += '<div class="fc-acc-body">';
    h += '<div class="fc-evidence-grid">';
    EVIDENCE_TYPES.forEach((et, ei) => {
      h += '<div class="fc-evidence-item"><input type="checkbox" class="fc-evidence-check" data-ev="' + esc(fam) + '-' + ei + '"> ' + esc(et) + '</div>';
    });
    h += '</div></div></div>';
  });
  h += '</div></div>';

  h += '</div>'; // fc-wrap
  container.innerHTML = h;

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERACTIVITY
  // ═══════════════════════════════════════════════════════════════════════════

  // Tab switching
  container.querySelectorAll('.fc-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      container.querySelectorAll('.fc-tab').forEach(t => t.classList.remove('active'));
      container.querySelectorAll('.fc-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const panel = container.querySelector('[data-panel="' + tab.dataset.tab + '"]');
      if (panel) panel.classList.add('active');
      if (tab.dataset.tab === 'gap') updateGapAnalysis();
      if (tab.dataset.tab === 'inherit') updateInheritance();
    });
  });

  // Accordion toggles
  container.querySelectorAll('.fc-acc-header').forEach(hdr => {
    hdr.addEventListener('click', () => {
      hdr.classList.toggle('open');
    });
  });

  // Gap analysis checkbox handling
  container.querySelectorAll('input[data-ctrl]').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) implemented[cb.dataset.ctrl] = true;
      else delete implemented[cb.dataset.ctrl];
      saveImpl();
      const famId = cb.dataset.fam;
      const famName = NIST_CONTROLS.find(c => c.id === cb.dataset.ctrl)?.family;
      if (famName) {
        const total = NIST_CONTROLS.filter(c => c.family === famName).length;
        const done = NIST_CONTROLS.filter(c => c.family === famName && implemented[c.id]).length;
        const el = container.querySelector('#fc-fam-count-' + famId);
        if (el) el.textContent = done + '/' + total;
      }
    });
  });

  // ATO status
  container.querySelectorAll('select[data-ato]').forEach(sel => {
    sel.addEventListener('change', () => {
      atoStatus[sel.dataset.ato] = sel.value;
      saveAto();
    });
  });

  // POA&M generator
  const poamBtn = container.querySelector('#fc-poam-gen');
  if (poamBtn) {
    poamBtn.addEventListener('click', () => {
      const ctrlId = container.querySelector('#fc-poam-ctrl')?.value;
      const ctrl = NIST_CONTROLS.find(c => c.id === ctrlId);
      const priority = container.querySelector('#fc-poam-priority')?.value || 'High';
      const date = container.querySelector('#fc-poam-date')?.value || '2027-03-31';
      const weakness = container.querySelector('#fc-poam-weakness')?.value || ctrl?.desc || '';
      const milestones = container.querySelector('#fc-poam-milestones')?.value || '';
      const resources = container.querySelector('#fc-poam-resources')?.value || '';
      const output = container.querySelector('#fc-poam-output');
      if (!output || !ctrl) return;
      const riskColor = priority === 'Critical' ? '#ef4444' : priority === 'High' ? '#f97316' : priority === 'Moderate' ? '#eab308' : '#22c55e';
      let ph = '<div class="fc-poam-entry">';
      ph += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">';
      ph += '<div style="font-weight:700;font-size:.9rem"><span class="fc-ctrl-id">' + esc(ctrlId) + '</span> ' + esc(ctrl.title) + '</div>';
      ph += '<span class="fc-badge" style="background:' + riskColor + '22;color:' + riskColor + '">' + esc(priority) + '</span>';
      ph += '</div>';
      ph += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:.78rem;margin-bottom:12px">';
      ph += '<div><strong style="color:#7a93b8">Scheduled Completion:</strong> ' + esc(date) + '</div>';
      ph += '<div><strong style="color:#7a93b8">Family:</strong> ' + esc(ctrl.family) + '</div>';
      ph += '</div>';
      ph += '<div style="font-size:.78rem;margin-bottom:8px"><strong style="color:#7a93b8">Weakness:</strong><br>' + esc(weakness) + '</div>';
      if (milestones) ph += '<div style="font-size:.78rem;margin-bottom:8px"><strong style="color:#7a93b8">Milestones:</strong><pre style="margin:4px 0;white-space:pre-wrap;font-family:inherit;color:#c8d6e5">' + esc(milestones) + '</pre></div>';
      if (resources) ph += '<div style="font-size:.78rem"><strong style="color:#7a93b8">Resources Required:</strong> ' + esc(resources) + '</div>';
      ph += '</div>';
      output.innerHTML = ph + output.innerHTML;
    });
  }

  // Inheritance model
  const inheritSelect = container.querySelector('#fc-inherit-type');
  if (inheritSelect) {
    inheritSelect.addEventListener('change', updateInheritance);
    updateInheritance();
  }

  function updateInheritance() {
    const type = container.querySelector('#fc-inherit-type')?.value || 'On-Premises';
    const viz = container.querySelector('#fc-inherit-viz');
    if (!viz) return;
    const dist = INHERITANCE[type];
    const famMap = INHERITANCE_FAMILIES[type] || {};
    let ih = '';
    ih += '<div style="margin:16px 0">';
    ih += '<div style="font-size:.78rem;margin-bottom:6px;color:#7a93b8">Overall Responsibility Distribution</div>';
    ih += '<div class="fc-inherit-bar">';
    if (dist.customer > 0) ih += '<div class="fc-inherit-seg fc-inherit-customer" style="width:' + dist.customer + '%">Customer ' + dist.customer + '%</div>';
    if (dist.shared > 0) ih += '<div class="fc-inherit-seg fc-inherit-shared" style="width:' + dist.shared + '%">Shared ' + dist.shared + '%</div>';
    if (dist.inherited > 0) ih += '<div class="fc-inherit-seg fc-inherit-inherited" style="width:' + dist.inherited + '%">Inherited ' + dist.inherited + '%</div>';
    ih += '</div>';
    ih += '<div style="display:flex;gap:20px;font-size:.72rem;margin-top:8px">';
    ih += '<span><span style="display:inline-block;width:12px;height:12px;background:#3b82f6;border-radius:2px;vertical-align:middle;margin-right:4px"></span> Customer</span>';
    ih += '<span><span style="display:inline-block;width:12px;height:12px;background:#eab308;border-radius:2px;vertical-align:middle;margin-right:4px"></span> Shared</span>';
    ih += '<span><span style="display:inline-block;width:12px;height:12px;background:#22c55e;border-radius:2px;vertical-align:middle;margin-right:4px"></span> CSP Inherited</span>';
    ih += '</div></div>';

    ih += '<table class="fc-table"><thead><tr><th>Control Family</th><th>Responsibility</th></tr></thead><tbody>';
    Object.entries(famMap).forEach(([fam, resp]) => {
      const color = resp === 'customer' ? '#3b82f6' : resp === 'shared' ? '#eab308' : '#22c55e';
      const label = resp === 'customer' ? 'Customer' : resp === 'shared' ? 'Shared' : 'CSP Inherited';
      ih += '<tr><td>' + esc(fam) + '</td><td><span class="fc-badge" style="background:' + color + '22;color:' + color + '">' + label + '</span></td></tr>';
    });
    ih += '</tbody></table>';
    viz.innerHTML = ih;
  }

  // Gap analysis rings
  function updateGapAnalysis() {
    const total = NIST_CONTROLS.length;
    const done = NIST_CONTROLS.filter(c => implemented[c.id]).length;

    const frameworks = [
      { name:'NIST 800-53', pct: Math.round(done / total * 100), color:'#00d4ff' },
      { name:'FedRAMP', pct: Math.round(done / total * 92), color:'#a78bfa' },
      { name:'CMMC L2', pct: Math.round(done / total * 85), color:'#34d399' },
      { name:'CSF 2.0', pct: Math.round(done / total * 95), color:'#fbbf24' },
      { name:'HIPAA', pct: Math.round(done / total * 88), color:'#f87171' },
      { name:'CJIS', pct: Math.round(done / total * 90), color:'#60a5fa' },
    ];

    const ringsEl = container.querySelector('#fc-gap-rings');
    if (ringsEl) {
      let rh = '';
      frameworks.forEach(fw => {
        const r = 40, c = 2 * Math.PI * r;
        const offset = c - (fw.pct / 100) * c;
        rh += '<div style="text-align:center">';
        rh += '<div class="fc-progress-ring">';
        rh += '<svg width="100" height="100"><circle cx="50" cy="50" r="' + r + '" fill="none" stroke="#1a2a44" stroke-width="8"/>';
        rh += '<circle cx="50" cy="50" r="' + r + '" fill="none" stroke="' + fw.color + '" stroke-width="8" stroke-dasharray="' + c + '" stroke-dashoffset="' + offset + '" stroke-linecap="round"/></svg>';
        rh += '<div class="fc-progress-ring-val" style="color:' + fw.color + '">' + fw.pct + '%</div>';
        rh += '</div>';
        rh += '<div style="font-size:.72rem;color:#7a93b8;margin-top:4px">' + esc(fw.name) + '</div>';
        rh += '</div>';
      });
      ringsEl.innerHTML = rh;
    }

    const missingEl = container.querySelector('#fc-gap-missing');
    if (missingEl) {
      const missing = NIST_CONTROLS.filter(c => !implemented[c.id]);
      let mh = '';
      if (missing.length === 0) {
        mh = '<div style="text-align:center;color:#4ade80;padding:20px">All controls implemented!</div>';
      } else {
        missing.forEach(c => {
          mh += '<div class="fc-check-row">';
          mh += '<span class="fc-ctrl-id">' + esc(c.id) + '</span>';
          mh += '<span style="flex:1;font-size:.78rem">' + esc(c.title) + '</span>';
          mh += '<span style="font-size:.7rem;color:#7a93b8">' + esc(c.family) + '</span>';
          mh += '</div>';
        });
      }
      missingEl.innerHTML = mh;
    }
  }
}
