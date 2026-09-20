// Darknode -- Extended Compliance Reference Database
// Copyright (c) 2026 SpartanKing18. All rights reserved.

const NIST_800_53 = [
  // ---------------------------------------------------------------------------
  // AC - Access Control (AC-1 through AC-25)
  // ---------------------------------------------------------------------------
  {
    id: "AC-1",
    family: "AC",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates an access control policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the access control policy and associated controls. These documents are reviewed and updated at an organization-defined frequency to ensure they remain relevant and effective.",
    supplementalGuidance: "Access control policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Organizations should ensure that access control policies are consistent with the risk management strategy and integrate with other organizational policies. Existing organizational policies may make the need for additional specific policies unnecessary.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AC-2",
    family: "AC",
    title: "Account Management",
    description: "The organization manages system accounts including identifying account types, establishing conditions for group and role membership, assigning account managers, and specifying authorized users. The organization requires approvals for requests to create accounts and creates, enables, modifies, disables, and removes accounts in accordance with policy. Account management includes the identification and management of shared, group, emergency, temporary, and guest accounts.",
    supplementalGuidance: "Organizations can simplify account management activities by establishing shared or group accounts for specific functions rather than individual accounts. Centralized management of accounts can reduce the risk of unauthorized access. Temporary and emergency accounts should have automatic expiration conditions and be closely monitored during their active periods.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AC-3",
    family: "AC",
    title: "Access Enforcement",
    description: "The system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies. Access enforcement mechanisms are employed at the application level and at the operating system and network level to control access between subjects and objects. The system enforces the most restrictive set of rights and privileges or access needed by users for the performance of specified tasks.",
    supplementalGuidance: "Access control policies include identity-based, role-based, attribute-based, and discretionary and mandatory access control. Access enforcement mechanisms can be implemented through access control lists, access control matrices, and cryptographic mechanisms. Organizations consider the use of encryption to protect information at rest and in transit as an additional access enforcement mechanism.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AC-4",
    family: "AC",
    title: "Information Flow Enforcement",
    description: "The system enforces approved authorizations for controlling the flow of information within the system and between connected systems based on applicable policy. Information flow control regulates where information can travel within a system and between systems, not merely who can access the information. Flow restrictions include blocking external traffic that claims to be from within the organization, and restricting data exports to external networks.",
    supplementalGuidance: "Information flow enforcement mechanisms include boundary protection devices such as gateways, routers, guards, encrypted tunnels, and firewalls. Organizations should implement flow control at both the network and application layers. Cross-domain solutions can be employed to enforce information flow policies between different security domains.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "AC-5",
    family: "AC",
    title: "Separation of Duties",
    description: "The organization separates duties of individuals as necessary to prevent malicious activity without collusion, identifies and documents specific duties requiring separation, and defines system access authorizations to support the separation of duties. Separation of duties addresses the potential for abuse of authorized privileges by ensuring that no single individual can control all aspects of a critical function or system. This principle limits the damage that can result from the actions of a single individual.",
    supplementalGuidance: "Separation of duties includes dividing mission and business functions and support functions among different individuals or roles. Organizations determine the appropriate degree of separation based on the level of concern for the function or process. Examples include separating system administration from audit functions, separating testing from production environments, and dividing key management functions among multiple individuals.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "AC-6",
    family: "AC",
    title: "Least Privilege",
    description: "The organization employs the principle of least privilege, allowing only authorized accesses for users and processes that are necessary to accomplish assigned organizational tasks. The system enforces the most restrictive set of rights and privileges or access needed by users for the performance of specified tasks. Least privilege applies to both logical access and physical access and is enforced by both automated and manual mechanisms.",
    supplementalGuidance: "Organizations employ least privilege for specific duties and systems including restricting privileged accounts to specific personnel or roles, preventing non-privileged users from executing privileged functions, and auditing the use of privileged functions. Security functions that require least privilege include setting up access controls, configuring audit functions, managing accounts, and performing system or network administration. Organizations should periodically review privileges assigned to roles and personnel.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "AC-7",
    family: "AC",
    title: "Unsuccessful Logon Attempts",
    description: "The system enforces a limit of a defined number of consecutive invalid logon attempts by a user during a defined time period. The system automatically locks the account or delays the next logon prompt when the maximum number of unsuccessful attempts is exceeded. This control applies regardless of whether the logon occurs via a local or network connection.",
    supplementalGuidance: "Organizations may implement automatic lockout or other responses to unsuccessful logon attempts such as an increasing delay between attempts. The lockout duration and the number of unsuccessful attempts should be consistent with the organization's risk tolerance. Organizations should consider using multi-factor authentication to reduce the risk of successful brute-force attacks on accounts.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "AC-8",
    family: "AC",
    title: "System Use Notification",
    description: "The system displays an approved system use notification message or banner before granting access that provides privacy and security notices consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The notification message informs potential users that they are accessing a government or organizational system, that system usage may be monitored and recorded, and that unauthorized use is prohibited and subject to criminal and civil penalties.",
    supplementalGuidance: "System use notification messages can be implemented in the form of warning banners displayed when individuals log in to systems. The exact content of the notification varies depending on applicable laws, regulations, and organizational policy. Organizations should consult with legal counsel regarding appropriate notification content. System use notifications are typically displayed prior to successful authentication.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AC-9",
    family: "AC",
    title: "Previous Logon Notification",
    description: "The system notifies the user upon successful logon of the date and time of the last logon, the number of unsuccessful logon attempts since the last successful logon, and changes to security-related characteristics of the user account. This information enables users to recognize if unauthorized access to their account has been attempted or if their account has been compromised.",
    supplementalGuidance: "Previous logon notification is applicable to system access via any interactive logon interface. Organizations can include additional information in the notification such as the location of the last logon. The notification provides users with awareness of potential unauthorized activity on their accounts and encourages them to report suspicious access attempts.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "AC-10",
    family: "AC",
    title: "Concurrent Session Control",
    description: "The system limits the number of concurrent sessions for each system account to an organization-defined number. This control addresses concurrent sessions for system accounts and does not address concurrent sessions by single users via multiple system accounts. The limitation on concurrent sessions applies to both local and remote sessions.",
    supplementalGuidance: "Organizations may define the maximum number of concurrent sessions for system accounts globally, by account type, by account, or by a combination thereof. Limiting the number of concurrent sessions reduces the risk of unauthorized access through session hijacking and helps prevent resource exhaustion attacks. Organizations should consider operational requirements when setting session limits.",
    priority: "P3",
    baseline: "High"
  },
  {
    id: "AC-11",
    family: "AC",
    title: "Device Lock",
    description: "The system prevents further access to the system by initiating a session lock after a defined period of inactivity or upon receiving a request from a user. The session lock is retained until the user reestablishes access using established identification and authentication procedures. Users can directly initiate session lock mechanisms to prevent inadvertent viewing when a device is unattended.",
    supplementalGuidance: "Session locks are temporary actions taken when users stop work and move away from the immediate vicinity of systems but do not want to log out because of the temporary nature of their absences. Organizations may deploy session lock mechanisms at the operating system level or at the application level. A session lock is not a substitute for logging out of the system. Pattern-hiding displays can be used to conceal the information previously visible on the display.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "AC-12",
    family: "AC",
    title: "Session Termination",
    description: "The system automatically terminates a user session after a defined period of inactivity, at a defined time, or when a defined condition is met. Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the session lock capability. Organizations may employ session termination to protect against unauthorized individuals gaining access to sessions left unattended for extended periods.",
    supplementalGuidance: "Session termination ends all processes associated with a user logical session, unlike session lock which retains the session state. Organizations establish maximum session duration periods and conditions for automatic termination based on mission and business requirements. Conditions triggering automatic session termination can include organization-defined periods of user inactivity, targeted responses to certain types of incidents, or time-of-day restrictions on system use.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "AC-13",
    family: "AC",
    title: "Supervision and Review -- Access Control",
    description: "Withdrawn. This control has been incorporated into AC-2 and AU-6. Organizations should refer to the account management control AC-2 and the audit record review, analysis, and reporting control AU-6 for the supervision and review requirements previously addressed by this control.",
    supplementalGuidance: "This control was withdrawn in Revision 5 to eliminate redundancy. The supervision and review activities are now addressed through the account management and audit review controls. Organizations transitioning from earlier revisions should ensure that AC-2 and AU-6 implementations adequately cover the intent of this former control.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "AC-14",
    family: "AC",
    title: "Permitted Actions Without Identification or Authentication",
    description: "The organization identifies specific user actions that can be performed on the system without identification or authentication consistent with organizational missions and business functions. The organization documents and provides supporting rationale for actions that do not require identification or authentication. This control addresses situations where organizations determine that no identification or authentication is required for specific system actions.",
    supplementalGuidance: "Actions without identification and authentication may include accessing public websites or other publicly accessible federal systems, accessing systems with guest or anonymous accounts, and accessing network resources without individual user identification. Organizations should minimize the actions permitted without identification or authentication to reduce risk. When identification and authentication are not required, other security controls may need to be heightened to compensate.",
    priority: "P3",
    baseline: "Low"
  },
  {
    id: "AC-15",
    family: "AC",
    title: "Automated Marking",
    description: "Withdrawn. This control has been incorporated into MP-3. Organizations should refer to the media marking control MP-3 for the automated marking requirements previously addressed by this control. Automated marking capabilities ensure that information is appropriately labeled when stored on digital media.",
    supplementalGuidance: "This control was withdrawn in Revision 5 to consolidate marking requirements under media protection controls. Organizations should ensure that their MP-3 implementations address both manual and automated marking of information. The consolidation reduces redundancy while maintaining the security intent of proper information labeling.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "AC-16",
    family: "AC",
    title: "Security and Privacy Attributes",
    description: "The organization provides the means to associate security and privacy attributes with information in storage, in process, and in transmission. The system supports and maintains the binding of security and privacy attributes to information. These attributes are used as the basis for enforcing access control and information flow control policies and can include classifications, handling caveats, source markings, and dissemination limitations.",
    supplementalGuidance: "Security and privacy attributes can be associated with subjects and objects at the hardware, firmware, operating system, or application level. The association of attributes to information is an important step in the implementation of attribute-based access control. Organizations should ensure that attribute definitions are consistent across the system and with external partners when information is shared.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "AC-17",
    family: "AC",
    title: "Remote Access",
    description: "The organization establishes and documents usage restrictions, configuration and connection requirements, and implementation guidance for each type of remote access allowed. The organization authorizes each type of remote access to the system prior to allowing such connections. Remote access is access to organizational systems by users or processes communicating through external networks such as the internet.",
    supplementalGuidance: "Remote access methods include dial-up, broadband, and wireless connections. Organizations should use encrypted virtual private networks to enhance confidentiality and integrity protections over remote connections. Usage restrictions and guidance for remote access include limiting access from specific network addresses, requiring multi-factor authentication, and encrypting all remote sessions.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "AC-18",
    family: "AC",
    title: "Wireless Access",
    description: "The organization establishes configuration requirements, connection requirements, and implementation guidance for each type of wireless access. The organization authorizes each type of wireless access to the system prior to allowing such connections. Wireless technologies include microwave, packet radio, satellite, and various 802.11x and Bluetooth protocols.",
    supplementalGuidance: "Organizations should employ authentication and encryption protocols for wireless access that are appropriate for the sensitivity of the information being transmitted. WPA3 Enterprise or equivalent encryption should be used for organizational wireless networks. Rogue wireless access point detection and monitoring capabilities should be employed to prevent unauthorized wireless connections.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "AC-19",
    family: "AC",
    title: "Access Control for Mobile Devices",
    description: "The organization establishes configuration requirements, connection requirements, and implementation guidance for organization-controlled mobile devices including usage restrictions. The organization authorizes the connection of mobile devices to organizational systems. Mobile devices include portable storage media, smartphones, tablets, and laptop computers when those devices are used outside of controlled areas.",
    supplementalGuidance: "Organizations should implement mobile device management solutions that enforce security policies on connected devices. Configuration requirements include enabling device encryption, requiring strong authentication, restricting application installation, and enabling remote wipe capabilities. Organizations may prohibit certain types of mobile devices or restrict their connection to specific system resources.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "AC-20",
    family: "AC",
    title: "Use of External Systems",
    description: "The organization establishes terms and conditions consistent with any trust relationships established with other organizations owning, operating, or maintaining external systems. The organization defines restrictions, terms, and conditions allowing authorized individuals to access the system from external systems. External systems include personally owned devices, systems operated by other organizations, and publicly accessible systems.",
    supplementalGuidance: "External systems are systems that are outside of the authorization boundary established by the organization and for which the organization typically has no direct control over security controls. Organizations should establish and enforce security requirements for external systems and limit the types of information that can be accessed or processed on external systems. Agreements with external system owners should address the security measures applied to protect organizational information.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "AC-21",
    family: "AC",
    title: "Information Sharing",
    description: "The organization facilitates information sharing by enabling authorized users to determine whether access authorizations assigned to sharing partners match the information's access and use restrictions. The organization employs automated mechanisms or manual processes to assist users in making information sharing and collaboration decisions. This control applies to information that may be restricted due to its sensitivity or classification.",
    supplementalGuidance: "Organizations should define the circumstances under which information sharing is permitted and implement mechanisms to ensure that sharing restrictions are enforced. Automated tools such as data loss prevention systems can assist in enforcing sharing restrictions. Users should receive training on the proper procedures for sharing information and the consequences of improper sharing.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "AC-22",
    family: "AC",
    title: "Publicly Accessible Content",
    description: "The organization designates individuals authorized to post information onto publicly accessible systems and trains those individuals to ensure that publicly accessible information does not contain nonpublic information. The organization reviews the proposed content of information prior to posting onto publicly accessible systems and reviews the content on publicly accessible systems on a defined frequency to ensure that nonpublic information is not present.",
    supplementalGuidance: "Organizations should implement a review and approval process for all content posted to publicly accessible systems. The review process should verify that no sensitive, proprietary, or personally identifiable information is inadvertently disclosed. Automated scanning tools can assist in identifying potentially sensitive content before it is posted to public-facing systems.",
    priority: "P3",
    baseline: "Low"
  },
  {
    id: "AC-23",
    family: "AC",
    title: "Data Mining Protection",
    description: "The organization employs techniques to detect and protect against data mining attempts on organizational data stores. Data mining prevention and detection techniques include limiting the types of responses provided to database queries, limiting the number or frequency of database queries, monitoring for unusual or suspicious query patterns, and notifying personnel of anomalous activities.",
    supplementalGuidance: "Organizations should implement controls to prevent adversaries from combining authorized data queries to derive sensitive information through aggregation. Database activity monitoring tools can be employed to detect potential data mining activities. Organizations should consider implementing query throttling and result-set limiting to reduce the risk of large-scale data exfiltration through seemingly legitimate queries.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "AC-24",
    family: "AC",
    title: "Access Control Decisions",
    description: "The organization establishes procedures to ensure that access control decisions are applied to each access request prior to access enforcement. Access control decisions involve the evaluation of applicable policy and the determination of whether the subject has been authorized to perform the requested actions on the designated object. Access control decisions can be made by centralized or distributed access control mechanisms.",
    supplementalGuidance: "Access control decisions are distinct from access enforcement and are typically made by policy decision points that evaluate requests against applicable access control policies. Organizations should ensure that access control decisions are consistent, repeatable, and auditable. Centralized access control decision mechanisms can simplify management and improve consistency across the enterprise.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "AC-25",
    family: "AC",
    title: "Reference Monitor",
    description: "The organization implements a reference monitor for access control that is tamperproof, always invoked, and small enough to be subject to analysis and testing. The reference monitor concept establishes a set of design requirements for the access control mechanism that mediates all access requests. The reference validation mechanism enforces the security policy and provides a foundation for the security architecture.",
    supplementalGuidance: "The reference monitor concept can be implemented as hardware, firmware, or software. The reference monitor should be verifiable to ensure complete and correct mediation of every access request. Organizations should implement reference monitors at multiple layers of the system architecture to provide defense in depth for access control decisions.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // AT - Awareness and Training (AT-1 through AT-6)
  // ---------------------------------------------------------------------------
  {
    id: "AT-1",
    family: "AT",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a security and privacy awareness and training policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the awareness and training policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Awareness and training policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Organizations should tailor awareness and training programs to the needs of the organization and the roles of personnel. Existing organizational policies may make the need for additional specific awareness and training policies unnecessary.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AT-2",
    family: "AT",
    title: "Literacy Training and Awareness",
    description: "The organization provides security and privacy literacy training to system users including initial training when the user is authorized access to the system, when required by system changes, and at a defined frequency thereafter. The literacy training includes awareness of the various social engineering techniques, indicators of insider threat, and methods to report suspicious behavior. The training ensures that users understand their responsibilities in maintaining the security posture of the organization.",
    supplementalGuidance: "Organizations determine the content and frequency of literacy training and awareness based on the specific organizational requirements and the systems to which personnel are authorized access. Awareness techniques include displaying posters, offering supplies inscribed with security reminders, generating security awareness newsletters, and conducting brown bag seminars. Literacy training can be provided as part of general professional development.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AT-3",
    family: "AT",
    title: "Role-Based Training",
    description: "The organization provides role-based security and privacy training to personnel with assigned security roles and responsibilities before authorizing access to the system or performing assigned duties, when required by system changes, and at a defined frequency thereafter. Role-based training addresses management, operational, and technical roles and responsibilities and includes security planning, incident response, contingency planning, and system development. The training is tailored to the specific operational environment and the individual's role.",
    supplementalGuidance: "Organizations determine the content and frequency of role-based training based on the assigned roles and responsibilities of individuals and the security and privacy requirements of the organization and the systems to which personnel are authorized. Role-based training includes physical security training for personnel with physical access responsibilities. Organizations may supplement role-based training with hands-on exercises and simulations.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AT-4",
    family: "AT",
    title: "Training Records",
    description: "The organization documents and monitors individual security and privacy training activities including basic security awareness training, role-based security training, and specific system-related training. The organization retains individual training records for a defined period. Training records include the type of training provided, the date the training was completed, and verification of training completion.",
    supplementalGuidance: "Training records can be automated using learning management systems that track training completion and generate reports on training status. Documentation of training activities supports evidence collection for audits and compliance reviews. Organizations should periodically review training records to identify personnel who have not completed required training and take appropriate corrective action.",
    priority: "P3",
    baseline: "Low"
  },
  {
    id: "AT-5",
    family: "AT",
    title: "Contacts with Security Groups and Associations",
    description: "The organization establishes and maintains contact with selected groups and associations within the security community to stay current with the latest security practices, techniques, technologies, and threat information. These contacts include special interest groups, forums, professional associations, news groups, and peer organizations. Maintaining such contacts facilitates the sharing of security-related information including threats, vulnerabilities, and incidents.",
    supplementalGuidance: "Organizations should identify and engage with relevant security communities of practice that align with their mission and operational environment. Ongoing contact with security groups and associations enables organizations to maintain awareness of current security best practices and emerging threats. Information obtained from these contacts should be distributed to appropriate personnel within the organization.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "AT-6",
    family: "AT",
    title: "Training Feedback",
    description: "The organization provides feedback on organizational training results to designated personnel on a defined frequency. The feedback includes assessments of training effectiveness, identification of gaps in training coverage, and recommendations for improving training programs. Training feedback mechanisms help organizations continuously improve the quality and relevance of their security and privacy training programs.",
    supplementalGuidance: "Training feedback can be obtained through evaluations, testing, exercises, and after-action reviews. Organizations should use feedback to identify areas where training content needs to be updated or enhanced. Tracking metrics such as training completion rates, test scores, and observed behavioral changes can help organizations assess the overall effectiveness of their training programs.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // AU - Audit and Accountability (AU-1 through AU-16)
  // ---------------------------------------------------------------------------
  {
    id: "AU-1",
    family: "AU",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates an audit and accountability policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the audit and accountability policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Audit and accountability policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Organizations should align audit and accountability requirements with their risk management strategy. Existing organizational policies may make the need for additional specific audit and accountability policies unnecessary.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AU-2",
    family: "AU",
    title: "Event Logging",
    description: "The organization identifies the types of events that the system is capable of logging in support of the audit function and coordinates the event logging function with other organizational entities requiring audit-related information to guide and inform the selection criteria. The organization specifies the events to be logged and the frequency of logging for each identified event. Event types include password changes, failed logons, failed access attempts, use of privileged functions, and other security-relevant events.",
    supplementalGuidance: "Organizations should define auditable events based on the potential impact to the organization if the events are not detected. The set of events to be audited should be reviewed and updated periodically to ensure that current threats are addressed. Event logging can generate a significant volume of data, so organizations should plan for adequate storage capacity and efficient log management processes.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AU-3",
    family: "AU",
    title: "Content of Audit Records",
    description: "The system generates audit records containing information that establishes what type of event occurred, when it occurred, where it occurred, the source of the event, the outcome of the event, and the identity of any individuals or subjects associated with the event. Audit record content that may be necessary to satisfy this requirement includes time stamps, source and destination addresses, user or process identifiers, event descriptions, and success or failure indications.",
    supplementalGuidance: "Organizations should ensure that audit records contain sufficient detail to support after-the-fact investigations of incidents. Detailed audit records are essential for reconstructing events and establishing accountability. Organizations may need to capture additional fields such as data objects accessed, commands executed, or network packet information depending on the operational environment and threat landscape.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AU-4",
    family: "AU",
    title: "Audit Log Storage Capacity",
    description: "The organization allocates audit log storage capacity and configures auditing to reduce the likelihood of such capacity being exceeded. The system provides a warning when allocated audit record storage volume reaches a defined percentage of maximum storage capacity. Adequate storage capacity ensures that audit information is not lost due to storage exhaustion during periods of high audit activity.",
    supplementalGuidance: "Organizations should consider the types and volume of auditable events when determining audit log storage requirements. Centralized log management solutions such as SIEM systems can help manage storage capacity across multiple systems. Organizations should implement automated mechanisms to alert administrators when audit log storage approaches capacity limits and define responses for when capacity is reached.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AU-5",
    family: "AU",
    title: "Response to Audit Logging Process Failures",
    description: "The system alerts defined personnel or roles in the event of an audit logging process failure and takes defined additional actions such as shutting down the system, overwriting the oldest audit records, or stopping the generation of audit records. Audit logging process failures include software and hardware errors, failures in the audit record capturing mechanisms, and audit storage capacity being reached or exceeded.",
    supplementalGuidance: "Organizations should define the specific actions to take when audit failures occur based on the impact of the loss of audit information. In high-security environments, the system may be configured to shut down rather than continue operating without audit capability. Organizations should test audit failure response mechanisms periodically to ensure they function as expected.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AU-6",
    family: "AU",
    title: "Audit Record Review, Analysis, and Reporting",
    description: "The organization reviews and analyzes system audit records at a defined frequency for indications of inappropriate or unusual activity. The organization reports findings to designated personnel or roles. Audit record review, analysis, and reporting covers information security and privacy audit record monitoring activities including those related to insider threat monitoring programs.",
    supplementalGuidance: "Organizations should integrate audit record review and analysis with their continuous monitoring program. Automated tools such as SIEM systems, log correlation engines, and anomaly detection systems can assist in identifying potentially malicious or suspicious activity. Organizations should establish baseline behavior profiles to help identify deviations that may indicate security incidents.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AU-7",
    family: "AU",
    title: "Audit Record Reduction and Report Generation",
    description: "The system provides an audit record reduction and report generation capability that supports on-demand audit review, analysis, and reporting requirements and after-the-fact investigations of incidents. Audit record reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. Report generation provides the ability to create standardized reports from audit data.",
    supplementalGuidance: "Audit record reduction and report generation capabilities do not alter the original audit records. Organizations should ensure that the reduction and reporting tools can support the types of queries and analyses needed for security investigations and compliance reporting. The capability should allow for the generation of both standard recurring reports and ad hoc reports based on specific investigation requirements.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "AU-8",
    family: "AU",
    title: "Time Stamps",
    description: "The system uses internal system clocks to generate time stamps for audit records. The system records time stamps that can be mapped to Coordinated Universal Time or Greenwich Mean Time and meets a defined granularity of time measurement. Accurate time stamps are essential for correlating events across multiple systems and establishing the sequence of events during incident investigations.",
    supplementalGuidance: "Organizations should synchronize internal system clocks to an authoritative time source such as a Network Time Protocol server to ensure consistency of time stamps across the enterprise. Time stamp granularity requirements may vary depending on the operational environment and the need for precision in event correlation. Organizations should protect the integrity of time sources and synchronization mechanisms.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AU-9",
    family: "AU",
    title: "Protection of Audit Information",
    description: "The system protects audit information and audit logging tools from unauthorized access, modification, and deletion. Audit information includes all information needed to successfully audit system activity such as audit records, audit log settings, and audit reports. The protection mechanisms are commensurate with the level of sensitivity of the audit information.",
    supplementalGuidance: "Organizations should implement access controls to restrict access to audit information to authorized personnel only. Cryptographic mechanisms such as digital signatures and hashing can be employed to detect unauthorized modifications to audit records. Organizations should store copies of audit records in a centralized, protected location or transmit them to a separate system to prevent loss in the event of a system compromise.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AU-10",
    family: "AU",
    title: "Non-repudiation",
    description: "The system provides irrefutable evidence that an individual or process performed specific actions within the system. Non-repudiation protects against claims by the originator of having not originated a particular action, the recipient of having not received a particular message, or either party of having not participated in a transaction. The system generates evidence of individual actions to support non-repudiation requirements.",
    supplementalGuidance: "Organizations should implement non-repudiation mechanisms using digital signatures, secure logging, and tamper-evident audit trails. Non-repudiation services can be achieved through various cryptographic techniques that bind the identity of an individual or process to a specific action. Organizations should consider implementing non-repudiation for critical business transactions, privileged operations, and legal or regulatory requirements.",
    priority: "P2",
    baseline: "High"
  },
  {
    id: "AU-11",
    family: "AU",
    title: "Audit Record Retention",
    description: "The organization retains audit records for a defined time period to provide support for after-the-fact investigations of incidents and to meet regulatory and organizational information retention requirements. The retention period is consistent with applicable laws, directives, policies, regulations, standards, and operational requirements. Long-term retention ensures that audit evidence is available for forensic analysis and legal proceedings.",
    supplementalGuidance: "Organizations should establish audit record retention periods based on the nature of the information, legal requirements, and operational needs. Retained audit records should be protected from unauthorized modification and deletion throughout the retention period. Organizations should implement mechanisms to ensure the integrity and availability of retained audit records, including regular verification of archived records.",
    priority: "P3",
    baseline: "Low"
  },
  {
    id: "AU-12",
    family: "AU",
    title: "Audit Record Generation",
    description: "The system provides audit record generation capability for the events defined in AU-2 at system components where audit capability is deployed. The system allows designated organizational personnel to select which auditable events are to be logged by specific components of the system. The audit record generation capability is deployed across the system to support the comprehensive capture of security-relevant events.",
    supplementalGuidance: "Organizations should ensure that audit record generation is enabled on all system components where auditing capability is needed to support the organization's audit requirements. The selection of events to audit should be reviewed periodically and updated to address changes in the threat environment. Organizations should verify that audit record generation does not adversely impact system performance.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "AU-13",
    family: "AU",
    title: "Monitoring for Information Disclosure",
    description: "The organization monitors designated open-source information and information sharing sites at a defined frequency for evidence of unauthorized disclosure of organizational information. This monitoring helps detect data leaks, intellectual property theft, and unauthorized publication of sensitive information. The monitoring covers publicly accessible websites, social media platforms, dark web forums, and code repositories.",
    supplementalGuidance: "Organizations should use automated tools and services to monitor for the unauthorized disclosure of organizational information across internet-accessible sources. Monitoring activities should be focused on information types that would cause the most significant harm if disclosed. Organizations should establish procedures for responding to detected unauthorized disclosures including containment, notification, and remediation actions.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "AU-14",
    family: "AU",
    title: "Session Audit",
    description: "The system provides the capability to capture and record all content related to a user session, or selectively capture and record content based on defined criteria. Session audit captures the complete sequence of events during a user session including commands entered, files accessed, and network connections established. This capability supports detailed forensic analysis and insider threat investigations.",
    supplementalGuidance: "Session audit capabilities can include screen capture, keystroke logging, and network traffic capture associated with specific user sessions. Organizations should implement session auditing selectively and in compliance with applicable privacy regulations and organizational policies. The captured session information should be protected with strong access controls and encryption due to its sensitive nature.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "AU-15",
    family: "AU",
    title: "Alternate Audit Logging Capability",
    description: "The organization provides an alternate audit logging capability in the event of a failure in the primary audit logging capability. The alternate capability ensures that critical audit events continue to be captured even when the primary audit system is unavailable. This control addresses the resilience of the audit function by providing redundancy for audit logging.",
    supplementalGuidance: "Organizations should implement alternate audit logging mechanisms that are independent of the primary audit system to ensure continuity of audit coverage. The alternate capability may include backup log servers, local logging with delayed forwarding, or manual logging procedures. Organizations should test the alternate audit capability periodically to verify that it can support continued operations during primary system failures.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "AU-16",
    family: "AU",
    title: "Cross-Organizational Audit Logging",
    description: "The organization employs methods for coordinating audit information among external organizations when audit information is transmitted across organizational boundaries. Cross-organizational audit logging enables the correlation of audit records from multiple organizations to identify coordinated attacks and shared threats. The organization establishes agreements with partner organizations regarding the sharing and protection of audit information.",
    supplementalGuidance: "Organizations should define the types of audit information to be shared and the mechanisms for secure transmission between organizations. Agreements should address the format, frequency, and protection requirements for shared audit data. Organizations should ensure that cross-organizational audit logging complies with applicable privacy laws and regulations governing the sharing of information between entities.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // CA - Assessment, Authorization, and Monitoring (CA-1 through CA-9)
  // ---------------------------------------------------------------------------
  {
    id: "CA-1",
    family: "CA",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates an assessment, authorization, and monitoring policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the assessment, authorization, and monitoring policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Assessment, authorization, and monitoring policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Organizations should ensure that assessment and authorization activities are integrated into the system development life cycle. Existing organizational policies may make the need for additional specific policies unnecessary.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "CA-2",
    family: "CA",
    title: "Control Assessments",
    description: "The organization develops a control assessment plan that describes the scope of the assessment including controls and control enhancements under assessment, assessment procedures to be used, and the assessment environment, team, and roles and responsibilities. The organization assesses the controls in the system and its environment of operation at a defined frequency to determine the extent to which the controls are implemented correctly, operating as intended, and producing the desired outcome.",
    supplementalGuidance: "Organizations should ensure that assessors have the appropriate level of independence and that assessment results are documented and shared with relevant stakeholders. Assessment plans should identify the assessment methodology including the depth and coverage of the assessment activities. Organizations can leverage the results of previous assessments, audits, and testing to reduce the overall assessment effort.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "CA-3",
    family: "CA",
    title: "Information Exchange",
    description: "The organization approves and manages the exchange of information between the system and other systems using interconnection security agreements, memoranda of understanding, or other exchange agreements. The organization documents interface characteristics, security and privacy requirements, controls, and responsibilities for each connection. Information exchange agreements are reviewed and updated at a defined frequency.",
    supplementalGuidance: "Organizations should carefully document all system interconnections and ensure that appropriate security controls are in place for each connection. Interconnection security agreements should specify the types of information that can be exchanged, the security mechanisms used to protect the information, and the responsibilities of each party. Organizations should monitor system connections to detect unauthorized data transfers and anomalous activity.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "CA-4",
    family: "CA",
    title: "Security Certification",
    description: "Withdrawn. This control has been incorporated into CA-2. Organizations should refer to the control assessments control CA-2 for the security certification requirements previously addressed by this control. The assessment process now encompasses the activities formerly described as security certification.",
    supplementalGuidance: "This control was withdrawn in Revision 4 to reduce redundancy with CA-2. Organizations transitioning from earlier revisions should ensure that their CA-2 implementation adequately addresses the intent of the former security certification control. The consolidation reflects the integration of certification activities into the broader control assessment process.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "CA-5",
    family: "CA",
    title: "Plan of Action and Milestones",
    description: "The organization develops a plan of action and milestones for the system to document the planned remediation actions to correct weaknesses or deficiencies noted during the assessment of controls and to reduce or eliminate known vulnerabilities. The organization updates the plan of action and milestones at a defined frequency based on findings from control assessments, audits, and continuous monitoring activities.",
    supplementalGuidance: "Plans of action and milestones are key organizational documents and are subject to reporting requirements established by the organization. Organizations should prioritize the remediation of weaknesses and deficiencies based on the risk they pose to the organization. The plan should include specific milestones with target completion dates, resources required, and responsible parties for each remediation action.",
    priority: "P3",
    baseline: "Low"
  },
  {
    id: "CA-6",
    family: "CA",
    title: "Authorization",
    description: "The organization assigns a senior official as the authorizing official for the system, ensures the authorizing official authorizes the system for processing before commencing operations, and updates the authorization at a defined frequency. The authorization decision is based on a determination of the risk to organizational operations, organizational assets, individuals, other organizations, and the nation resulting from the operation of the system and the plan to monitor controls on an ongoing basis.",
    supplementalGuidance: "The authorization process is a management responsibility and requires the authorizing official to explicitly accept the risk of operating the system. Organizations should ensure that authorization decisions are informed by a comprehensive risk assessment and that authorizing officials have access to all relevant security and privacy information. Authorization decisions should be documented and maintained as part of the system security plan.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "CA-7",
    family: "CA",
    title: "Continuous Monitoring",
    description: "The organization develops a continuous monitoring strategy and implements a continuous monitoring program that includes ongoing assessments of control effectiveness, ongoing awareness of threats and vulnerabilities, and ongoing assessment of the security and privacy posture of the organization. The continuous monitoring program includes configuration management and change detection, security impact analyses, and status reporting and active response to identified issues.",
    supplementalGuidance: "Continuous monitoring programs allow organizations to maintain the security authorization of systems and common controls over time in highly dynamic environments. The terms continuous and ongoing imply that organizations assess and monitor their controls and risks at a frequency sufficient to support risk-based decisions. Organizations should automate continuous monitoring activities to the greatest extent possible to improve efficiency and timeliness of response.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "CA-8",
    family: "CA",
    title: "Penetration Testing",
    description: "The organization conducts penetration testing at a defined frequency on systems and system components. Penetration testing attempts to circumvent or defeat the security features of a system by simulating the actions of an adversary. The scope of penetration testing includes network, application, database, and physical security testing as appropriate for the operational environment.",
    supplementalGuidance: "Organizations should employ penetration testing to identify vulnerabilities that may not be detected through other assessment methods. Penetration testing rules of engagement should be established prior to testing to define the scope, approach, and limitations of the testing activities. Test results should be documented, and findings should be incorporated into the plan of action and milestones for remediation.",
    priority: "P2",
    baseline: "High"
  },
  {
    id: "CA-9",
    family: "CA",
    title: "Internal System Connections",
    description: "The organization authorizes internal connections of system components and documents for each internal connection the interface characteristics, security and privacy requirements, and the nature of the information communicated. Internal connections include connections between separate physical systems, logical connections between system components, and connections to mobile devices within the organization.",
    supplementalGuidance: "Organizations should apply the same rigor to internal system connections as to external connections, as compromised internal components can serve as attack vectors. Internal connection documentation should be maintained and updated as the system architecture changes. Organizations should implement network segmentation and monitoring to limit the impact of compromised internal connections.",
    priority: "P2",
    baseline: "Moderate"
  },

  // ---------------------------------------------------------------------------
  // CM - Configuration Management (CM-1 through CM-14)
  // ---------------------------------------------------------------------------
  {
    id: "CM-1",
    family: "CM",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a configuration management policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the configuration management policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Configuration management policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Organizations should integrate configuration management with change management and release management processes. Existing organizational policies may make the need for additional specific configuration management policies unnecessary.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "CM-2",
    family: "CM",
    title: "Baseline Configuration",
    description: "The organization develops, documents, and maintains under configuration control a current baseline configuration of the system. The baseline configuration is a set of specifications for a system or a configuration item within a system that has been formally reviewed and agreed on at a given point in time and which can only be changed through change control procedures. Baseline configurations serve as a basis for future builds, releases, and changes to the system.",
    supplementalGuidance: "Baseline configurations include information about system components such as standard software packages, patch levels, network topology, and configuration settings. Organizations should maintain baseline configurations for development, test, and production environments. The baseline should be updated when significant changes are made to the system and should be stored in a protected repository to prevent unauthorized modifications.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "CM-3",
    family: "CM",
    title: "Configuration Change Control",
    description: "The organization determines and documents the types of changes to the system that are configuration-controlled. The organization reviews proposed configuration-controlled changes to the system and approves or disapproves such changes with explicit consideration for security and privacy impact analyses. Configuration change control for the system includes documentation, approval, testing, and implementation of changes.",
    supplementalGuidance: "Organizations should implement a formal change control process that includes impact analysis, testing, approval, and rollback procedures for all configuration changes. Automated tools can assist in tracking and managing configuration changes across the enterprise. Emergency changes should be documented retroactively and reviewed to ensure they do not introduce security vulnerabilities.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "CM-4",
    family: "CM",
    title: "Impact Analyses",
    description: "The organization analyzes changes to the system to determine potential security and privacy impacts prior to change implementation. The analysis includes evaluation of the effect of the change on the security and privacy posture of the system, existing security controls, and any dependencies with other systems. Impact analyses help organizations make informed decisions about approving or rejecting proposed changes.",
    supplementalGuidance: "Organizations should establish criteria for determining the level of impact analysis required based on the nature and scope of the proposed change. Impact analyses should consider both direct and indirect effects of the change on the system and its environment. Organizations should maintain documentation of impact analyses to support audit and review requirements.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "CM-5",
    family: "CM",
    title: "Access Restrictions for Change",
    description: "The organization defines, documents, approves, and enforces physical and logical access restrictions associated with changes to the system. Access restrictions include limiting access to configuration management tools, production libraries, and code repositories to authorized personnel only. The organization ensures that only qualified and authorized individuals can make changes to the system.",
    supplementalGuidance: "Organizations should implement role-based access controls for change management tools and repositories. Access restrictions should be enforced through both technical and procedural mechanisms. Audit logs should capture all access to change management functions and any changes made to the system to support accountability and after-the-fact investigations.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "CM-6",
    family: "CM",
    title: "Configuration Settings",
    description: "The organization establishes and documents configuration settings for system components that reflect the most restrictive mode consistent with operational requirements. The organization implements the configuration settings and identifies, documents, and approves any deviations from established configuration settings. Configuration settings are the set of parameters that can be changed in hardware, software, or firmware that affect the security posture of the system.",
    supplementalGuidance: "Organizations should use security configuration checklists and benchmarks from authoritative sources such as NIST, CIS, and DISA as the basis for establishing configuration settings. Automated configuration scanning tools should be employed to verify compliance with established settings and detect configuration drift. Deviations from the approved configuration should be documented with risk-based justification and approved by the appropriate authority.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "CM-7",
    family: "CM",
    title: "Least Functionality",
    description: "The organization configures the system to provide only mission-essential capabilities by disabling or restricting the use of non-essential functions, ports, protocols, and services. The organization reviews the system at a defined frequency to identify unnecessary and non-secure functions, ports, protocols, and services. Least functionality ensures that the system has the minimum set of capabilities needed to support the mission.",
    supplementalGuidance: "Organizations should maintain a list of authorized software and functions for each system and remove or disable all other software and functions. Restricting functionality reduces the attack surface of the system and limits the potential for exploitation of vulnerabilities. Organizations should use application whitelisting, port filtering, and service management to enforce least functionality requirements.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "CM-8",
    family: "CM",
    title: "System Component Inventory",
    description: "The organization develops and documents an inventory of system components that accurately reflects the system, includes all components within the system boundary, is at the level of granularity deemed necessary for tracking and reporting, and includes defined information for achieving accountability. The inventory is updated at a defined frequency as an integral part of component installations, removals, and system updates.",
    supplementalGuidance: "Organizations should use automated discovery and inventory tools to maintain accurate and up-to-date component inventories. The inventory should include hardware, software, firmware, and documentation components. Organizations should reconcile the inventory periodically to identify any unauthorized components that may have been introduced into the system environment.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "CM-9",
    family: "CM",
    title: "Configuration Management Plan",
    description: "The organization develops, documents, and implements a configuration management plan for the system that addresses roles, responsibilities, and configuration management processes and procedures. The plan establishes a process for identifying configuration items throughout the system development life cycle and for managing the configuration of the configuration items. The plan defines the configuration items for the system and places them under configuration management.",
    supplementalGuidance: "Configuration management plans should be tailored to the specific needs and complexity of the system. The plan should address how configuration management activities will be coordinated with change management and release management processes. Organizations should ensure that the configuration management plan is reviewed and updated as the system evolves throughout its life cycle.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "CM-10",
    family: "CM",
    title: "Software Usage Restrictions",
    description: "The organization uses software and associated documentation in accordance with contract agreements and copyright laws. The organization tracks the use of software and associated documentation protected by quantity licenses to control copying and distribution. The organization controls and documents the use of peer-to-peer file sharing technology to ensure that this capability is not used for the unauthorized distribution of organizational information.",
    supplementalGuidance: "Organizations should implement software asset management processes to track software licenses and ensure compliance with license agreements. Automated tools can assist in monitoring software usage and detecting unauthorized or unlicensed software installations. Organizations should provide guidance to users regarding acceptable software usage practices and the consequences of software piracy.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "CM-11",
    family: "CM",
    title: "User-Installed Software",
    description: "The organization establishes and enforces policies governing the installation of software by users. The organization defines the types of software installations permitted and prohibited, and monitors compliance with software installation policies. Controlling user-installed software prevents the introduction of unauthorized or malicious software into the system environment.",
    supplementalGuidance: "Organizations should restrict software installation privileges to authorized personnel and implement technical controls such as application whitelisting to enforce software installation policies. Automated tools can detect and alert on unauthorized software installations. Organizations should consider providing an approved software catalog to users to facilitate the acquisition of authorized software.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "CM-12",
    family: "CM",
    title: "Information Location",
    description: "The organization identifies and documents the location of information that is processed and maintained by the system, including the specific system components on which the information is processed and stored. The organization identifies and documents the users who have access to the system and system components where the information is processed and stored. Understanding information locations is critical for implementing appropriate protections and responding to incidents.",
    supplementalGuidance: "Organizations should maintain an accurate mapping of information types to the system components where they reside. Information location documentation supports data protection impact assessments and incident response activities. Organizations should update information location documentation when changes are made to information storage, processing, or transmission practices.",
    priority: "P2",
    baseline: "High"
  },
  {
    id: "CM-13",
    family: "CM",
    title: "Data Action Mapping",
    description: "The organization develops and documents a map of system data actions, including the types of data processed, the system components involved, and the data flows between components. Data action mapping identifies where personal information and sensitive data are collected, stored, used, shared, and disposed of within the system. This mapping supports privacy impact analyses and the implementation of data protection controls.",
    supplementalGuidance: "Data action mapping is particularly important for systems that process personally identifiable information or other sensitive data categories. Organizations should use the data action map to identify potential privacy risks and implement appropriate technical and policy safeguards. The map should be reviewed and updated periodically to reflect changes in data processing activities and system architecture.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "CM-14",
    family: "CM",
    title: "Signed Components",
    description: "The organization prevents the installation of software and firmware components without verification that the component has been digitally signed using a certificate that is recognized and approved by the organization. Signed components provide assurance that the software has not been tampered with since it was signed by the developer or vendor. This control helps prevent the introduction of malicious or unauthorized code into the system.",
    supplementalGuidance: "Organizations should establish a trusted certificate authority infrastructure or use recognized third-party certificate authorities for component signing verification. Code signing verification should be enforced at the operating system and application levels. Organizations should maintain a list of approved signing certificates and revoke trust for certificates that are compromised or no longer valid.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // CP - Contingency Planning (CP-1 through CP-13)
  // ---------------------------------------------------------------------------
  {
    id: "CP-1",
    family: "CP",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a contingency planning policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the contingency planning policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Contingency planning policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Organizations should align contingency planning with business continuity and disaster recovery planning efforts. The policy should address the full range of potential disruptions including natural disasters, infrastructure failures, and cyber attacks.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "CP-2",
    family: "CP",
    title: "Contingency Plan",
    description: "The organization develops a contingency plan for the system that identifies essential mission and business functions and associated contingency requirements, provides recovery objectives, restoration priorities, and metrics. The plan addresses contingency roles, responsibilities, and assigned individuals with contact information, and is reviewed and updated at a defined frequency. The contingency plan is coordinated with incident handling activities and other related plans.",
    supplementalGuidance: "Organizations should ensure that the contingency plan addresses the full range of potential disruptions and provides clear guidance for personnel to follow during and after a disruption. The plan should be tested regularly to validate its effectiveness and identify areas for improvement. Organizations should distribute copies of the plan to key personnel and maintain copies at alternate locations to ensure availability during a disruption.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "CP-3",
    family: "CP",
    title: "Contingency Training",
    description: "The organization provides contingency training to system users consistent with assigned roles and responsibilities within a defined time period of assuming a contingency role or responsibility, when required by system changes, and at a defined frequency thereafter. Contingency training includes training on the procedures to be followed during a contingency event, the use of alternate processing sites, and the recovery and reconstitution of the system.",
    supplementalGuidance: "Organizations should ensure that contingency training is practical and includes hands-on exercises whenever possible. Training should cover the specific actions that personnel are expected to take during different types of contingency events. Organizations should document training completion and incorporate lessons learned from exercises and actual events into future training programs.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "CP-4",
    family: "CP",
    title: "Contingency Plan Testing",
    description: "The organization tests the contingency plan for the system at a defined frequency using organization-defined tests to determine the effectiveness of the plan and the readiness of the organization to execute the plan. The organization reviews the contingency plan test results and initiates corrective actions if needed. Testing methods include tabletop exercises, simulations, parallel processing, and full recovery testing at alternate sites.",
    supplementalGuidance: "Organizations should test the contingency plan using a variety of methods to ensure comprehensive coverage of different failure scenarios. Test results should be documented and used to update the contingency plan and improve organizational preparedness. Organizations should involve all relevant stakeholders in contingency plan testing to ensure coordination and communication effectiveness.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "CP-5",
    family: "CP",
    title: "Contingency Plan Update",
    description: "Withdrawn. This control has been incorporated into CP-2. Organizations should refer to the contingency plan control CP-2 for the plan update requirements previously addressed by this control. The contingency plan update activities are now addressed as part of the overall contingency plan development and maintenance process.",
    supplementalGuidance: "This control was withdrawn to reduce redundancy with CP-2 which already addresses plan review and update requirements. Organizations should ensure that their CP-2 implementation includes regular plan updates triggered by significant changes to the system, organizational structure, or threat environment. The consolidation streamlines the contingency planning requirements while maintaining the security intent.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "CP-6",
    family: "CP",
    title: "Alternate Storage Site",
    description: "The organization establishes an alternate storage site including necessary agreements to permit the storage and retrieval of system backup information. The alternate storage site is geographically separated from the primary storage site to reduce susceptibility to the same threats. The organization ensures that the alternate storage site provides security controls equivalent to those of the primary site.",
    supplementalGuidance: "Organizations should consider the geographic distance between primary and alternate storage sites to ensure that both sites are not subject to the same regional threats such as natural disasters. The alternate storage site should provide adequate physical and environmental protections for stored media. Organizations should establish and test procedures for retrieving backup information from the alternate storage site.",
    priority: "P1",
    baseline: "High"
  },
  {
    id: "CP-7",
    family: "CP",
    title: "Alternate Processing Site",
    description: "The organization establishes an alternate processing site including necessary agreements to permit the transfer and resumption of system operations for essential mission and business functions within a defined time period when the primary processing capabilities are unavailable. The organization ensures that equipment and supplies required to transfer and resume operations are available at the alternate processing site or contracts are in place to support delivery to the site.",
    supplementalGuidance: "Organizations should ensure that the alternate processing site provides the same security capabilities as the primary site. The time period for resumption of operations at the alternate site should be based on the recovery time objectives established in the contingency plan. Organizations should regularly test the ability to transfer operations to the alternate processing site and verify that the site can support sustained operations.",
    priority: "P1",
    baseline: "High"
  },
  {
    id: "CP-8",
    family: "CP",
    title: "Telecommunications Services",
    description: "The organization establishes alternate telecommunications services including necessary agreements to permit the resumption of system operations for essential mission and business functions within a defined time period when the primary telecommunications capabilities are unavailable. Alternate telecommunications services include diverse telecommunications service providers, diverse telecommunications pathways, and redundant telecommunications equipment.",
    supplementalGuidance: "Organizations should consider the diversity of telecommunications pathways and service providers to reduce the risk of a single point of failure. Primary and alternate telecommunications services should not share common points of failure such as the same physical cable routes or switching facilities. Organizations should test alternate telecommunications services periodically to verify their availability and capacity.",
    priority: "P1",
    baseline: "High"
  },
  {
    id: "CP-9",
    family: "CP",
    title: "System Backup",
    description: "The organization conducts backups of user-level information, system-level information, and system documentation at a defined frequency consistent with recovery time and recovery point objectives. The organization protects the confidentiality, integrity, and availability of backup information. Backup activities include the identification of critical information and software, the backup schedule, and the storage location of backup copies.",
    supplementalGuidance: "Organizations should implement a comprehensive backup strategy that addresses all critical system components and data. The backup frequency and retention period should be based on the organization's recovery objectives and regulatory requirements. Organizations should regularly test the restoration of backup data to verify the integrity and completeness of backup copies.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "CP-10",
    family: "CP",
    title: "System Recovery and Reconstitution",
    description: "The organization provides for the recovery and reconstitution of the system to a known state within a defined time period after a disruption, compromise, or failure. Recovery involves restoring system capabilities and reconstitution involves returning the system to full operational status. The recovery and reconstitution processes include the restoration of system data, configurations, and software from trusted backup sources.",
    supplementalGuidance: "Organizations should establish detailed recovery and reconstitution procedures that address different types of system failures and disruptions. Recovery priorities should be based on the criticality of system functions and the recovery time objectives established in the contingency plan. Organizations should verify the integrity of recovered systems before returning them to operational status to prevent the reintroduction of compromised components.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "CP-11",
    family: "CP",
    title: "Alternate Communications Protocols",
    description: "The organization provides the capability to employ alternative communications protocols in support of maintaining continuity of operations. Alternative communications protocols enable the system to continue functioning when primary communication channels are unavailable or compromised. This capability addresses both the availability and integrity of communications during contingency operations.",
    supplementalGuidance: "Organizations should identify and implement alternative communication methods that can be used when primary protocols are unavailable. Alternative protocols should be tested periodically to ensure they can support the required communications during contingency operations. The selection of alternative protocols should consider the security properties of the protocol and the types of information that will be transmitted.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "CP-12",
    family: "CP",
    title: "Safe Mode",
    description: "The organization restricts the ability to enter safe mode to authorized personnel and documents safe mode procedures. When an information system cannot operate in its normal mode due to a compromise or failure, the system transitions to a safe mode that restricts the types of activities or connections permitted. Safe mode operations may include limiting functionality, restricting network access, or operating in a degraded state.",
    supplementalGuidance: "Organizations should define the conditions under which the system transitions to safe mode and the specific restrictions imposed during safe mode operations. Safe mode procedures should be documented in the contingency plan and personnel should be trained on safe mode operations. The transition to and from safe mode should be logged for audit purposes.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "CP-13",
    family: "CP",
    title: "Alternative Security Mechanisms",
    description: "The organization employs alternative or supplemental security mechanisms when the primary means of implementing security functions is unavailable or compromised. Alternative security mechanisms provide continued protection for the system when primary mechanisms fail or are rendered ineffective. This control ensures that the loss of a single security mechanism does not leave the system unprotected.",
    supplementalGuidance: "Organizations should identify critical security functions and establish alternative mechanisms that can provide equivalent protection. The transition to alternative security mechanisms should be seamless to minimize disruption to system operations and security coverage. Organizations should test alternative security mechanisms periodically to ensure they can provide adequate protection when needed.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // IA - Identification and Authentication (IA-1 through IA-12)
  // ---------------------------------------------------------------------------
  {
    id: "IA-1",
    family: "IA",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates an identification and authentication policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the identification and authentication policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Identification and authentication policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Organizations should ensure that identification and authentication requirements are commensurate with the risk level of the systems and the sensitivity of the information accessed. Existing organizational policies may make the need for additional specific policies unnecessary.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IA-2",
    family: "IA",
    title: "Identification and Authentication (Organizational Users)",
    description: "The system uniquely identifies and authenticates organizational users or processes acting on behalf of organizational users. Identification and authentication of organizational users is accomplished through passwords, tokens, biometrics, key cards, or other recognized forms of authentication. Multi-factor authentication combining two or more different factors provides stronger assurance of user identity.",
    supplementalGuidance: "Organizations should implement identification and authentication mechanisms that are appropriate for the sensitivity of the information and the risk level of the system. Multi-factor authentication should be required for privileged accounts and for access to sensitive information. Organizations should consider implementing phishing-resistant authentication mechanisms such as FIDO2 or PIV credentials for high-value systems.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IA-3",
    family: "IA",
    title: "Device Identification and Authentication",
    description: "The system uniquely identifies and authenticates specific or types of devices before establishing a local, remote, or network connection. Device authentication is accomplished through shared known information such as MAC addresses, IP addresses, or device certificates. This control addresses device-level authentication to ensure that only authorized devices connect to organizational systems.",
    supplementalGuidance: "Organizations should implement device authentication mechanisms that are appropriate for the operational environment and the risk level of the connection. Certificate-based device authentication provides stronger assurance than MAC address or IP address-based authentication alone. Organizations should maintain an inventory of authorized devices and regularly verify that only approved devices are connected to the network.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "IA-4",
    family: "IA",
    title: "Identifier Management",
    description: "The organization manages system identifiers by receiving authorization from designated personnel to assign an individual, group, role, service, or device identifier. The organization selects an identifier that identifies an individual, group, role, service, or device, assigns the identifier to the intended individual, group, role, service, or device, and prevents reuse of identifiers for a defined time period. The organization also disables the identifier after a defined period of inactivity.",
    supplementalGuidance: "Organizations should implement a formal identifier management process that includes identifier lifecycle management from creation through decommission. Identifier reuse should be prohibited for a sufficient period to prevent confusion in audit records and access control decisions. Organizations should periodically review assigned identifiers to verify their continued validity and disable identifiers that are no longer needed.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IA-5",
    family: "IA",
    title: "Authenticator Management",
    description: "The organization manages system authenticators by establishing initial authenticator content, establishing administrative procedures for initial authenticator distribution, defining conditions for authenticator change or refresh, and protecting authenticator content from unauthorized disclosure and modification. The organization also changes default authenticators prior to system installation and establishes minimum and maximum lifetime restrictions for authenticators.",
    supplementalGuidance: "Authenticators include passwords, cryptographic tokens, biometric data, certificates, and one-time password devices. Organizations should implement policies that enforce authenticator complexity, change frequency, and protection requirements. Default authenticators shipped with hardware and software should be changed immediately upon installation, and unused or expired authenticators should be promptly revoked or disabled.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IA-6",
    family: "IA",
    title: "Authentication Feedback",
    description: "The system obscures feedback of authentication information during the authentication process to protect the information from possible exploitation or use by unauthorized individuals. Authentication feedback includes the display of characters when entering passwords, the display of biometric data, and other visual or audible indicators that could reveal authentication information. The obscuring of authentication feedback does not apply to user name or similar identifiers.",
    supplementalGuidance: "Organizations should ensure that authentication feedback mechanisms do not reveal authentication secrets to observers or through electronic eavesdropping. Password masking with asterisks or dots is a common implementation of this control. Organizations should consider the risk of shoulder surfing and other observation-based attacks when designing authentication interfaces.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "IA-7",
    family: "IA",
    title: "Cryptographic Module Authentication",
    description: "The system implements mechanisms for authentication to a cryptographic module that meet the requirements of applicable laws, executive orders, directives, policies, regulations, standards, and guidelines for such authentication. Cryptographic module authentication typically involves the use of passwords, tokens, or other authenticators to unlock access to the cryptographic capabilities of the module.",
    supplementalGuidance: "Organizations should ensure that cryptographic modules used within the system meet FIPS 140 validation requirements at the appropriate level. Authentication to cryptographic modules should be commensurate with the sensitivity of the information protected by the module. Organizations should implement strong authentication mechanisms for access to cryptographic modules that protect high-value information.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IA-8",
    family: "IA",
    title: "Identification and Authentication (Non-Organizational Users)",
    description: "The system uniquely identifies and authenticates non-organizational users or processes acting on behalf of non-organizational users. Non-organizational users include all system users other than organizational users explicitly covered by IA-2. This control addresses identification and authentication requirements for individuals who access organizational systems from outside the organization.",
    supplementalGuidance: "Organizations should implement identification and authentication mechanisms for non-organizational users that are commensurate with the risk associated with the type of access granted. Non-organizational users may include customers, partners, contractors, and the general public. Organizations should consider using federated identity management solutions to simplify the management of non-organizational user identities while maintaining security requirements.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IA-9",
    family: "IA",
    title: "Service Identification and Authentication",
    description: "The organization identifies and authenticates services and service providers before the services are used by the system. Service identification and authentication ensures that the system only connects to and uses authorized services and service providers. This control addresses the authentication of services such as web services, cloud services, and other external services that interact with the system.",
    supplementalGuidance: "Organizations should implement mutual authentication for services to ensure that both the requesting and providing entities are verified. Service authentication can be accomplished through certificates, tokens, or other cryptographic mechanisms. Organizations should maintain a registry of authorized services and verify service provider identities before establishing connections.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "IA-10",
    family: "IA",
    title: "Adaptive Authentication",
    description: "The organization requires users to provide additional authentication information when defined conditions or situations are identified. Adaptive authentication supplementally challenges users when circumstances dictate a higher level of assurance is needed, such as when accessing from an unfamiliar device, geographic location, or during unusual hours. This control enables risk-based authentication decisions.",
    supplementalGuidance: "Organizations should define the conditions that trigger adaptive authentication challenges and the additional authentication factors required. Conditions may include logging in from a new location, accessing sensitive resources for the first time, or exhibiting behavior inconsistent with established user profiles. Organizations should implement adaptive authentication in a way that balances security requirements with user experience.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "IA-11",
    family: "IA",
    title: "Re-authentication",
    description: "The organization requires users to re-authenticate when defined circumstances or situations require re-authentication. Re-authentication applies to any situation where the confidence in the continued authentication of the user needs to be revalidated. Circumstances requiring re-authentication include privilege escalation, change in role or group membership, after a period of inactivity, and before accessing sensitive operations.",
    supplementalGuidance: "Organizations should define the specific circumstances that trigger re-authentication and the authentication mechanisms to be used for re-authentication. Re-authentication should be required for sensitive operations such as modifying security settings, accessing restricted data, or performing administrative functions. The re-authentication interval should be based on the risk level of the system and the sensitivity of the information being accessed.",
    priority: "P0",
    baseline: "Low"
  },
  {
    id: "IA-12",
    family: "IA",
    title: "Identity Proofing",
    description: "The organization identity proofs users who require accounts for logical access to systems based on appropriate identity proofing methods. Identity proofing is the process by which a credential service provider verifies that a user is who they claim to be before issuing credentials. The level of identity proofing rigor is commensurate with the risk associated with the role and the information to be accessed.",
    supplementalGuidance: "Organizations should implement identity proofing processes that are consistent with NIST SP 800-63 Digital Identity Guidelines. Identity proofing may involve in-person verification, remote verification through trusted third parties, or a combination of methods. Organizations should document the identity proofing process and maintain evidence of identity verification for audit purposes.",
    priority: "P1",
    baseline: "Moderate"
  },

  // ---------------------------------------------------------------------------
  // IR - Incident Response (IR-1 through IR-10)
  // ---------------------------------------------------------------------------
  {
    id: "IR-1",
    family: "IR",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates an incident response policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the incident response policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Incident response policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Organizations should align incident response activities with the organization's risk management strategy and ensure coordination with external entities such as law enforcement and incident response organizations. The policy should address the full incident lifecycle from preparation through lessons learned.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IR-2",
    family: "IR",
    title: "Incident Response Training",
    description: "The organization provides incident response training to system users consistent with assigned roles and responsibilities within a defined time period of assuming an incident response role or responsibility, when required by system changes, and at a defined frequency thereafter. Incident response training includes the procedures for detecting, analyzing, containing, eradicating, and recovering from incidents. Training is tailored to the specific roles of incident response personnel.",
    supplementalGuidance: "Organizations should ensure that incident response training includes both classroom-based and practical exercises. Training should cover the use of incident response tools, communication procedures, and escalation processes. Organizations should update training materials to reflect changes in the threat landscape, organizational structure, and lessons learned from previous incidents.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "IR-3",
    family: "IR",
    title: "Incident Response Testing",
    description: "The organization tests the incident response capability for the system at a defined frequency using defined tests to determine the effectiveness of the incident response capability. Testing methods include tabletop exercises, walkthroughs, simulations, and comprehensive exercises. The organization coordinates incident response testing with organizational elements responsible for related plans such as business continuity and disaster recovery.",
    supplementalGuidance: "Organizations should design incident response tests to evaluate the full range of incident response activities from detection through recovery. Test scenarios should be based on realistic threat scenarios and should exercise both technical and non-technical aspects of the incident response capability. Test results should be documented and used to improve the incident response plan and procedures.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "IR-4",
    family: "IR",
    title: "Incident Handling",
    description: "The organization implements an incident handling capability for incidents that is consistent with the incident response plan and includes preparation, detection and analysis, containment, eradication, and recovery. The organization coordinates incident handling activities with contingency planning activities and incorporates lessons learned from ongoing incident handling activities into incident response procedures, training, and testing. The organization correlates incident information and individual incident responses to achieve an organization-wide perspective.",
    supplementalGuidance: "Organizations should establish a centralized incident handling capability that can coordinate response activities across the enterprise. Incident handling procedures should include criteria for determining the severity of incidents and the appropriate response actions for each severity level. Organizations should implement automated tools for incident detection, analysis, and response to improve the speed and consistency of incident handling.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IR-5",
    family: "IR",
    title: "Incident Monitoring",
    description: "The organization tracks and documents incidents on an ongoing basis. Incident monitoring includes the collection and analysis of information from various sources such as intrusion detection systems, audit records, network monitors, physical access records, and user reports. The organization maintains records of incidents from initial detection through final resolution and closure.",
    supplementalGuidance: "Organizations should implement incident tracking systems that capture all relevant information about each incident including timeline, actions taken, and outcomes. Incident monitoring data should be analyzed to identify trends, recurring issues, and areas for improvement. Organizations should use incident monitoring information to support risk assessments and to justify investments in security controls.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IR-6",
    family: "IR",
    title: "Incident Reporting",
    description: "The organization requires personnel to report suspected incidents to the organizational incident response capability within a defined time period. The organization reports incident information to defined authorities. Incident reporting includes both internal reporting to organizational management and external reporting to oversight bodies, law enforcement, and other organizations as required by law, regulation, or policy.",
    supplementalGuidance: "Organizations should establish clear and accessible reporting channels for personnel to report suspected incidents. Reporting requirements should specify the types of information to be reported, the timeframes for reporting, and the designated recipients. Organizations should provide training and guidance to personnel on recognizing and reporting potential incidents to ensure timely detection and response.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IR-7",
    family: "IR",
    title: "Incident Response Assistance",
    description: "The organization provides an incident response support resource integral to the organizational incident response capability that offers advice and assistance to users of the system for the handling and reporting of incidents. The support resource is an integral part of the organizational incident response capability. Incident response assistance may be provided through a help desk, dedicated security operations center, or designated security personnel.",
    supplementalGuidance: "Organizations should ensure that incident response support resources are available to all system users and that the support is provided in a timely manner. The support resource should have the expertise and authority to provide effective guidance on incident handling procedures. Organizations should publicize the availability and contact information for incident response support resources to ensure that users know how to request assistance.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "IR-8",
    family: "IR",
    title: "Incident Response Plan",
    description: "The organization develops an incident response plan that provides the organization with a roadmap for implementing its incident response capability. The plan describes the structure and organization of the incident response capability, provides a high-level approach for how the incident response capability fits into the overall organization, and defines reportable incidents. The plan is reviewed and updated at a defined frequency and distributed to defined personnel.",
    supplementalGuidance: "Organizations should ensure that the incident response plan is consistent with the organization's mission, size, structure, and functions. The plan should address roles and responsibilities, communication procedures, metrics for measuring capability effectiveness, and references to related plans. Organizations should review and update the plan based on lessons learned from incidents, exercises, changes in the organization, and changes in the threat environment.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "IR-9",
    family: "IR",
    title: "Information Spillage Response",
    description: "The organization responds to information spills by identifying the specific information involved in the contamination, alerting defined personnel, isolating the contaminated system or component, eradicating the information from the contaminated system, and taking other defined corrective actions. Information spillage refers to instances where information is placed on systems that are not authorized to process such information. This includes the inadvertent exposure of classified or sensitive information.",
    supplementalGuidance: "Organizations should establish specific procedures for responding to information spillage incidents that address the unique challenges of containing and remediating unauthorized information disclosures. The response should include notification of affected parties and appropriate authorities as required by policy. Organizations should conduct root cause analysis of spillage incidents to identify and correct the processes or behaviors that led to the spillage.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "IR-10",
    family: "IR",
    title: "Integrated Information Security Analysis Team",
    description: "The organization establishes an integrated team of forensic and malware analysts, tool developers, and real-time operations personnel to support the incident response process. The team provides a cross-functional capability for detecting, analyzing, and responding to sophisticated threats and advanced persistent threat activity. The integrated team approach ensures that diverse expertise is available to address complex incident scenarios.",
    supplementalGuidance: "Organizations should ensure that the integrated analysis team has access to the tools, data, and authorities needed to perform comprehensive analysis of incidents. Team members should have specialized skills in areas such as digital forensics, malware reverse engineering, network analysis, and threat intelligence. Organizations should provide ongoing training and development opportunities to maintain the team's technical capabilities.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // MA - Maintenance (MA-1 through MA-7)
  // ---------------------------------------------------------------------------
  {
    id: "MA-1",
    family: "MA",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a system maintenance policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the system maintenance policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "System maintenance policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The policy should address both routine and non-routine maintenance activities and their associated security implications. Organizations should ensure that maintenance policies cover both on-site and remote maintenance activities and address the use of maintenance tools and equipment.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "MA-2",
    family: "MA",
    title: "Controlled Maintenance",
    description: "The organization schedules, documents, and reviews records of maintenance, repair, and replacement on system components in accordance with manufacturer or vendor specifications and organizational requirements. The organization approves and monitors all maintenance activities, whether performed on site or remotely and whether the system or components are serviced on site or removed to another location. Maintenance activities include hardware servicing, software patching, and firmware updates.",
    supplementalGuidance: "Organizations should maintain detailed records of all maintenance activities including the date, personnel involved, components affected, and the nature of the maintenance performed. Maintenance records should be reviewed periodically to identify trends and potential issues. Organizations should ensure that maintenance activities do not compromise the security of the system and that maintenance personnel have the appropriate clearances and authorizations.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "MA-3",
    family: "MA",
    title: "Maintenance Tools",
    description: "The organization approves, controls, and monitors the use of system maintenance tools. Maintenance tools include diagnostic and test equipment used to conduct maintenance on the system. The organization inspects maintenance tools carried into a facility by maintenance personnel for improper or unauthorized modifications and checks media containing diagnostic and test programs for malicious code before the media are used in the system.",
    supplementalGuidance: "Organizations should maintain an approved list of maintenance tools and ensure that only authorized tools are used for system maintenance. Maintenance tools should be inspected before use to ensure they have not been tampered with or modified in an unauthorized manner. Organizations should consider dedicating maintenance tools to specific systems or facilities to reduce the risk of cross-contamination.",
    priority: "P3",
    baseline: "Moderate"
  },
  {
    id: "MA-4",
    family: "MA",
    title: "Nonlocal Maintenance",
    description: "The organization authorizes, monitors, and controls nonlocal maintenance and diagnostic activities. The organization allows the use of nonlocal maintenance and diagnostic tools only as consistent with organizational policy and documents in the security plan for the system. Nonlocal maintenance and diagnostic activities are conducted by individuals communicating through an external network such as the internet.",
    supplementalGuidance: "Organizations should implement strong authentication and encryption for all nonlocal maintenance sessions. Nonlocal maintenance sessions should be monitored and recorded for audit purposes. Organizations should terminate nonlocal maintenance sessions and network connections when the maintenance is complete and verify that all temporary accounts and access privileges granted for maintenance are removed.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "MA-5",
    family: "MA",
    title: "Maintenance Personnel",
    description: "The organization establishes a process for maintenance personnel authorization and maintains a list of authorized maintenance organizations or personnel. The organization ensures that non-escorted personnel performing maintenance on the system possess the required access authorizations. The organization designates organizational personnel with required access authorizations and technical competence to supervise the maintenance activities of personnel who do not possess the required access authorizations.",
    supplementalGuidance: "Organizations should verify the identities and access authorizations of maintenance personnel before granting access to the system or facility. Maintenance personnel from external organizations should be escorted by authorized organizational personnel unless they have been granted appropriate access authorizations. Organizations should document and review maintenance personnel access authorizations on a regular basis.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "MA-6",
    family: "MA",
    title: "Timely Maintenance",
    description: "The organization obtains maintenance support and spare parts for defined system components within a defined time period of failure. Timely maintenance ensures that failed system components are repaired or replaced promptly to minimize the impact on system availability and security. The organization maintains service level agreements with maintenance providers that specify response times and parts availability.",
    supplementalGuidance: "Organizations should identify critical system components that require timely maintenance support and establish appropriate service level agreements. Spare parts inventories should be maintained for components that are essential to system operations and where long lead times for replacement could adversely affect the mission. Organizations should consider maintaining on-site spare parts for the most critical components.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "MA-7",
    family: "MA",
    title: "Field Maintenance",
    description: "The organization restricts or prohibits field maintenance on defined system components to authorized service facilities. Field maintenance refers to maintenance performed on system components at the location where the components are deployed rather than at a dedicated maintenance facility. This control addresses situations where maintenance should only be performed in controlled environments to protect sensitive system components.",
    supplementalGuidance: "Organizations should identify system components that require maintenance at authorized service facilities based on the sensitivity of the information processed and the security requirements of the component. Restricting field maintenance reduces the risk of unauthorized access to sensitive components and information during the maintenance process. Organizations should establish procedures for securely transporting components to and from authorized maintenance facilities.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // MP - Media Protection (MP-1 through MP-8)
  // ---------------------------------------------------------------------------
  {
    id: "MP-1",
    family: "MP",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a media protection policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the media protection policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Media protection policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The policy should address all types of media including digital media, non-digital media, and system input and output devices. Organizations should consider the full lifecycle of media from acquisition through disposal when developing media protection policies.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "MP-2",
    family: "MP",
    title: "Media Access",
    description: "The organization restricts access to defined types of digital and non-digital media to defined personnel or roles. Media access restrictions apply to both the physical and logical access to media containing organizational information. The organization implements access controls that limit the ability to read, copy, modify, and destroy information on media to authorized individuals only.",
    supplementalGuidance: "Organizations should implement both physical and logical access controls for media based on the sensitivity of the information contained on the media. Physical access controls include locked storage containers and restricted access areas. Logical access controls include encryption and access control lists. Organizations should maintain records of media access to support accountability and audit requirements.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "MP-3",
    family: "MP",
    title: "Media Marking",
    description: "The organization marks system media indicating the distribution limitations, handling caveats, and applicable security markings of the information. Media marking ensures that individuals handling or accessing the media are aware of the sensitivity of the information it contains. The marking is consistent with the information classification and handling guidelines established by the organization.",
    supplementalGuidance: "Organizations should establish media marking procedures that are consistent with the information classification scheme and applicable regulations. Marking can be accomplished through physical labels, electronic headers, and metadata tags. Organizations should ensure that media marking is applied before the media is distributed or stored and that personnel are trained on the meaning of media markings and their handling responsibilities.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "MP-4",
    family: "MP",
    title: "Media Storage",
    description: "The organization physically controls and securely stores defined types of digital and non-digital media within defined controlled areas. The organization protects system media containing sensitive information until the media are destroyed or sanitized using approved equipment, techniques, and procedures. Controlled areas for media storage include locked cabinets, secure rooms, and environmentally controlled vaults.",
    supplementalGuidance: "Organizations should implement environmental controls for media storage areas to protect against damage from temperature, humidity, fire, and other environmental threats. Access to media storage areas should be restricted to authorized personnel and access should be logged. Organizations should maintain an inventory of media in storage and periodically verify the inventory to detect missing or unauthorized media.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "MP-5",
    family: "MP",
    title: "Media Transport",
    description: "The organization protects and controls defined types of digital and non-digital media during transport outside of controlled areas using defined security safeguards. The organization documents activities associated with the transport of system media and restricts the activities associated with the transport of such media to authorized personnel. Transport protections include physical security, encryption, and chain-of-custody documentation.",
    supplementalGuidance: "Organizations should implement transport security measures commensurate with the sensitivity of the information on the media. Encryption should be used to protect the confidentiality of information on digital media during transport. Organizations should maintain chain-of-custody records for media being transported and verify the integrity of media upon receipt at the destination.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "MP-6",
    family: "MP",
    title: "Media Sanitization",
    description: "The organization sanitizes system media prior to disposal, release out of organizational control, or release for reuse using defined sanitization techniques and procedures in accordance with applicable standards and policies. Media sanitization applies to all digital and non-digital media used to store organizational information. The sanitization process ensures that information previously stored on the media cannot be recovered or reconstructed.",
    supplementalGuidance: "Organizations should use sanitization methods that are appropriate for the classification level of the information and the type of media. NIST SP 800-88 provides guidance on media sanitization techniques including clearing, purging, and destroying. Organizations should verify that sanitization has been successfully completed before releasing media and maintain records of sanitization activities for audit purposes.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "MP-7",
    family: "MP",
    title: "Media Use",
    description: "The organization restricts the use of defined types of digital and non-digital media on defined systems or system components using defined security safeguards. Media use restrictions can include prohibiting the use of removable media on certain systems, requiring encryption for removable media, or limiting the types of media that can be used. Organizations enforce media use policies through technical controls and user awareness.",
    supplementalGuidance: "Organizations should implement technical controls such as device whitelisting, port disabling, and data loss prevention tools to enforce media use restrictions. Removable media presents a significant risk for data exfiltration and malware introduction, so organizations should carefully control its use. Organizations should provide alternative mechanisms for legitimate data transfer needs to reduce the temptation to circumvent media use restrictions.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "MP-8",
    family: "MP",
    title: "Media Downgrading",
    description: "The organization establishes a process for downgrading system media that includes employing downgrading mechanisms with defined strength and integrity, ensuring that the downgrading actions are reviewed, tested, validated, and approved, and tracking downgrading actions on a per-item basis. Media downgrading applies to the process of changing the classification or sensitivity level of media to allow its use in a lower security environment.",
    supplementalGuidance: "Organizations should establish clear criteria for when media downgrading is permitted and the specific procedures to be followed. Downgrading should only be performed by authorized personnel using approved methods and should be documented for accountability. Organizations should verify that the downgrading process has been completed successfully before allowing the media to be used in the lower security environment.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // PE - Physical and Environmental Protection (PE-1 through PE-23)
  // ---------------------------------------------------------------------------
  {
    id: "PE-1",
    family: "PE",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a physical and environmental protection policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the physical and environmental protection policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Physical and environmental protection policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. Organizations should coordinate physical and environmental protection requirements with facility management and security organizations. The policy should address the protection of both the physical facility and the system components housed within the facility.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PE-2",
    family: "PE",
    title: "Physical Access Authorizations",
    description: "The organization develops, approves, and maintains a list of individuals with authorized access to the facility where the system resides. The organization issues authorization credentials for facility access and reviews the access list detailing authorized facility access by individuals at a defined frequency. Physical access authorizations apply to employees, contractors, visitors, and other individuals who require access to organizational facilities.",
    supplementalGuidance: "Organizations should implement a formal process for authorizing physical access that includes verification of the individual's identity and need for access. Access authorizations should be reviewed and updated regularly to reflect personnel changes, terminations, and changes in access requirements. Organizations should promptly remove physical access authorizations when individuals no longer require access.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PE-3",
    family: "PE",
    title: "Physical Access Control",
    description: "The organization enforces physical access authorizations at defined entry and exit points to the facility where the system resides by verifying individual access authorizations before granting access and controlling ingress and egress with defined physical access control systems, guards, or both. The organization maintains physical access audit logs for defined entry and exit points. Physical access controls include card readers, biometric scanners, keypads, locks, guards, and mantraps.",
    supplementalGuidance: "Organizations should implement multiple layers of physical access control to create defense in depth for sensitive areas. Entry points should be monitored by security personnel, automated systems, or both. Organizations should regularly test and maintain physical access control systems to ensure they function correctly and provide adequate protection against unauthorized physical access.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PE-4",
    family: "PE",
    title: "Access Control for Transmission",
    description: "The organization controls physical access to defined system distribution and transmission lines within organizational facilities using defined security safeguards. Distribution and transmission lines include cabling used to connect system components and communication wiring. Physical protection of these lines prevents unauthorized physical access that could result in interception, modification, or disruption of communications.",
    supplementalGuidance: "Organizations should protect communication cabling and distribution systems from unauthorized access, interception, and physical damage. Protection measures include routing cables through conduits, using locked wiring closets, implementing cable management systems, and conducting periodic inspections. Organizations should consider using fiber optic cabling for sensitive communications as it is more resistant to electromagnetic interception.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "PE-5",
    family: "PE",
    title: "Access Control for Output Devices",
    description: "The organization controls physical access to system output devices to prevent unauthorized individuals from obtaining the output. Output devices include monitors, printers, scanners, audio devices, and facsimile machines. Physical access control for output devices prevents the inadvertent or deliberate viewing, copying, or removal of sensitive output by unauthorized individuals.",
    supplementalGuidance: "Organizations should position output devices in areas that are physically accessible only to authorized personnel. Printers and similar devices should be located in secure areas with controlled access. Organizations should implement pull printing solutions that require user authentication at the device before releasing print jobs to prevent sensitive documents from being left unattended on output trays.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "PE-6",
    family: "PE",
    title: "Monitoring Physical Access",
    description: "The organization monitors physical access to the facility where the system resides to detect and respond to physical security incidents. Physical access monitoring includes the use of intrusion alarms, surveillance equipment, security guards, and other monitoring mechanisms. The organization reviews physical access logs at a defined frequency and upon occurrence of defined events or potential indications of events.",
    supplementalGuidance: "Organizations should implement automated monitoring systems that provide real-time alerts for unauthorized physical access attempts. Monitoring data should be retained for a period consistent with the organization's audit and investigation requirements. Organizations should integrate physical access monitoring with their overall security monitoring and incident response capabilities to enable comprehensive threat detection.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PE-7",
    family: "PE",
    title: "Visitor Control",
    description: "Withdrawn. This control has been incorporated into PE-2 and PE-3. Organizations should refer to the physical access authorizations control PE-2 and physical access control PE-3 for the visitor control requirements previously addressed by this control.",
    supplementalGuidance: "This control was withdrawn to reduce redundancy. Visitor management requirements are now addressed through PE-2 for access authorization and PE-3 for physical access control. Organizations should ensure their PE-2 and PE-3 implementations include provisions for visitor identification, escort requirements, and visitor access records.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "PE-8",
    family: "PE",
    title: "Visitor Access Records",
    description: "The organization maintains visitor access records to the facility where the system resides that include the name and organization of the person visiting, the signature of the visitor, the form of identification, the date of access, the time of entry and departure, the purpose of the visit, and the name and organization of the person visited. The organization reviews visitor access records at a defined frequency and reports anomalies to defined personnel.",
    supplementalGuidance: "Organizations should maintain visitor access records for a period consistent with the organization's record retention policy and regulatory requirements. Visitor records should be protected from unauthorized access and modification. Organizations should establish procedures for reviewing visitor access records to identify patterns of suspicious activity or unauthorized visits.",
    priority: "P3",
    baseline: "Low"
  },
  {
    id: "PE-9",
    family: "PE",
    title: "Power Equipment and Cabling",
    description: "The organization protects power equipment and power cabling for the system from damage and destruction. Power equipment includes electrical panels, generators, uninterruptible power supplies, and power distribution units. Protection measures include physical barriers, locked enclosures, and restricted access areas to prevent accidental or intentional damage to power infrastructure.",
    supplementalGuidance: "Organizations should ensure that power equipment is located in areas with controlled access and is protected from environmental hazards such as flooding and fire. Power cabling should be routed to minimize the risk of accidental damage and should be protected from unauthorized tampering. Organizations should implement redundant power systems to ensure continued operation in the event of damage to primary power equipment.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "PE-10",
    family: "PE",
    title: "Emergency Shutoff",
    description: "The organization provides the capability of shutting off power to defined system components or the system in emergency situations. Emergency shutoff switches or mechanisms are located in close proximity to the systems and are readily accessible to authorized personnel. The organization protects the emergency power shutoff capability from unauthorized activation.",
    supplementalGuidance: "Organizations should ensure that emergency shutoff mechanisms are clearly marked and accessible to authorized personnel while protected from accidental or unauthorized activation. Emergency shutoff procedures should be documented and personnel should be trained on their use. Organizations should test emergency shutoff capabilities periodically to verify they function correctly.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "PE-11",
    family: "PE",
    title: "Emergency Power",
    description: "The organization provides an uninterruptible power supply to facilitate an orderly shutdown of the system in the event of a primary power source loss. The uninterruptible power supply provides sufficient power to permit the system to perform an orderly shutdown or to transition to a long-term alternative power source. Emergency power provisions protect the system from power fluctuations that could damage hardware or corrupt data.",
    supplementalGuidance: "Organizations should size emergency power systems based on the power requirements of the system components they protect and the time needed to perform an orderly shutdown or transition to alternative power. Emergency power systems should be tested periodically to verify they can provide adequate power for the required duration. Organizations should implement power conditioning equipment to protect against voltage fluctuations and surges.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "PE-12",
    family: "PE",
    title: "Emergency Lighting",
    description: "The organization employs and maintains automatic emergency lighting for the system that activates in the event of a power outage or disruption and that covers emergency exits and evacuation routes within the facility. Emergency lighting ensures that personnel can safely evacuate the facility and that security monitoring activities can continue during power disruptions.",
    supplementalGuidance: "Organizations should ensure that emergency lighting covers all critical areas including server rooms, control rooms, and emergency exits. Emergency lighting systems should be tested periodically and batteries should be replaced according to manufacturer recommendations. Organizations should consider using emergency lighting that is sufficient for personnel to safely operate system components during power outages.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PE-13",
    family: "PE",
    title: "Fire Protection",
    description: "The organization employs and maintains fire detection and suppression systems for the facility that are supported by an independent energy source. The organization employs fire detection devices and systems that activate automatically and notify defined personnel and emergency responders in the event of a fire. Fire suppression systems are appropriate for the environment and the type of equipment being protected.",
    supplementalGuidance: "Organizations should select fire suppression systems that are appropriate for the type of equipment and materials in the protected area. Clean agent fire suppression systems are preferred for areas containing electronic equipment as they do not leave residue. Organizations should ensure that fire detection and suppression systems are inspected and maintained in accordance with applicable codes and standards.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PE-14",
    family: "PE",
    title: "Environmental Controls",
    description: "The organization maintains temperature and humidity levels within the facility where the system resides at defined acceptable levels and monitors environmental conditions at a defined frequency. Environmental controls protect system components from damage due to excessive heat, cold, or humidity. The organization employs environmental monitoring systems that provide alarms when conditions exceed acceptable ranges.",
    supplementalGuidance: "Organizations should implement automated environmental monitoring systems that provide real-time alerts when temperature or humidity levels deviate from acceptable ranges. Environmental controls should be sized appropriately for the heat load generated by the system components in the facility. Organizations should establish procedures for responding to environmental control failures to protect system components from damage.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PE-15",
    family: "PE",
    title: "Water Damage Protection",
    description: "The organization protects the system from damage resulting from water leakage by providing master shutoff or isolation valves that are accessible, working properly, and known to key personnel. Water damage protection includes implementing detection mechanisms such as water sensors and alarms in areas where the system is located. The organization coordinates water damage protection measures with facility management and emergency response teams.",
    supplementalGuidance: "Organizations should install water detection sensors in areas where system components are located, particularly in areas near water pipes, HVAC systems, and below grade. Water detection systems should be connected to the alarm monitoring system and provide alerts to appropriate personnel. Organizations should ensure that water shutoff valves are accessible and that personnel know their locations and how to operate them.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PE-16",
    family: "PE",
    title: "Delivery and Removal",
    description: "The organization authorizes and controls defined types of system components entering and exiting the facility and maintains records of the items. Delivery and removal controls include the inspection of incoming hardware and software to verify that the items match purchase orders and are free from tampering. The organization controls the removal of system components from the facility to prevent unauthorized removal of equipment or information.",
    supplementalGuidance: "Organizations should implement a formal process for authorizing and tracking the delivery and removal of system components. Incoming items should be inspected before being introduced into the system environment. Organizations should maintain an asset tracking system that records the movement of system components into and out of the facility to support accountability and investigation activities.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "PE-17",
    family: "PE",
    title: "Alternate Work Site",
    description: "The organization employs management, operational, and technical controls at alternate work sites equivalent to those at the primary site. Alternate work sites include government facilities or private residences of employees where work is performed. The organization assesses the effectiveness of controls at alternate work sites as feasible and provides a means for employees to communicate with security personnel in case of incidents.",
    supplementalGuidance: "Organizations should establish security requirements for alternate work sites that address physical security, network security, and the protection of organizational information. Employees working at alternate sites should be provided with guidance on securing their workspace and protecting sensitive information. Organizations should periodically assess the security posture of alternate work sites to ensure compliance with organizational security requirements.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "PE-18",
    family: "PE",
    title: "Location of System Components",
    description: "The organization positions system components within the facility to minimize potential damage from physical and environmental hazards and to minimize the opportunity for unauthorized access. The location of system components considers the proximity to external walls, windows, loading docks, and other access points. Components are positioned to reduce the risk of interception, damage, and unauthorized physical access.",
    supplementalGuidance: "Organizations should consider the placement of system components relative to potential threat sources such as external walls, windows, and areas accessible to the general public. Sensitive system components should be located in interior areas of the facility away from external access points. Organizations should consider the proximity of system components to potential environmental hazards such as water pipes, HVAC equipment, and fire suppression systems.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "PE-19",
    family: "PE",
    title: "Information Leakage",
    description: "The organization protects the system from information leakage due to electromagnetic signals emanations. Information leakage includes the unintentional release of data through electromagnetic emanations from system components that could be intercepted by unauthorized individuals using specialized equipment. TEMPEST countermeasures and other shielding techniques are employed to protect against emanations-based information leakage.",
    supplementalGuidance: "Organizations should assess the risk of information leakage through electromagnetic emanations based on the sensitivity of the information processed by the system. TEMPEST protections can include shielded enclosures, filtered power lines, and fiber optic communications. Organizations should consult with appropriate technical experts to determine the level of emanation protection needed for their specific operational environment.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "PE-20",
    family: "PE",
    title: "Asset Monitoring and Tracking",
    description: "The organization employs asset location technologies to track and monitor the location and movement of defined assets within defined controlled areas. Asset monitoring and tracking capabilities help organizations detect unauthorized removal of system components and maintain accountability for organizational assets. Technologies used for asset tracking include RFID tags, GPS systems, and cellular-based location services.",
    supplementalGuidance: "Organizations should implement asset tracking solutions that are appropriate for the value and sensitivity of the assets being monitored. Asset tracking data should be integrated with the organization's asset management and security monitoring systems. Organizations should establish procedures for responding to alerts generated by asset tracking systems that indicate unauthorized asset movement.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "PE-21",
    family: "PE",
    title: "Electromagnetic Pulse Protection",
    description: "The organization employs protective measures against electromagnetic pulse damage for defined system components. Electromagnetic pulse events can be caused by high-altitude nuclear detonations, specialized weapons, or lightning and can damage or destroy electronic system components. Protection measures include hardened enclosures, surge protectors, and geographically distributed processing capabilities.",
    supplementalGuidance: "Organizations should assess the risk of electromagnetic pulse events based on the geographic location and criticality of the system. Protection measures should be commensurate with the assessed risk and the criticality of the system components being protected. Organizations should consider both natural and adversarial electromagnetic pulse threats when determining appropriate protective measures.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "PE-22",
    family: "PE",
    title: "Component Marking",
    description: "The organization marks system components indicating the impact level or classification level of the information permitted to be processed, stored, or transmitted by the component. Component marking enables personnel to quickly determine the security level of a particular system or component. Marking methods include physical labels, electronic tags, and color coding schemes.",
    supplementalGuidance: "Organizations should establish a component marking scheme that is consistent with the information classification framework and readily understood by personnel. Component markings should be applied in a manner that is tamper-resistant and clearly visible. Organizations should include component marking requirements in their asset management and configuration management processes.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "PE-23",
    family: "PE",
    title: "Facility Location",
    description: "The organization plans the location of the facility where the system resides considering physical and environmental hazards and for existing facilities, considers the physical and environmental hazards in the organizational risk management strategy. Facility location planning considers threats such as flooding, earthquakes, hurricanes, and proximity to hazardous materials storage or transportation routes. The selection of facility location is a risk-based decision that balances operational requirements with security considerations.",
    supplementalGuidance: "Organizations should conduct a comprehensive risk assessment of potential facility locations that considers both natural and man-made threats. The assessment should evaluate the proximity to emergency response services, critical infrastructure, and potential threat sources. Organizations should consider establishing geographically dispersed facilities to reduce the risk of a single event affecting all organizational systems.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // PL - Planning (PL-1 through PL-11)
  // ---------------------------------------------------------------------------
  {
    id: "PL-1",
    family: "PL",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a planning policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the planning policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Planning policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The planning policy establishes the framework for developing security and privacy plans for organizational systems. Organizations should ensure that planning activities are integrated with the system development life cycle and enterprise architecture processes.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PL-2",
    family: "PL",
    title: "System Security and Privacy Plans",
    description: "The organization develops security and privacy plans for the system that are consistent with the organization's enterprise architecture, defines the constituent system components, describes the operational context of the system, provides the security and privacy categorization of the system, describes the operational environment for the system, and describes relationships with or connections to other systems. The plans are reviewed and updated at a defined frequency.",
    supplementalGuidance: "System security and privacy plans are the primary documents that describe the implementation of the security and privacy controls for the system. The plans should be comprehensive enough to support the authorization decision and should be consistent with the organization's risk management strategy. Organizations should maintain the plans as living documents that are updated to reflect changes in the system and its operating environment.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PL-3",
    family: "PL",
    title: "System Security Plan Update",
    description: "Withdrawn. This control has been incorporated into PL-2. Organizations should refer to the system security and privacy plans control PL-2 for the plan update requirements previously addressed by this control. The plan update activities are now addressed as part of the overall plan development and maintenance process.",
    supplementalGuidance: "This control was withdrawn to reduce redundancy with PL-2 which already addresses plan review and update requirements. Organizations should ensure that their PL-2 implementation includes regular plan updates triggered by significant changes to the system, organizational policies, or the threat environment. Plan updates should be documented and approved by the authorizing official.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "PL-4",
    family: "PL",
    title: "Rules of Behavior",
    description: "The organization establishes and makes readily available to individuals requiring access to the system the rules that describe their responsibilities and expected behavior for information and system usage, security, and privacy. The organization receives a signed acknowledgment from such individuals indicating that they have read, understand, and agree to abide by the rules of behavior before authorizing access to information and the system.",
    supplementalGuidance: "Organizations should ensure that rules of behavior cover all relevant aspects of system usage including acceptable use, data handling, incident reporting, and consequences for violations. Rules of behavior should be reviewed and updated periodically to address changes in organizational policies and the operating environment. Organizations should require personnel to re-acknowledge the rules of behavior at a defined frequency.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "PL-5",
    family: "PL",
    title: "Privacy Impact Assessment",
    description: "Withdrawn. This control has been incorporated into RA-8. Organizations should refer to the privacy impact assessments control RA-8 for the requirements previously addressed by this control. Privacy impact assessments are now addressed under the risk assessment family to better align with the risk-based approach to privacy.",
    supplementalGuidance: "This control was withdrawn to consolidate privacy-related assessment activities under the risk assessment family. Organizations should ensure that their RA-8 implementation addresses the privacy impact assessment requirements formerly covered by this control. The consolidation provides a more integrated approach to assessing privacy risks within the broader risk management framework.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "PL-6",
    family: "PL",
    title: "Security-Related Activity Planning",
    description: "Withdrawn. This control has been incorporated into PL-2. Organizations should refer to the system security and privacy plans control PL-2 for security-related activity planning requirements previously addressed by this control. Security-related activity planning is now addressed as part of the overall system security planning process.",
    supplementalGuidance: "This control was withdrawn to reduce redundancy with PL-2. Organizations should ensure their system security and privacy plans address the planning of security-related activities including assessments, audits, maintenance, and training. The integration of activity planning into the system security plan provides a more cohesive approach to security planning.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "PL-7",
    family: "PL",
    title: "Concept of Operations",
    description: "The organization develops a concept of operations for the system that describes how the organization intends to operate the system from the perspective of information security and privacy. The concept of operations includes a description of the operational environment, system objectives, security requirements, and the organizational roles and responsibilities related to the operation and maintenance of the system.",
    supplementalGuidance: "The concept of operations provides a high-level description of the system's security and privacy posture and how it supports the organization's mission. Organizations should ensure that the concept of operations is consistent with the system security plan and other security documentation. The document serves as a communication tool between management, technical staff, and external stakeholders.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "PL-8",
    family: "PL",
    title: "Security and Privacy Architectures",
    description: "The organization develops security and privacy architectures for the system that describe how the overall security and privacy architecture is implemented. The architectures include a description of the philosophy, requirements, and approach to be taken with regard to protecting the confidentiality, integrity, and availability of organizational information. The architectures are reviewed and updated at a defined frequency to reflect changes.",
    supplementalGuidance: "Security and privacy architectures can be developed at the system level, mission level, or business process level. The architectures should be consistent with and support the organization's enterprise architecture and risk management strategy. Organizations should ensure that security and privacy architectures address all aspects of the system including hardware, software, firmware, networks, and interfaces with external systems.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "PL-9",
    family: "PL",
    title: "Central Management",
    description: "The organization centrally manages defined security controls and related processes. Central management includes the organization-wide management and implementation of selected security controls across all organizational systems. Centrally managed controls and processes include those related to account management, configuration management, continuous monitoring, patch management, and vulnerability management.",
    supplementalGuidance: "Central management reduces inconsistencies in the implementation and management of security controls across the organization. Organizations should identify the specific controls that benefit from centralized management based on the complexity and diversity of their system environment. Automated tools and platforms can facilitate the central management of security controls across distributed organizational systems.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "PL-10",
    family: "PL",
    title: "Baseline Selection",
    description: "The organization selects a control baseline for the system based on the security and privacy categorization of the system. The selected baseline represents the minimum set of controls necessary to protect the system and the information it processes. Organizations tailor the baseline by supplementing it with additional controls based on risk assessments and specific operational requirements.",
    supplementalGuidance: "Organizations should follow the categorization process described in FIPS 199 and NIST SP 800-60 to determine the appropriate baseline for their systems. The baseline selection should be documented in the system security plan and approved by the authorizing official. Organizations may need to apply controls from higher baselines based on specific risk factors or regulatory requirements.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PL-11",
    family: "PL",
    title: "Baseline Tailoring",
    description: "The organization tailors the selected control baseline by applying scoping guidance, selecting compensating controls, assigning specific values to parameters, supplementing the baseline with additional controls, and providing additional specification information for control implementation. Baseline tailoring ensures that the controls applied to the system are appropriate for the specific operational environment and risk profile.",
    supplementalGuidance: "Organizations should document all tailoring decisions and the rationale for each decision in the system security plan. Tailoring activities should be reviewed and approved by the authorizing official to ensure that the resulting control set provides adequate protection. Organizations should consider threat intelligence, vulnerability information, and organizational risk tolerance when making tailoring decisions.",
    priority: "P1",
    baseline: "Low"
  },

  // ---------------------------------------------------------------------------
  // PM - Program Management (PM-1 through PM-32)
  // ---------------------------------------------------------------------------
  {
    id: "PM-1",
    family: "PM",
    title: "Information Security Program Plan",
    description: "The organization develops and disseminates an organization-wide information security program plan that provides an overview of the requirements for the security program and a description of the security program management controls and common controls in place or planned for meeting those requirements. The plan is reviewed and updated at a defined frequency to address organizational changes and problems identified during plan implementation or control assessments.",
    supplementalGuidance: "The information security program plan can be represented in a single document or compilations of documents at the discretion of the organization. The plan documents the organization-wide security strategy and provides the basis for managing the security program. Organizations should ensure that the plan is aligned with the organization's mission, business objectives, and risk management strategy.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-2",
    family: "PM",
    title: "Information Security Program Leadership Role",
    description: "The organization appoints a senior information security officer with the mission and resources to coordinate, develop, implement, and maintain an organization-wide information security program. The senior information security officer serves as the primary liaison for the information security program and advises the head of the organization on information security matters. This role has the authority to ensure that security requirements are integrated into organizational processes.",
    supplementalGuidance: "Organizations should ensure that the senior information security officer has the authority, resources, and organizational placement to effectively manage the security program. The role should have direct access to senior organizational leadership to communicate security risks and requirements. Organizations should define the specific responsibilities of the role including risk management, policy development, and incident response oversight.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-3",
    family: "PM",
    title: "Information Security and Privacy Resources",
    description: "The organization includes the resources needed to implement the information security and privacy programs in capital planning and investment requests and documents all exceptions to this requirement. The organization prepares, implements, and updates plans that describe how resources are allocated to protect the information and system. Resource planning ensures that adequate funding, staffing, and technology are available to support the security program.",
    supplementalGuidance: "Organizations should integrate information security and privacy resource requirements into the organization's budget planning and capital investment processes. Resource planning should consider both current security needs and anticipated future requirements based on threat trends and technology changes. Organizations should establish metrics to demonstrate the value and effectiveness of security investments.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-4",
    family: "PM",
    title: "Plan of Action and Milestones Process",
    description: "The organization implements a process to ensure that plans of action and milestones for the information security, privacy, and supply chain risk management programs and associated organizational systems are maintained and document the remedial information security, privacy, and supply chain risk management actions to adequately respond to risk. The organization reviews plans of action and milestones at a defined frequency and in accordance with organizational policies.",
    supplementalGuidance: "The plan of action and milestones process helps organizations prioritize and track the remediation of security and privacy weaknesses. Organizations should establish criteria for prioritizing remediation actions based on risk level, resource availability, and operational impact. The process should include regular reviews of outstanding items to ensure that remediation activities are progressing according to schedule.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-5",
    family: "PM",
    title: "System Inventory",
    description: "The organization develops and maintains an inventory of organizational systems. The inventory includes all systems that process, store, or transmit organizational information and identifies the interfaces between each system and all connected systems. The system inventory supports the identification of information systems that require protection and the assessment of organization-wide security posture.",
    supplementalGuidance: "Organizations should maintain a comprehensive and current inventory of all systems including cloud-based systems, mobile systems, and systems operated on behalf of the organization by third parties. The inventory should be reconciled periodically to identify unauthorized or unaccounted-for systems. Organizations should integrate the system inventory with their asset management and configuration management processes.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-6",
    family: "PM",
    title: "Measures of Performance",
    description: "The organization develops, monitors, and reports on the results of information security and privacy measures of performance. Measures of performance help organizations assess the implementation, efficiency, and effectiveness of security controls and the overall security program. Performance metrics should be meaningful, measurable, and actionable to support informed decision-making.",
    supplementalGuidance: "Organizations should establish a balanced set of metrics that address process, outcome, and impact measures. Performance measures should be aligned with organizational goals and objectives and should be regularly reviewed and updated to ensure they remain relevant. Automated tools and dashboards can facilitate the collection, analysis, and reporting of security performance metrics.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-7",
    family: "PM",
    title: "Enterprise Architecture",
    description: "The organization develops and maintains an enterprise architecture with consideration for information security, privacy, and the resulting risk to organizational operations and assets, individuals, other organizations, and the nation. The enterprise architecture includes a security and privacy architecture that describes the security and privacy considerations and requirements throughout the system development life cycle.",
    supplementalGuidance: "Organizations should integrate security and privacy requirements into the enterprise architecture from the earliest stages of design. The enterprise architecture should reflect the organization's risk management strategy and support the implementation of security controls across all systems. Organizations should review and update the enterprise architecture regularly to reflect changes in the organization and the threat environment.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-8",
    family: "PM",
    title: "Critical Infrastructure Plan",
    description: "The organization addresses information security and privacy issues in the development, documentation, and updating of a critical infrastructure and key resources protection plan. The plan identifies the critical assets and systems that are essential to the organization's mission and the measures in place to protect those assets. The plan is coordinated with other organizational plans including contingency plans and continuity of operations plans.",
    supplementalGuidance: "Organizations should identify their critical infrastructure components and the dependencies between them to understand the potential impact of a disruption. The plan should address both physical and cyber threats to critical infrastructure and include measures for prevention, detection, response, and recovery. Organizations should coordinate critical infrastructure protection activities with relevant government agencies and private sector partners.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-9",
    family: "PM",
    title: "Risk Management Strategy",
    description: "The organization develops a comprehensive strategy to manage risk to organizational operations and assets, individuals, other organizations, and the nation associated with the operation and use of organizational systems. The strategy consistently addresses risk from the organization level through the mission and business process level to the system level. The risk management strategy is reviewed and updated at a defined frequency.",
    supplementalGuidance: "The risk management strategy establishes the organizational approach to identifying, assessing, responding to, and monitoring risk. The strategy should define the risk tolerance of the organization and provide guidance on the types of risk responses that are acceptable. Organizations should ensure that the risk management strategy is communicated to all relevant stakeholders and is integrated into organizational decision-making processes.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-10",
    family: "PM",
    title: "Authorization Process",
    description: "The organization manages the authorization process for organizational systems by establishing and managing the authorization process for systems across the organization, assigns an authorizing official for each system, and ensures the authorization process is integrated into the continuous monitoring program. The authorization process includes the evaluation of risk and the explicit acceptance of risk by the authorizing official.",
    supplementalGuidance: "Organizations should establish a consistent authorization process that applies to all organizational systems. The process should include clear criteria for granting, denying, and revoking authorizations. Organizations should implement ongoing authorization mechanisms that allow for continuous risk assessment and authorization decisions rather than relying solely on periodic reauthorization.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-11",
    family: "PM",
    title: "Mission and Business Process Definition",
    description: "The organization defines organizational mission and business processes with consideration for information security and privacy and the resulting risk to organizational operations, organizational assets, individuals, other organizations, and the nation. The organization determines information protection and personally identifiable information processing needs arising from the defined mission and business processes.",
    supplementalGuidance: "Organizations should integrate information security and privacy considerations into the definition and management of mission and business processes. The identification of protection needs should be based on a thorough understanding of the information processed, the systems used, and the threats and vulnerabilities relevant to each process. This analysis supports the categorization of systems and the selection of appropriate security controls.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-12",
    family: "PM",
    title: "Insider Threat Program",
    description: "The organization implements an insider threat program that includes a cross-discipline insider threat incident handling team. The insider threat program gathers, integrates, and centrally analyzes information from multiple sources to identify potential insider threat activities. The program includes the development of insider threat policies, procedures, and detection capabilities to address the full range of insider threats.",
    supplementalGuidance: "Organizations should establish an insider threat program that integrates information from human resources, security, information technology, and other relevant organizational functions. The program should include mechanisms for identifying behavioral indicators of insider threats and procedures for responding to identified threats. Organizations should balance insider threat monitoring with employee privacy rights and applicable laws and regulations.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-13",
    family: "PM",
    title: "Security and Privacy Workforce",
    description: "The organization establishes a security and privacy workforce development and improvement program. The program identifies, tracks, and manages the security and privacy workforce to ensure that adequate personnel with the necessary skills and competencies are available to support the organization's security and privacy requirements. The program addresses recruitment, retention, training, and professional development of security and privacy personnel.",
    supplementalGuidance: "Organizations should assess their current and future security and privacy workforce needs and develop plans to address any gaps. The workforce program should include professional development opportunities, career paths, and succession planning. Organizations should leverage industry certifications, training programs, and academic partnerships to develop and maintain the skills of their security and privacy workforce.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-14",
    family: "PM",
    title: "Testing, Training, and Monitoring",
    description: "The organization implements a process for ensuring that organizational plans for conducting security and privacy testing, training, and monitoring activities associated with organizational systems are developed and maintained. The process includes the management of testing, training, and monitoring results across the organization. The organization uses the results to support risk management decisions and improve the security and privacy posture.",
    supplementalGuidance: "Organizations should establish a comprehensive testing, training, and monitoring strategy that addresses all organizational systems. The strategy should define the frequency, scope, and methods for testing and monitoring activities. Organizations should analyze results across systems to identify trends, common weaknesses, and areas for improvement in the overall security program.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-15",
    family: "PM",
    title: "Security and Privacy Groups and Associations",
    description: "The organization establishes and institutionalizes contact with selected groups and associations within the security and privacy communities to stay current with recommended security and privacy practices, techniques, and technologies. The organization shares current security and privacy-related information with appropriate external entities through these contacts. Participation in security groups and associations facilitates the exchange of threat intelligence and best practices.",
    supplementalGuidance: "Organizations should identify and participate in security and privacy groups that are relevant to their mission, industry, and operational environment. Contacts should include government agencies, industry groups, professional associations, and academic institutions. Organizations should designate individuals to represent the organization in these groups and to disseminate relevant information to internal stakeholders.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-16",
    family: "PM",
    title: "Threat Awareness Program",
    description: "The organization implements a threat awareness program that includes a cross-organization information-sharing capability that can influence the development of the system and security architectures, selection of security solutions, monitoring, threat hunting, and response and recovery activities. The threat awareness program provides threat intelligence to organizational decision-makers to support risk-informed security and privacy decisions.",
    supplementalGuidance: "Organizations should establish threat awareness programs that collect, analyze, and disseminate threat information from multiple sources including government agencies, industry partners, and commercial threat intelligence providers. The program should provide actionable intelligence that can be used to improve security controls and response capabilities. Organizations should participate in information sharing and analysis organizations relevant to their industry.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-17",
    family: "PM",
    title: "Protecting Controlled Unclassified Information on External Systems",
    description: "The organization establishes policy and procedures to ensure that requirements for the protection of controlled unclassified information that is processed, stored, or transmitted on external systems are implemented in accordance with applicable laws, executive orders, directives, policies, regulations, and standards. External systems include systems operated by contractors, partners, and other entities outside the organization.",
    supplementalGuidance: "Organizations should define the security requirements for controlled unclassified information processed on external systems and include these requirements in contracts and agreements. Compliance with protection requirements should be verified through assessments, audits, or other monitoring mechanisms. Organizations should maintain visibility into the security practices of external system operators through regular reporting and oversight.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-18",
    family: "PM",
    title: "Privacy Program Plan",
    description: "The organization develops and disseminates an organization-wide privacy program plan that provides an overview of the organization's privacy program and a description of the privacy program management controls and common controls in place or planned. The plan includes the role of the senior agency official for privacy and identifies privacy requirements based on applicable laws, regulations, and policies.",
    supplementalGuidance: "The privacy program plan can be a standalone document or integrated with the information security program plan. The plan should identify the organization's privacy goals, objectives, and strategies. Organizations should ensure that the privacy program plan is reviewed and updated periodically to address changes in privacy requirements and organizational practices.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-19",
    family: "PM",
    title: "Privacy Program Leadership Role",
    description: "The organization appoints a senior agency official for privacy with the authority, mission, accountability, and resources to coordinate, develop, and implement applicable privacy requirements and manage privacy risks through the organization-wide privacy program. The senior privacy official is responsible for developing and maintaining the privacy program and ensuring compliance with applicable privacy laws, regulations, and policies.",
    supplementalGuidance: "Organizations should ensure that the senior privacy official has sufficient authority and organizational placement to effectively manage the privacy program. The role should have direct access to senior leadership and should be independent of information technology functions where possible. Organizations should provide adequate resources and staffing to support the privacy program's objectives.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-20",
    family: "PM",
    title: "Dissemination of Privacy Program Information",
    description: "The organization maintains a central resource accessible to the public on the organization's website that contains the organization's privacy program information. The publicly accessible information includes the organization's privacy policies, system of records notices, privacy impact assessments, and privacy reports. This transparency supports public trust and accountability in the organization's handling of personal information.",
    supplementalGuidance: "Organizations should ensure that publicly available privacy program information is current, accurate, and easily accessible. The information should be written in plain language that is understandable to the general public. Organizations should update privacy program information promptly when changes occur in privacy practices, policies, or applicable requirements.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-21",
    family: "PM",
    title: "Accounting of Disclosures",
    description: "The organization develops and maintains an accurate accounting of disclosures of personally identifiable information including the date, nature, and purpose of each disclosure and the name and address of the person or organization to which the disclosure was made. The accounting of disclosures supports the individual's right to know who has received their personal information and for what purpose.",
    supplementalGuidance: "Organizations should implement automated mechanisms to track and record disclosures of personally identifiable information wherever feasible. The accounting should be maintained for the required retention period and should be made available to individuals upon request. Organizations should include the accounting of disclosures requirement in system design specifications for systems that process personal information.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-22",
    family: "PM",
    title: "Personally Identifiable Information Quality Management",
    description: "The organization develops and documents organization-wide policies and procedures for ensuring the quality of personally identifiable information. Quality management activities include the correction, deletion, and disposal of inaccurate or outdated personally identifiable information. The organization establishes processes to enable individuals to request corrections to their personal information and to resolve disputes regarding data accuracy.",
    supplementalGuidance: "Organizations should implement data quality controls throughout the information lifecycle from collection through disposal. Quality management should include periodic reviews of data accuracy, completeness, and currency. Organizations should provide accessible mechanisms for individuals to report and request correction of inaccurate personal information.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-23",
    family: "PM",
    title: "Data Governance Body",
    description: "The organization establishes a data governance body consisting of representatives from key organizational functions to provide leadership, guidance, and oversight for data governance activities. The governance body develops data governance policies, provides strategic direction for data management, and oversees the implementation of data governance processes across the organization.",
    supplementalGuidance: "The data governance body should include representatives from information security, privacy, legal, records management, and business functions. The body should establish data governance policies that address data quality, data protection, data sharing, and data retention. Organizations should ensure that the data governance body has the authority and resources to enforce data governance policies across the organization.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-24",
    family: "PM",
    title: "Data Integrity Board",
    description: "The organization establishes a data integrity board to oversee organizational computer matching agreements and to ensure that those agreements comply with the computer matching provisions of the Privacy Act. The data integrity board reviews and approves all matching programs and monitors the implementation of matching agreements to protect individual privacy rights. The board includes the inspector general or designee as a member.",
    supplementalGuidance: "The data integrity board should establish procedures for reviewing proposed computer matching programs and assessing their compliance with applicable privacy requirements. The board should document its review and approval decisions and maintain records of all active matching programs. Organizations should ensure that the board meets at the frequency necessary to provide timely oversight of matching activities.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-25",
    family: "PM",
    title: "Minimization of Personally Identifiable Information Used in Testing, Training, and Research",
    description: "The organization develops policies and procedures that address the use of personally identifiable information for internal testing, training, and research. The organization implements controls to minimize the use, collection, and retention of personally identifiable information for testing, training, and research purposes. Where feasible, the organization uses de-identified, synthetic, or anonymized data sets instead of actual personally identifiable information.",
    supplementalGuidance: "Organizations should establish clear criteria for when the use of personally identifiable information in testing, training, and research environments is justified. Data masking, anonymization, and synthetic data generation techniques should be employed to reduce the risk of unauthorized disclosure. Organizations should periodically review testing and training environments to ensure that personally identifiable information is not retained beyond its authorized purpose.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-26",
    family: "PM",
    title: "Complaint Management",
    description: "The organization develops and implements a process for receiving and responding to complaints, concerns, or questions from individuals about the organizational security and privacy practices. The complaint management process includes acknowledgment of the complaint, investigation of the issue, and communication of the resolution to the complainant. The organization tracks complaints and uses the information to identify trends and areas for improvement.",
    supplementalGuidance: "Organizations should provide accessible mechanisms for individuals to submit complaints and should respond to complaints in a timely manner. The complaint management process should include procedures for escalating complex or sensitive complaints to appropriate organizational officials. Organizations should analyze complaint data to identify systemic issues and implement corrective actions to prevent recurring problems.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-27",
    family: "PM",
    title: "Privacy Reporting",
    description: "The organization develops and disseminates privacy reports on an organization-defined frequency to designated oversight bodies to demonstrate accountability with statutory, regulatory, and policy privacy mandates. Privacy reports include information on the state of the privacy program, significant privacy events, privacy impact assessments completed, and the status of remediation activities for identified privacy issues.",
    supplementalGuidance: "Organizations should establish a privacy reporting cadence and content framework that meets the requirements of applicable laws, regulations, and organizational policies. Privacy reports should provide sufficient detail to enable oversight bodies to assess the effectiveness of the privacy program. Organizations should use standardized reporting formats to facilitate comparison across reporting periods and organizational entities.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-28",
    family: "PM",
    title: "Risk Framing",
    description: "The organization establishes and maintains a risk framing strategy that includes identifying assumptions, constraints, risk tolerances, and priorities for managing risk at the organizational level. Risk framing establishes the context within which risk management decisions are made and provides the foundation for the risk management process. The strategy is informed by applicable laws, executive orders, directives, and organizational mission requirements.",
    supplementalGuidance: "Risk framing should precede risk assessment and should establish the boundaries and parameters for risk management activities. Organizations should ensure that risk framing considers both internal and external factors that may affect the organization's risk posture. The risk framing strategy should be communicated to all relevant stakeholders and should be reviewed and updated as conditions change.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-29",
    family: "PM",
    title: "Risk Management Program Leadership Roles",
    description: "The organization appoints a senior accountable official for risk management to align information security and privacy management processes with strategic, operational, and budgetary planning processes. The organization establishes a risk executive function to facilitate the organization-wide application of the risk management process. The risk management leadership ensures that risk management is integrated into organizational governance structures.",
    supplementalGuidance: "The risk management leadership role should have the authority and organizational placement to influence risk management decisions across the organization. The risk executive function should coordinate risk management activities across organizational functions and systems. Organizations should ensure that risk management leadership has access to timely and accurate information about the organization's risk posture.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-30",
    family: "PM",
    title: "Supply Chain Risk Management Strategy",
    description: "The organization develops an organization-wide strategy for managing supply chain risks associated with the development, acquisition, maintenance, and disposal of systems, system components, and system services. The strategy addresses the identification, assessment, and mitigation of supply chain risks throughout the system development life cycle. The strategy is reviewed and updated at a defined frequency.",
    supplementalGuidance: "Organizations should integrate supply chain risk management into their overall risk management strategy and ensure that supply chain risks are considered in acquisition and procurement decisions. The strategy should address risks associated with both domestic and international supply chains and should include criteria for evaluating the trustworthiness of suppliers. Organizations should implement controls to detect and prevent the introduction of counterfeit or compromised components.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-31",
    family: "PM",
    title: "Continuous Monitoring Strategy",
    description: "The organization develops an organization-wide continuous monitoring strategy and implements a continuous monitoring program. The strategy establishes metrics, monitoring frequencies, and an assessment approach for ongoing monitoring of the security and privacy posture of organizational systems. The continuous monitoring program provides ongoing awareness of threats, vulnerabilities, and the effectiveness of security controls.",
    supplementalGuidance: "The continuous monitoring strategy should address the monitoring of system-level controls, common controls, and the overall security program. Organizations should leverage automated tools and technologies to support continuous monitoring activities. The strategy should define how continuous monitoring results are used to support ongoing authorization decisions and to inform risk management activities.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PM-32",
    family: "PM",
    title: "Purposing",
    description: "The organization analyzes systems on an organization-defined frequency to identify those that are operating in a degraded or debilitated state and have the potential to adversely affect the mission or business functions of the organization. The analysis includes the identification of systems that are no longer needed, systems that require significant upgrades, and systems that should be replaced or decommissioned. Purposing decisions are documented and incorporated into organizational planning.",
    supplementalGuidance: "Organizations should establish criteria for evaluating the condition and suitability of systems relative to their intended purpose. Systems that are identified as operating in a degraded state should be prioritized for remediation, replacement, or decommission. Organizations should integrate purposing activities with their capital planning and investment processes to ensure that resources are allocated appropriately.",
    priority: "P1",
    baseline: "Low"
  },

  // ---------------------------------------------------------------------------
  // PS - Personnel Security (PS-1 through PS-9)
  // ---------------------------------------------------------------------------
  {
    id: "PS-1",
    family: "PS",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a personnel security policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the personnel security policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Personnel security policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The policy should address all phases of the employment lifecycle from pre-employment screening through termination and transfer. Organizations should coordinate personnel security requirements with human resources and legal departments.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PS-2",
    family: "PS",
    title: "Position Risk Designation",
    description: "The organization assigns a risk designation to all organizational positions and establishes screening criteria for individuals filling those positions. The organization reviews and updates position risk designations at a defined frequency. Risk designations reflect the level of trust, sensitivity, and potential for harm associated with the position and determine the level of background investigation required.",
    supplementalGuidance: "Organizations should categorize positions based on the sensitivity of the information that the position has access to and the potential impact of actions taken by the individual in the position. Position risk designations should be reviewed when there are changes in the position's duties, access privileges, or the sensitivity of the systems the position supports. Organizations should coordinate position risk designations with their human resources and security offices.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PS-3",
    family: "PS",
    title: "Personnel Screening",
    description: "The organization screens individuals prior to authorizing access to the system and rescreens individuals at a defined frequency and when defined events occur that trigger a rescreen. The level of screening is commensurate with the risk designation of the position and the sensitivity of the information to be accessed. Personnel screening includes background checks, reference checks, and verification of credentials and qualifications.",
    supplementalGuidance: "Organizations should implement screening processes that are consistent with applicable laws, regulations, and organizational policies. The depth and scope of the screening should be appropriate for the risk level of the position. Organizations should establish procedures for taking action when screening reveals information that may affect the individual's suitability for the position.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PS-4",
    family: "PS",
    title: "Personnel Termination",
    description: "The organization upon termination of individual employment disables system access within a defined time period, terminates or revokes any authenticators and credentials associated with the individual, conducts exit interviews that include a discussion of information security topics, retrieves all security-related organizational property, and retains access to organizational information and systems formerly controlled by the terminated individual.",
    supplementalGuidance: "Organizations should establish termination procedures that ensure the timely removal of all access privileges and the return of all organizational property. Termination procedures should be coordinated between human resources, information technology, security, and the individual's supervisor. For involuntary terminations, organizations should consider the potential for retaliatory actions and implement appropriate safeguards.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PS-5",
    family: "PS",
    title: "Personnel Transfer",
    description: "The organization reviews and confirms ongoing operational need for current logical and physical access authorizations to systems and facilities when individuals are reassigned or transferred to other positions within the organization. The organization initiates defined transfer or reassignment actions within a defined time period following the formal transfer action. Access authorizations are modified as necessary to reflect the individual's new role and responsibilities.",
    supplementalGuidance: "Organizations should ensure that access privileges are adjusted promptly when personnel are transferred to reflect their new responsibilities and to remove access that is no longer needed. Transfer procedures should include a review of the individual's current access authorizations and a determination of the access needed for the new position. Organizations should coordinate transfer actions between the losing and gaining organizations.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "PS-6",
    family: "PS",
    title: "Access Agreements",
    description: "The organization develops and documents access agreements for organizational systems, ensures that individuals requiring access to organizational information and systems sign appropriate access agreements before being granted access, and reviews and updates the access agreements at a defined frequency. Access agreements include nondisclosure agreements, acceptable use agreements, rules of behavior, and conflict-of-interest agreements.",
    supplementalGuidance: "Organizations should ensure that access agreements clearly define the terms and conditions of access and the consequences of violations. Access agreements should be tailored to the type of access being granted and the sensitivity of the information involved. Organizations should maintain signed copies of access agreements and require individuals to re-acknowledge agreements periodically or when significant changes occur.",
    priority: "P3",
    baseline: "Low"
  },
  {
    id: "PS-7",
    family: "PS",
    title: "External Personnel Security",
    description: "The organization establishes personnel security requirements including security roles and responsibilities for external providers. The organization requires external providers to comply with personnel security policies and procedures established by the organization. The organization monitors provider compliance with personnel security requirements and documents personnel security requirements in acquisition documents.",
    supplementalGuidance: "Organizations should include personnel security requirements in contracts and service level agreements with external providers. Compliance with personnel security requirements should be verified through audits, assessments, or other monitoring mechanisms. Organizations should ensure that external personnel undergo appropriate background screening before being granted access to organizational systems and information.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PS-8",
    family: "PS",
    title: "Personnel Sanctions",
    description: "The organization employs a formal sanctions process for individuals failing to comply with established information security and privacy policies and procedures. The sanctions process is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The organization notifies defined personnel within a defined time period when a formal employee sanctions process is initiated.",
    supplementalGuidance: "Organizations should establish and communicate a graduated sanctions process that includes verbal and written warnings, suspension of access privileges, reassignment, demotion, and termination. The sanctions process should be applied consistently and fairly across the organization. Organizations should coordinate the sanctions process with human resources, legal counsel, and management to ensure compliance with applicable employment laws and regulations.",
    priority: "P3",
    baseline: "Low"
  },
  {
    id: "PS-9",
    family: "PS",
    title: "Position Descriptions",
    description: "The organization incorporates security and privacy role and responsibility requirements into organizational position descriptions. Position descriptions include the specific security and privacy duties expected of the individual in the position, required security certifications and training, and the level of access to organizational information and systems. The integration of security requirements into position descriptions supports accountability and workforce planning.",
    supplementalGuidance: "Organizations should ensure that security and privacy responsibilities are clearly defined in position descriptions for all positions that have security or privacy implications. Position descriptions should be reviewed and updated when there are changes in the position's duties, required skills, or access requirements. Organizations should use position descriptions to support personnel selection, performance evaluation, and training planning.",
    priority: "P1",
    baseline: "Low"
  },

  // ---------------------------------------------------------------------------
  // PT - PII Processing and Transparency (PT-1 through PT-8)
  // ---------------------------------------------------------------------------
  {
    id: "PT-1",
    family: "PT",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a personally identifiable information processing and transparency policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "PII processing and transparency policies should be consistent with applicable privacy laws, regulations, and organizational privacy requirements. The policy should address the full lifecycle of personally identifiable information from collection through disposal. Organizations should ensure that the policy is communicated to all personnel who process personally identifiable information.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PT-2",
    family: "PT",
    title: "Authority to Process Personally Identifiable Information",
    description: "The organization determines and documents the legal authority that permits the collection, use, maintenance, and sharing of personally identifiable information for each system and for each collection of personally identifiable information. The organization specifies in its privacy notices the authority that permits the processing of personally identifiable information. Legal authorities can include federal statutes, executive orders, regulations, and contracts.",
    supplementalGuidance: "Organizations should identify and document the specific legal basis for each type of personally identifiable information processing activity. The documentation should include references to the specific statutes, regulations, or other legal authorities that authorize the processing. Organizations should review processing authorities periodically and when there are changes in applicable laws or organizational activities.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PT-3",
    family: "PT",
    title: "Personally Identifiable Information Processing Purposes",
    description: "The organization identifies and documents the specific purpose for processing personally identifiable information and describes the purpose in its privacy notices. The organization limits the processing of personally identifiable information to only that which is compatible with the identified purpose. Purpose limitation is a fundamental privacy principle that ensures personal information is not used for purposes beyond those for which it was collected.",
    supplementalGuidance: "Organizations should define the specific purposes for which personally identifiable information is collected and processed before the collection occurs. The purposes should be documented in system privacy impact assessments and privacy notices. Organizations should implement technical and policy controls to prevent the use of personally identifiable information for purposes other than those identified and documented.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PT-4",
    family: "PT",
    title: "Consent",
    description: "The organization implements mechanisms to obtain consent from individuals for the processing of their personally identifiable information where consent is required by applicable law, regulation, or policy. The consent mechanism provides individuals with clear and understandable information about the purposes for which their information will be processed and the option to decline or withdraw consent. Organizations maintain records of consent provided by individuals.",
    supplementalGuidance: "Organizations should implement consent mechanisms that are specific, informed, and freely given. The consent process should be designed to be easily understandable and should not be bundled with other terms and conditions. Organizations should provide individuals with the ability to withdraw consent and should implement processes to cease processing when consent is withdrawn.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PT-5",
    family: "PT",
    title: "Privacy Notice",
    description: "The organization provides effective notice to the public and to individuals regarding its activities that impact privacy, including its collection, use, sharing, safeguarding, maintenance, and disposal of personally identifiable information. The privacy notice includes the authority for collecting the information, whether providing the information is mandatory or voluntary, the effects of not providing the information, and the purpose for which the information will be used.",
    supplementalGuidance: "Organizations should provide privacy notices at the point of collection and make general privacy notices available through their websites. Privacy notices should be written in plain language and should be updated when there are changes in privacy practices. Organizations should consider providing layered notices that provide summary information with links to more detailed explanations.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PT-6",
    family: "PT",
    title: "System of Records Notice",
    description: "The organization publishes system of records notices in the Federal Register that provide effective notice to individuals about any privacy act system of records. The notice includes the system name, location, categories of individuals covered, categories of records maintained, routine uses, policies and practices for storage, retrievability, access controls, retention, and disposal. The notice is updated when there are significant changes to the system of records.",
    supplementalGuidance: "System of records notices are required under the Privacy Act for federal agencies that maintain systems of records. Organizations should ensure that notices are accurate, complete, and current. Organizations should publish updated notices in the Federal Register when significant changes are made to the system of records or the practices described in the existing notice.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PT-7",
    family: "PT",
    title: "Specific Categories of Personally Identifiable Information",
    description: "The organization identifies and applies processing conditions for specific categories of personally identifiable information that may require additional protections. Specific categories include social security numbers, financial information, health information, biometric data, and information about minors. The organization implements enhanced technical, physical, and administrative safeguards for these categories of personally identifiable information.",
    supplementalGuidance: "Organizations should identify the specific categories of personally identifiable information that are processed by their systems and determine whether additional protections are required by law, regulation, or policy. Enhanced protections may include stronger encryption, additional access controls, more frequent auditing, and stricter retention requirements. Organizations should train personnel on the handling requirements for specific categories of personally identifiable information.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "PT-8",
    family: "PT",
    title: "Computer Matching Requirements",
    description: "The organization applies the applicable provisions of the Computer Matching and Privacy Protection Act when conducting computer matching programs. The organization establishes and maintains matching agreements for programs that compare records from two or more automated systems of records. Computer matching programs are subject to the oversight of the data integrity board and require specific procedural safeguards to protect individual privacy.",
    supplementalGuidance: "Organizations should establish procedures for identifying and managing computer matching programs in compliance with the Computer Matching and Privacy Protection Act. Matching agreements should specify the purpose, legal authority, records to be matched, and procedures for handling results. Organizations should ensure that matching programs are reviewed and approved by the data integrity board before implementation.",
    priority: "P1",
    baseline: "Low"
  },

  // ---------------------------------------------------------------------------
  // RA - Risk Assessment (RA-1 through RA-10)
  // ---------------------------------------------------------------------------
  {
    id: "RA-1",
    family: "RA",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a risk assessment policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the risk assessment policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Risk assessment policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The policy should establish the framework for conducting risk assessments across the organization. Organizations should ensure that risk assessment activities are integrated with the organization's overall risk management strategy.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "RA-2",
    family: "RA",
    title: "Security Categorization",
    description: "The organization categorizes information and the system in accordance with applicable laws, executive orders, directives, policies, regulations, standards, and guidelines. The organization documents the security categorization results including supporting rationale in the security plan for the system. The categorization process considers the potential impact on organizational operations, organizational assets, individuals, other organizations, and the nation if the information or system is compromised.",
    supplementalGuidance: "Organizations should follow the categorization guidance in FIPS 199 and NIST SP 800-60 to determine the appropriate security category for their systems. The categorization should consider the confidentiality, integrity, and availability impact levels for the information processed, stored, and transmitted by the system. Security categorization is the foundation for the selection of appropriate security controls.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "RA-3",
    family: "RA",
    title: "Risk Assessment",
    description: "The organization conducts an assessment of risk including the likelihood and magnitude of harm from the unauthorized access, use, disclosure, disruption, modification, or destruction of the system, the information it processes, stores, or transmits, and any related information. The organization documents risk assessment results and updates the risk assessment at a defined frequency or when there are significant changes to the system, its environment of operation, or other conditions that may impact the security or privacy state of the system.",
    supplementalGuidance: "Risk assessments take into account vulnerabilities, threat sources, and security controls planned or in place to determine the resulting level of residual risk. Organizations should use a consistent risk assessment methodology and framework such as NIST SP 800-30. The results of risk assessments should be communicated to relevant stakeholders and used to inform risk management decisions.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "RA-4",
    family: "RA",
    title: "Risk Assessment Update",
    description: "Withdrawn. This control has been incorporated into RA-3. Organizations should refer to the risk assessment control RA-3 for the risk assessment update requirements previously addressed by this control. Risk assessment updates are now addressed as part of the ongoing risk assessment process.",
    supplementalGuidance: "This control was withdrawn to reduce redundancy with RA-3 which already addresses the periodic review and update of risk assessments. Organizations should ensure that their RA-3 implementation includes provisions for updating risk assessments based on changes in the system, threat environment, and organizational risk tolerance. The integration of update requirements into RA-3 provides a more streamlined approach.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "RA-5",
    family: "RA",
    title: "Vulnerability Monitoring and Scanning",
    description: "The organization monitors and scans for vulnerabilities in the system and hosted applications at a defined frequency and when new vulnerabilities potentially affecting the system are identified and reported. The organization employs vulnerability monitoring tools and techniques that facilitate interoperability among tools and automate parts of the vulnerability management process by using standards for enumerating platforms, software flaws, and improper configurations.",
    supplementalGuidance: "Organizations should implement a comprehensive vulnerability scanning program that includes network-based, host-based, and application-level scanning. Vulnerability scanning results should be analyzed and prioritized based on the severity of the vulnerability and the criticality of the affected system. Organizations should establish timeframes for remediating identified vulnerabilities based on their risk rating.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "RA-6",
    family: "RA",
    title: "Technical Surveillance Countermeasures Survey",
    description: "The organization employs a technical surveillance countermeasures survey at defined locations at a defined frequency or when defined events or indicators occur. Technical surveillance countermeasures surveys detect the presence of technical surveillance devices and activities directed at collecting classified or sensitive information. The surveys are conducted by qualified personnel using appropriate equipment and techniques.",
    supplementalGuidance: "Organizations should determine the need for technical surveillance countermeasures surveys based on the sensitivity of the information processed in the surveyed areas. Surveys should be conducted by trained and qualified personnel using state-of-the-art detection equipment. Organizations should establish procedures for responding to the detection of technical surveillance devices or activities.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "RA-7",
    family: "RA",
    title: "Risk Response",
    description: "The organization responds to findings from security and privacy assessments, monitoring, and audits in accordance with organizational risk tolerance. Risk responses include accepting, avoiding, mitigating, sharing, or transferring risk. The organization documents the risk response decisions and the rationale for the chosen response and ensures that risk responses are implemented within defined time frames.",
    supplementalGuidance: "Organizations should establish a consistent framework for evaluating and responding to identified risks. The risk response should be commensurate with the level of risk and the organization's risk tolerance. Organizations should track risk response actions to completion and verify that the selected response effectively reduces the risk to an acceptable level.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "RA-8",
    family: "RA",
    title: "Privacy Impact Assessments",
    description: "The organization conducts privacy impact assessments for systems processing personally identifiable information. The assessment evaluates the privacy risks associated with the system and identifies measures to mitigate those risks. Privacy impact assessments are conducted when a system is developed or significantly modified and when there are changes in the types of personally identifiable information processed or the processing activities performed.",
    supplementalGuidance: "Privacy impact assessments should evaluate the collection, use, sharing, and storage of personally identifiable information and assess the potential privacy risks to individuals. The assessment should identify privacy controls and safeguards to mitigate identified risks. Organizations should publish summaries of privacy impact assessments to the extent required by applicable law and organizational policy.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "RA-9",
    family: "RA",
    title: "Criticality Analysis",
    description: "The organization identifies critical system components and functions by performing a criticality analysis for defined systems, system components, or system services at defined decision points in the system development life cycle. The criticality analysis identifies the mission-essential functions that must be protected to ensure continued operations. The analysis informs the prioritization of security and protection measures.",
    supplementalGuidance: "Criticality analysis helps organizations focus their security resources on the most important system components and functions. The analysis should consider the dependencies between system components and the impact of component failure on mission-essential functions. Organizations should update criticality analyses when there are significant changes to the system architecture or mission requirements.",
    priority: "P1",
    baseline: "High"
  },
  {
    id: "RA-10",
    family: "RA",
    title: "Threat Hunting",
    description: "The organization establishes and maintains a cyber threat hunting capability to search for indicators of compromise in organizational systems and detect, track, and disrupt threats that evade existing controls. Threat hunting is a proactive approach to threat detection that uses intelligence-driven hypotheses, analytics, and manual techniques to identify advanced threats. The hunting capability uses threat intelligence, anomaly detection, and data analytics to identify adversary activity.",
    supplementalGuidance: "Organizations should establish threat hunting programs that are supported by adequate tools, technologies, and skilled personnel. Threat hunting activities should be informed by current threat intelligence and should focus on detecting threats that are likely to target the organization. Organizations should document and share the results of threat hunting activities to improve the overall security posture and to enhance detection capabilities.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // SA - System and Services Acquisition (SA-1 through SA-23)
  // ---------------------------------------------------------------------------
  {
    id: "SA-1",
    family: "SA",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a system and services acquisition policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the system and services acquisition policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "System and services acquisition policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The policy should address the integration of security requirements into the acquisition process. Organizations should ensure that security requirements are included in all stages of the system acquisition lifecycle from planning through disposal.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SA-2",
    family: "SA",
    title: "Allocation of Resources",
    description: "The organization determines the high-level information security and privacy requirements for the system or system service in mission and business process planning, determines and documents the resources required to protect the system or system service as part of the organizational capital planning and investment control process, and establishes a discrete line item for information security and privacy in organizational programming and budgeting documentation.",
    supplementalGuidance: "Organizations should ensure that adequate resources are allocated for information security and privacy throughout the system lifecycle. Resource allocation should be based on the security categorization of the system and the specific security requirements identified through risk assessment. Organizations should track security-related expenditures separately to enable effective oversight and accountability.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SA-3",
    family: "SA",
    title: "System Development Life Cycle",
    description: "The organization manages the system using a defined system development life cycle that incorporates information security and privacy considerations. The organization defines and documents information security and privacy roles and responsibilities throughout the system development life cycle, identifies individuals having information security and privacy roles and responsibilities, and integrates the organizational information security and privacy risk management process into system development life cycle activities.",
    supplementalGuidance: "Organizations should select a system development life cycle methodology that is appropriate for the system and organizational requirements. Security and privacy activities should be integrated into each phase of the development lifecycle rather than being addressed as an afterthought. Organizations should establish security gates at key decision points in the lifecycle to ensure that security requirements are being met.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SA-4",
    family: "SA",
    title: "Acquisition Process",
    description: "The organization includes security and privacy functional requirements, strength requirements, security and privacy assurance requirements, controls, control enhancements, and other security and privacy-related information in the acquisition contract for the system, system component, or system service. The organization requires the developer of the system to provide a description of the functional properties of the controls employed and design and implementation information for the controls.",
    supplementalGuidance: "Organizations should include security requirements in all acquisition documents including requests for proposals, contracts, and service level agreements. Security requirements should be specific, measurable, and testable. Organizations should evaluate proposed solutions against security requirements during the source selection process and verify compliance during acceptance testing.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SA-5",
    family: "SA",
    title: "System Documentation",
    description: "The organization obtains or develops administrator documentation for the system that describes the secure configuration, installation, and operation of the system, effective use and maintenance of security and privacy functions and mechanisms, and known vulnerabilities regarding configuration and use of administrative functions. The organization also obtains or develops user documentation that describes user-accessible security and privacy functions, methods for their use, and user responsibilities.",
    supplementalGuidance: "Organizations should ensure that system documentation is current, complete, and available to authorized personnel. Documentation should include security-relevant configuration parameters and their recommended settings. Organizations should protect system documentation from unauthorized access as it may contain information that could be exploited by adversaries to compromise the system.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "SA-6",
    family: "SA",
    title: "Software Usage Restrictions",
    description: "Withdrawn. This control has been incorporated into CM-10 and SI-7. Organizations should refer to the software usage restrictions control CM-10 and the software, firmware, and information integrity control SI-7 for the requirements previously addressed by this control.",
    supplementalGuidance: "This control was withdrawn to consolidate software usage requirements under configuration management and system integrity controls. Organizations should ensure that their CM-10 and SI-7 implementations address the software usage restriction requirements formerly covered by this control. The consolidation eliminates redundancy while maintaining the security intent of controlling software usage.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SA-7",
    family: "SA",
    title: "User-Installed Software",
    description: "Withdrawn. This control has been incorporated into CM-11 and SI-7. Organizations should refer to the user-installed software control CM-11 and the software, firmware, and information integrity control SI-7 for the requirements previously addressed by this control.",
    supplementalGuidance: "This control was withdrawn to consolidate user-installed software requirements under configuration management and system integrity controls. Organizations should ensure that their CM-11 and SI-7 implementations address the user-installed software requirements formerly covered by this control. The consolidation provides a more integrated approach to controlling software installation.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SA-8",
    family: "SA",
    title: "Security and Privacy Engineering Principles",
    description: "The organization applies systems security and privacy engineering principles in the specification, design, development, implementation, and modification of the system and system components. Security engineering principles include defense in depth, least privilege, fail-safe defaults, complete mediation, separation of duties, minimization of attack surface, and privacy by design. These principles are applied throughout the system development lifecycle.",
    supplementalGuidance: "Organizations should ensure that system designers and developers are trained on security and privacy engineering principles and their application. Security engineering principles should be documented in the system architecture and design specifications. Organizations should verify that security engineering principles are correctly implemented through code reviews, design reviews, and testing activities.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SA-9",
    family: "SA",
    title: "External System Services",
    description: "The organization requires that providers of external system services comply with organizational security and privacy requirements and employ appropriate controls in accordance with applicable laws, executive orders, directives, policies, regulations, standards, and guidelines. The organization defines and documents organizational oversight and user roles and responsibilities with regard to external system services and monitors compliance with security requirements.",
    supplementalGuidance: "Organizations should include security requirements in contracts and service level agreements with external service providers. External services include cloud services, managed security services, and outsourced system operations. Organizations should implement oversight mechanisms to verify that external service providers maintain compliance with security requirements throughout the service period.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SA-10",
    family: "SA",
    title: "Developer Configuration Management",
    description: "The organization requires the developer of the system, system component, or system service to perform configuration management during system, component, or service development, implementation, and operation. The developer tracks security flaws, flaw resolution, and reports findings to defined personnel. Configuration management includes tracking changes to the system, maintaining documentation of changes, and verifying the integrity of system components.",
    supplementalGuidance: "Organizations should include developer configuration management requirements in acquisition contracts and verify compliance through reviews and audits. Developer configuration management should address source code management, build management, and release management. Organizations should require developers to maintain an audit trail of all changes made to system components during development.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SA-11",
    family: "SA",
    title: "Developer Testing and Evaluation",
    description: "The organization requires the developer of the system, system component, or system service to create and implement a security and privacy assessment plan. The developer performs unit, integration, system, and regression testing and evaluation at a defined depth and coverage and produces evidence of the execution of the assessment plan and the results of the testing and evaluation.",
    supplementalGuidance: "Organizations should define the types and depth of testing required based on the criticality and risk level of the system. Testing should include both functional security testing and vulnerability scanning. Organizations should review developer testing results and verify that identified issues have been remediated before accepting the system or component.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SA-12",
    family: "SA",
    title: "Supply Chain Protection",
    description: "Withdrawn. This control has been incorporated into SR-1 through SR-12. Organizations should refer to the supply chain risk management family for the supply chain protection requirements previously addressed by this control. Supply chain protection is now addressed comprehensively through the dedicated supply chain risk management control family.",
    supplementalGuidance: "This control was withdrawn when the supply chain risk management family was introduced in Revision 5. Organizations should ensure that their implementation of the SR family controls adequately addresses the supply chain protection requirements formerly covered by this control. The dedicated SR family provides a more comprehensive framework for managing supply chain risks.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SA-13",
    family: "SA",
    title: "Trustworthiness",
    description: "Withdrawn. This control has been incorporated into SA-8. Organizations should refer to the security and privacy engineering principles control SA-8 for the trustworthiness requirements previously addressed by this control. Trustworthiness considerations are now integrated into the broader security engineering principles framework.",
    supplementalGuidance: "This control was withdrawn to consolidate trustworthiness requirements under security engineering principles. Organizations should ensure that their SA-8 implementation addresses trustworthiness as part of the security engineering process. Trustworthiness encompasses the assurance that system components will operate as intended and resist subversion.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SA-14",
    family: "SA",
    title: "Criticality Analysis",
    description: "Withdrawn. This control has been incorporated into RA-9. Organizations should refer to the criticality analysis control RA-9 for the requirements previously addressed by this control. Criticality analysis is now addressed under the risk assessment family to better align with the risk management framework.",
    supplementalGuidance: "This control was withdrawn to consolidate criticality analysis requirements under the risk assessment family. Organizations should ensure that their RA-9 implementation addresses the criticality analysis requirements formerly covered by this control. The consolidation provides a more integrated approach to identifying and prioritizing critical system components.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SA-15",
    family: "SA",
    title: "Development Process, Standards, and Tools",
    description: "The organization requires the developer of the system, system component, or system service to follow a documented development process that explicitly addresses security and privacy requirements, identifies the standards and tools used in the development process, and documents the specific tool options and tool configurations used in the development process. The development process includes secure coding practices and quality assurance processes.",
    supplementalGuidance: "Organizations should evaluate and approve the development processes, standards, and tools used by developers to ensure they support the production of secure systems. Development tools should include static and dynamic analysis tools, code review tools, and security testing tools. Organizations should require developers to use approved development environments and maintain separation between development, test, and production environments.",
    priority: "P2",
    baseline: "High"
  },
  {
    id: "SA-16",
    family: "SA",
    title: "Developer-Provided Training",
    description: "The organization requires the developer of the system, system component, or system service to provide defined training on the correct use and operation of the implemented security and privacy functions, controls, and mechanisms. Training covers the proper configuration, administration, and operation of the system's security capabilities. Developer-provided training ensures that organizational personnel can effectively use and maintain the security features of the system.",
    supplementalGuidance: "Organizations should specify developer training requirements in acquisition contracts and ensure that training is provided before the system is placed into operation. Training should be tailored to the roles and responsibilities of the trainees including system administrators, operators, and end users. Organizations should evaluate the quality and effectiveness of developer-provided training.",
    priority: "P2",
    baseline: "High"
  },
  {
    id: "SA-17",
    family: "SA",
    title: "Developer Security and Privacy Architecture and Design",
    description: "The organization requires the developer of the system, system component, or system service to produce a design specification and security and privacy architecture that is consistent with the organization's security and privacy architecture, accurately and completely describes the required security and privacy functionality, and serves as the basis for implementation. The architecture addresses security and privacy from a defense-in-depth perspective.",
    supplementalGuidance: "Organizations should review developer security architectures and designs to ensure they meet organizational security requirements. The security architecture should describe how the system implements the required security controls and how the controls work together to provide comprehensive protection. Organizations should verify that the implemented system is consistent with the approved design specification.",
    priority: "P1",
    baseline: "High"
  },
  {
    id: "SA-18",
    family: "SA",
    title: "Tamper Resistance and Detection",
    description: "Withdrawn. This control has been incorporated into SR-9. Organizations should refer to the tamper resistance and detection control SR-9 for the requirements previously addressed by this control. Tamper resistance and detection capabilities are now addressed under the supply chain risk management family.",
    supplementalGuidance: "This control was withdrawn when supply chain risk management controls were added in Revision 5. Organizations should ensure that their SR-9 implementation addresses the tamper resistance and detection requirements formerly covered by this control. The consolidation aligns tamper protection with the broader supply chain risk management framework.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SA-19",
    family: "SA",
    title: "Component Authenticity",
    description: "Withdrawn. This control has been incorporated into SR-11. Organizations should refer to the component authenticity control SR-11 for the requirements previously addressed by this control. Component authenticity verification is now addressed under the supply chain risk management family for better alignment with supply chain risk management activities.",
    supplementalGuidance: "This control was withdrawn to consolidate component authenticity requirements under the supply chain risk management family. Organizations should ensure that their SR-11 implementation addresses the component authenticity requirements formerly covered by this control. Verifying component authenticity is a critical element of supply chain risk management.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SA-20",
    family: "SA",
    title: "Customized Development of Critical Components",
    description: "The organization re-implements or custom develops defined critical system components when the standard commercial or government off-the-shelf solution is not adequate to address specific security requirements. Custom development of critical components allows organizations to build components that meet their unique security needs and that can be more thoroughly analyzed and tested. The decision to custom develop is based on a cost-benefit analysis and risk assessment.",
    supplementalGuidance: "Organizations should carefully evaluate the security benefits and costs of custom development versus the use of commercial products. Custom-developed components may provide greater assurance against certain types of threats but require ongoing maintenance and support. Organizations should ensure that custom development follows secure development practices and that the resulting components are thoroughly tested.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SA-21",
    family: "SA",
    title: "Developer Screening",
    description: "The organization requires that the developer of the system, system component, or system service satisfies defined personnel screening requirements. Developer screening helps ensure that individuals with access to the development environment and source code are trustworthy and do not pose a risk to the integrity of the system. Screening requirements are commensurate with the criticality and sensitivity of the system being developed.",
    supplementalGuidance: "Organizations should define screening requirements for developers based on the sensitivity of the system and the level of access granted during development. Screening may include background investigations, verification of citizenship, and checks for criminal history. Organizations should include developer screening requirements in acquisition contracts and verify compliance.",
    priority: "P1",
    baseline: "High"
  },
  {
    id: "SA-22",
    family: "SA",
    title: "Unsupported System Components",
    description: "The organization replaces system components when support for the components is no longer available from the developer, vendor, or manufacturer. The organization provides options for alternative sources for continued support for unsupported components when replacement is not feasible. Unsupported components may not receive security patches or updates, increasing the risk of exploitation of known vulnerabilities.",
    supplementalGuidance: "Organizations should maintain awareness of the support status of all system components and plan for the replacement of components before support ends. When replacement is not immediately feasible, organizations should implement compensating controls to mitigate the increased risk associated with unsupported components. Organizations should include end-of-support considerations in their technology refresh planning.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "SA-23",
    family: "SA",
    title: "Specialization",
    description: "The organization employs specialized processing components to increase the security and privacy of the system. Specialized components include those designed for specific security functions such as cryptographic processing, content filtering, and intrusion detection. The use of specialized components allows organizations to implement security functions with greater assurance and performance than general-purpose components.",
    supplementalGuidance: "Organizations should evaluate the benefits of using specialized security components versus implementing security functions on general-purpose hardware and software. Specialized components can provide higher performance and greater assurance for critical security functions. Organizations should ensure that specialized components are compatible with the overall system architecture and are properly configured and maintained.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // SC - System and Communications Protection (SC-1 through SC-51)
  // ---------------------------------------------------------------------------
  {
    id: "SC-1",
    family: "SC",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a system and communications protection policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the system and communications protection policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "System and communications protection policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The policy should address the protection of information during processing, transmission, and storage. Organizations should ensure that the policy covers both internal and external communications protection requirements.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SC-2",
    family: "SC",
    title: "Separation of System and User Functionality",
    description: "The system separates user functionality including user interface services from system management functionality. Separation of system and user functionality can include isolating administrative interfaces on different domains, using different computers, or employing virtualization techniques. This separation reduces the attack surface by limiting the exposure of administrative functions to potential user-level compromises.",
    supplementalGuidance: "Organizations should implement separation mechanisms that are appropriate for the sensitivity of the system and the risk level of the operational environment. Virtualization, containerization, and network segmentation are common techniques for implementing this separation. Organizations should ensure that the separation mechanisms are properly configured and that they cannot be bypassed by unprivileged users.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SC-3",
    family: "SC",
    title: "Security Function Isolation",
    description: "The system isolates security functions from nonsecurity functions. Security function isolation is achieved through the use of hardware separation, software separation, or a combination of both. The isolation of security functions ensures that nonsecurity functions cannot interfere with or compromise the correct operation of security mechanisms and that security functions are protected from tampering and bypass.",
    supplementalGuidance: "Organizations should implement security function isolation using mechanisms that are appropriate for the sensitivity and criticality of the system. Hardware-based isolation provides the strongest separation guarantees. Organizations should verify that isolation mechanisms are correctly implemented and that security functions cannot be affected by failures or compromises in nonsecurity components.",
    priority: "P1",
    baseline: "High"
  },
  {
    id: "SC-4",
    family: "SC",
    title: "Information in Shared System Resources",
    description: "The system prevents unauthorized and unintended information transfer via shared system resources. Shared system resources include memory, storage, network connections, and processing capabilities that may be used by multiple users or processes. The system ensures that information from one process or user is not inadvertently or deliberately made available to another unauthorized process or user through shared resources.",
    supplementalGuidance: "Organizations should implement controls to prevent information leakage through shared system resources such as memory scrubbing, disk sanitization between uses, and process isolation. The risk of information leakage through shared resources is particularly significant in multi-tenant environments such as cloud computing platforms. Organizations should evaluate shared resource protections when deploying systems in shared environments.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SC-5",
    family: "SC",
    title: "Denial-of-Service Protection",
    description: "The system protects against or limits the effects of denial-of-service attacks by employing defined controls. Denial-of-service attacks can target system resources such as bandwidth, connectivity, storage, and processing capacity. The system implements mechanisms to detect and mitigate denial-of-service attacks including rate limiting, traffic filtering, connection throttling, and traffic monitoring.",
    supplementalGuidance: "Organizations should implement multiple layers of denial-of-service protection including network-level protections, application-level protections, and cloud-based mitigation services. The selection of denial-of-service protection mechanisms should be based on the types of denial-of-service attacks most likely to target the system. Organizations should establish procedures for responding to denial-of-service attacks and restoring normal operations.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SC-6",
    family: "SC",
    title: "Resource Availability",
    description: "The system protects the availability of resources by allocating defined resources by priority, by quota, or by a combination of both. Resource availability controls prevent any single user, process, or component from monopolizing system resources to the detriment of other users and system functions. These controls ensure fair access to processing, memory, storage, and network resources.",
    supplementalGuidance: "Organizations should implement resource allocation mechanisms that ensure critical system functions receive the resources they need to operate effectively. Resource quotas and priorities should be established based on the criticality of the functions they support. Organizations should monitor resource utilization and adjust allocations as needed to maintain system performance and availability.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-7",
    family: "SC",
    title: "Boundary Protection",
    description: "The system monitors and controls communications at the external managed interfaces to the system and at key internal managed interfaces within the system. The system implements subnetworks for publicly accessible system components that are physically or logically separated from internal organizational networks. The system connects to external networks or systems only through managed interfaces consisting of boundary protection devices arranged in accordance with an organizational security and privacy architecture.",
    supplementalGuidance: "Boundary protection mechanisms include firewalls, gateways, routers, intrusion detection and prevention systems, and demilitarized zones. Organizations should implement boundary protection at multiple layers of the network architecture to provide defense in depth. Boundary protection devices should be configured to deny all traffic by default and only allow explicitly authorized communications.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SC-8",
    family: "SC",
    title: "Transmission Confidentiality and Integrity",
    description: "The system protects the confidentiality and integrity of transmitted information. The system implements cryptographic mechanisms to prevent unauthorized disclosure of information and detect changes to information during transmission. Protection of transmission confidentiality and integrity applies to both internal and external communications and covers all types of network traffic including data, voice, and video.",
    supplementalGuidance: "Organizations should implement encryption and integrity protections for all sensitive information during transmission. Common mechanisms include TLS, IPsec, and SSH protocols. Organizations should ensure that cryptographic implementations meet organizational standards and that cryptographic keys are managed in accordance with organizational key management policies.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SC-9",
    family: "SC",
    title: "Transmission Confidentiality",
    description: "Withdrawn. This control has been incorporated into SC-8. Organizations should refer to the transmission confidentiality and integrity control SC-8 for the transmission confidentiality requirements previously addressed by this control. Transmission confidentiality and integrity requirements are now addressed together.",
    supplementalGuidance: "This control was withdrawn to consolidate transmission protection requirements under SC-8. Organizations should ensure that their SC-8 implementation addresses both confidentiality and integrity protections for transmitted information. The consolidation provides a more comprehensive approach to protecting information during transmission.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-10",
    family: "SC",
    title: "Network Disconnect",
    description: "The system terminates the network connection associated with a communications session at the end of the session or after a defined period of inactivity. Network disconnect applies to internal and external networks. Terminating network connections when they are no longer needed reduces the risk of unauthorized access to the system through abandoned or hijacked sessions.",
    supplementalGuidance: "Organizations should define appropriate inactivity timeouts based on the sensitivity of the system and the type of network connection. Network disconnect mechanisms should be implemented at both the network and application levels. Organizations should ensure that network disconnect does not adversely affect authorized users who may experience brief periods of inactivity during normal operations.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "SC-11",
    family: "SC",
    title: "Trusted Path",
    description: "Withdrawn. This control has been incorporated into SC-3. Organizations should refer to the security function isolation control SC-3 for the trusted path requirements previously addressed by this control. Trusted path functionality is now addressed as part of the security function isolation framework.",
    supplementalGuidance: "This control was withdrawn to consolidate trusted path requirements. Organizations should ensure that their SC-3 implementation includes trusted path mechanisms where needed. Trusted paths provide a mechanism for users to communicate directly with security functions without interference from untrusted software or hardware.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-12",
    family: "SC",
    title: "Cryptographic Key Establishment and Management",
    description: "The organization establishes and manages cryptographic keys when cryptography is employed within the system in accordance with defined key management requirements. Key management includes the generation, distribution, storage, access, use, rotation, and destruction of cryptographic keys. The organization maintains availability of information in the event of the loss of cryptographic keys by users.",
    supplementalGuidance: "Organizations should develop and implement a comprehensive key management plan that addresses all phases of the cryptographic key lifecycle. Key management practices should comply with applicable standards such as NIST SP 800-57. Organizations should implement controls to protect the confidentiality and integrity of cryptographic keys and ensure that keys are changed at appropriate intervals.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SC-13",
    family: "SC",
    title: "Cryptographic Protection",
    description: "The system implements defined cryptographic uses and type of cryptography required for each use in accordance with applicable laws, executive orders, directives, policies, regulations, and standards. Cryptographic protection applies to the protection of information at rest, information in transit, and information during processing. The system employs FIPS-validated cryptographic modules for all cryptographic operations.",
    supplementalGuidance: "Organizations should use FIPS-validated or NSA-approved cryptographic modules for all cryptographic operations. The selection of cryptographic algorithms and key sizes should be consistent with current guidance from NIST and the organization's security policies. Organizations should maintain an inventory of cryptographic implementations and monitor for the deprecation of algorithms and protocols.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SC-14",
    family: "SC",
    title: "Public Access Protections",
    description: "Withdrawn. This control has been incorporated into AC-2, AC-3, AC-5, SC-7, and SI-3. Organizations should refer to the account management, access enforcement, separation of duties, boundary protection, and malicious code protection controls for the public access protection requirements previously addressed by this control.",
    supplementalGuidance: "This control was withdrawn to distribute public access protection requirements across more specific controls. Organizations should ensure that their implementations of AC-2, AC-3, AC-5, SC-7, and SI-3 collectively address the protection of publicly accessible system components. The distribution of requirements reflects the multi-layered nature of public access protection.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-15",
    family: "SC",
    title: "Collaborative Computing Devices and Applications",
    description: "The system prohibits remote activation of collaborative computing devices and applications with defined exceptions. The system provides an explicit indication of use to users physically present at the devices. Collaborative computing devices include remote meeting and video conferencing technologies, networked white boards, cameras, and microphones.",
    supplementalGuidance: "Organizations should disable remote activation of collaborative computing devices by default and only enable it when explicitly authorized. Indicators of device activation include visible LED lights, audible tones, or on-screen notifications. Organizations should educate users about the risks associated with collaborative computing devices and the importance of physical controls such as lens covers and microphone switches.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SC-16",
    family: "SC",
    title: "Transmission of Security and Privacy Attributes",
    description: "The system associates security and privacy attributes with information exchanged between systems and between system components. Security and privacy attributes include access control information, data classification labels, and privacy markings that accompany data during transmission. The association of attributes with transmitted information ensures that receiving systems can enforce appropriate access controls and protections.",
    supplementalGuidance: "Organizations should implement mechanisms to ensure that security and privacy attributes are bound to transmitted information and cannot be modified in transit without detection. Attribute transmission mechanisms should be interoperable with the receiving system's attribute processing capabilities. Organizations should verify that security and privacy attributes are correctly interpreted and enforced by receiving systems.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-17",
    family: "SC",
    title: "Public Key Infrastructure Certificates",
    description: "The organization issues public key certificates under an appropriate certificate policy or obtains public key certificates from an approved service provider. Public key infrastructure certificates are used for authentication, digital signatures, encryption, and other security functions. The organization manages the lifecycle of certificates including issuance, renewal, revocation, and archival.",
    supplementalGuidance: "Organizations should establish a certificate management process that addresses the full lifecycle of public key certificates. Certificate policies should define the practices and procedures for certificate issuance, management, and revocation. Organizations should implement automated certificate management tools to reduce the risk of expired or misconfigured certificates.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SC-18",
    family: "SC",
    title: "Mobile Code",
    description: "The organization defines acceptable and unacceptable mobile code and mobile code technologies, establishes usage restrictions and implementation guidance for acceptable mobile code and mobile code technologies, and authorizes, monitors, and controls the use of mobile code within the system. Mobile code includes JavaScript, ActiveX, Java applets, Flash, and other technologies that are downloaded and executed on local systems.",
    supplementalGuidance: "Organizations should implement controls to restrict the execution of mobile code to authorized technologies and from trusted sources. Web browsers and email clients should be configured to block or restrict untrusted mobile code. Organizations should consider the use of application sandboxing and content filtering to mitigate the risks associated with mobile code execution.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "SC-19",
    family: "SC",
    title: "Voice over Internet Protocol",
    description: "Withdrawn. This control, along with its enhancements, is no longer necessary because Voice over Internet Protocol technology is sufficiently mature. Organizations should apply security controls to VoIP implementations based on risk assessment results rather than as a separate requirement.",
    supplementalGuidance: "This control was withdrawn because VoIP technology has matured sufficiently that general security controls are adequate for addressing VoIP security risks. Organizations should ensure that VoIP implementations are covered by their general network security and communications protection controls. Risk assessments should determine whether additional VoIP-specific controls are needed.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-20",
    family: "SC",
    title: "Secure Name/Address Resolution Service (Authoritative Source)",
    description: "The system provides additional data origin authentication and integrity verification artifacts along with the authoritative name resolution data the system returns in response to external name and address resolution queries. The system provides the means to indicate the security status of child zones and to enable verification of a chain of trust among parent and child domains when operating as part of a distributed, hierarchical namespace. This control supports DNSSEC implementation.",
    supplementalGuidance: "Organizations should implement DNSSEC on authoritative DNS servers to provide authentication and integrity verification for DNS responses. DNSSEC protects against DNS spoofing and cache poisoning attacks that could redirect users to malicious sites. Organizations should ensure that DNSSEC keys are properly managed and that zone signing is maintained across key rollovers.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SC-21",
    family: "SC",
    title: "Secure Name/Address Resolution Service (Recursive or Caching Resolver)",
    description: "The system requests and performs data origin authentication and data integrity verification on the name and address resolution responses the system receives from authoritative sources. Recursive resolvers that support DNSSEC validation verify the authenticity and integrity of DNS responses before providing them to requesting clients. This control ensures that the system validates DNSSEC signatures when resolving domain names.",
    supplementalGuidance: "Organizations should configure recursive DNS resolvers to validate DNSSEC signatures on DNS responses. DNSSEC validation protects internal systems from accepting forged or tampered DNS responses. Organizations should monitor DNSSEC validation failures and investigate potential DNS-based attacks when validation failures are detected.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SC-22",
    family: "SC",
    title: "Architecture and Provisioning for Name/Address Resolution Service",
    description: "The system that collectively provides name and address resolution service for an organization is fault-tolerant and implements internal and external role separation. Name resolution service is implemented using multiple redundant DNS servers to ensure availability. Internal DNS servers are separated from external DNS servers to prevent the disclosure of internal network information to external entities.",
    supplementalGuidance: "Organizations should implement redundant DNS infrastructure to ensure the availability of name resolution services. Internal and external DNS should be separated to prevent the leakage of internal network information. Organizations should implement DNS rate limiting and other protections to mitigate the risk of DNS-based denial-of-service attacks.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SC-23",
    family: "SC",
    title: "Session Authenticity",
    description: "The system protects the authenticity of communications sessions. Session authenticity protections include mechanisms to detect and prevent session hijacking and man-in-the-middle attacks. The system employs cryptographic mechanisms such as digital certificates, challenge-response protocols, and session tokens to verify that communication sessions are established with authenticated endpoints.",
    supplementalGuidance: "Organizations should implement session management mechanisms that protect against session fixation, session hijacking, and replay attacks. Session tokens should be generated using cryptographically secure random number generators and should have appropriate expiration periods. Organizations should implement secure cookie attributes and transport-layer encryption to protect session information.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SC-24",
    family: "SC",
    title: "Fail in Known State",
    description: "The system fails to a defined known state for defined types of failures, preserving system state information in failure. Failing in a known state addresses the security concern that a failure in the system does not result in an insecure state. The system implements mechanisms to ensure that when a failure occurs, the system transitions to a state that maintains the confidentiality, integrity, and availability of organizational information.",
    supplementalGuidance: "Organizations should define the known states that the system should transition to upon various types of failures. Fail-safe mechanisms should be implemented for critical security functions to ensure that failures do not result in unauthorized access or information disclosure. Organizations should test fail-safe mechanisms periodically to verify they operate correctly under various failure conditions.",
    priority: "P1",
    baseline: "High"
  },
  {
    id: "SC-25",
    family: "SC",
    title: "Thin Nodes",
    description: "The organization employs thin nodes or minimal-functionality devices to limit the processing and storage of information on client devices. Thin nodes reduce the attack surface by limiting the software and data stored on endpoints. Processing is performed on centralized servers, and client devices primarily function as display and input terminals.",
    supplementalGuidance: "Thin node architectures reduce the risk of data loss or theft from endpoint devices by centralizing information processing and storage. Organizations should implement thin node solutions for environments where the risk of device compromise is high or where the protection of endpoint data is particularly challenging. Virtual desktop infrastructure is a common implementation of the thin node concept.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-26",
    family: "SC",
    title: "Decoys",
    description: "The organization employs decoy systems or components to mislead and confuse adversaries, detect unauthorized activity, and gather information about adversary tactics, techniques, and procedures. Decoys include honeypots, honeynets, and deception technologies that simulate real systems to attract adversaries. The information gathered from decoy interactions is used to improve the organization's security posture and threat intelligence.",
    supplementalGuidance: "Organizations should deploy decoy systems that are realistic enough to engage adversaries while being isolated from production systems. Decoy systems should be monitored continuously to capture adversary activities and techniques. Organizations should use information gathered from decoys to update their threat models and improve their detection and response capabilities.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-27",
    family: "SC",
    title: "Platform-Independent Applications",
    description: "The organization employs defined platform-independent applications to ensure that applications can operate across a variety of system platforms. Platform-independent applications are not dependent on specific operating systems or hardware configurations, reducing the risk of vendor lock-in and facilitating migration to alternative platforms. This capability supports continuity of operations and flexibility in system architecture.",
    supplementalGuidance: "Organizations should consider platform independence when selecting or developing applications for critical functions. Platform-independent applications facilitate disaster recovery by allowing operations to be resumed on alternative platforms. Organizations should test platform-independent applications across multiple platforms to verify compatibility and consistent security behavior.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-28",
    family: "SC",
    title: "Protection of Information at Rest",
    description: "The system protects the confidentiality and integrity of information at rest. Information at rest includes information stored on system hard drives, removable media, backup tapes, and in databases. Protection mechanisms include encryption, access controls, and physical security measures to prevent unauthorized access to stored information.",
    supplementalGuidance: "Organizations should implement encryption for sensitive information stored on all system components including mobile devices, removable media, and backup storage. The strength of the encryption should be commensurate with the sensitivity of the information and the risk level of the storage environment. Organizations should implement key management procedures to ensure that encrypted information can be recovered when needed.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SC-29",
    family: "SC",
    title: "Heterogeneity",
    description: "The organization employs a diverse set of information technologies for defined system components in the implementation of the system. Heterogeneity reduces the probability that a single vulnerability or exploit can compromise all system components simultaneously. By employing diverse technologies, organizations ensure that adversaries must develop multiple exploits to compromise the entire system.",
    supplementalGuidance: "Organizations should consider using diverse operating systems, hardware platforms, network devices, and security tools to reduce the impact of single-point-of-failure vulnerabilities. Heterogeneity should be balanced against the increased complexity and management overhead it introduces. Organizations should ensure that their personnel have the skills needed to manage and maintain diverse technology environments.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-30",
    family: "SC",
    title: "Concealment and Misdirection",
    description: "The organization employs concealment and misdirection techniques for defined systems at defined time periods to confuse and mislead adversaries. Concealment techniques include the use of network address translation, port randomization, and traffic camouflage. Misdirection techniques include the use of decoy systems, fake data, and misleading network configurations to divert adversary attention away from critical assets.",
    supplementalGuidance: "Organizations should implement concealment and misdirection techniques as part of a comprehensive defensive strategy. These techniques are most effective when used in combination with other security controls and should be updated periodically to maintain their effectiveness against adaptive adversaries. Organizations should ensure that concealment and misdirection techniques do not interfere with legitimate system operations.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-31",
    family: "SC",
    title: "Covert Channel Analysis",
    description: "The organization performs a covert channel analysis to identify those aspects of communications within the system that are potential avenues for covert storage and timing channels. Covert channels are communication paths that can be exploited to transfer information in a manner that violates the security policy. The analysis identifies the maximum bandwidth of each identified covert channel and determines the potential impact of the covert channel.",
    supplementalGuidance: "Organizations should conduct covert channel analyses for systems that process information at multiple security levels or that enforce mandatory access control policies. The analysis should identify both storage channels and timing channels and should assess the risk posed by each identified channel. Organizations should implement controls to limit the bandwidth of identified covert channels to acceptable levels.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-32",
    family: "SC",
    title: "System Partitioning",
    description: "The organization partitions the system into defined system components residing in separate physical or logical domains or environments based on defined circumstances for physical or logical separation of components. System partitioning reduces the attack surface by isolating components and limiting the impact of a compromise in one partition to other partitions. Partitioning can be achieved through physical separation, virtualization, or network segmentation.",
    supplementalGuidance: "Organizations should partition systems based on the sensitivity and criticality of the functions and information processed by each component. Partitioning boundaries should be enforced through strong access controls and monitoring. Organizations should implement security controls at partition boundaries to detect and prevent unauthorized communication between partitions.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-33",
    family: "SC",
    title: "Transmission Preparation Integrity",
    description: "Withdrawn. This control has been incorporated into SC-8. Organizations should refer to the transmission confidentiality and integrity control SC-8 for the transmission preparation integrity requirements previously addressed by this control.",
    supplementalGuidance: "This control was withdrawn to consolidate transmission integrity requirements under SC-8. Organizations should ensure that their SC-8 implementation addresses integrity protections during the preparation of information for transmission. The consolidation provides a unified approach to protecting information during transmission.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-34",
    family: "SC",
    title: "Non-Modifiable Executable Programs",
    description: "The system at defined system components loads and executes the operating environment from hardware-enforced, read-only media and loads and executes defined applications from hardware-enforced, read-only media. Non-modifiable executable programs ensure that the system operating environment and critical applications cannot be tampered with during execution. This control protects against persistent malware and unauthorized modifications to system software.",
    supplementalGuidance: "Organizations should identify critical system components that would benefit from non-modifiable executable program protections. Read-only media implementations include write-protected USB drives, CD/DVDs, and firmware-based solutions. Organizations should implement complementary controls for components that cannot use non-modifiable executable programs.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-35",
    family: "SC",
    title: "External Malicious Code Identification",
    description: "The system includes components specifically designed to proactively seek and identify malicious code originating from external sources. This control addresses the identification of malicious code that enters the system through external communications channels including email, web browsing, and file transfers. The identification capability operates at the network boundary and at key internal network points.",
    supplementalGuidance: "Organizations should deploy multiple layers of malicious code identification at network boundaries and within the internal network. Identification mechanisms should include signature-based detection, behavioral analysis, and sandboxing technologies. Organizations should ensure that malicious code identification capabilities are updated regularly with current threat signatures and indicators of compromise.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-36",
    family: "SC",
    title: "Distributed Processing and Storage",
    description: "The organization distributes processing and storage across multiple physical locations. Distributed processing and storage reduces the risk that a single physical security event could affect all organizational information and processing capabilities. Distribution can be achieved through the use of multiple data centers, cloud regions, or geographically dispersed facilities.",
    supplementalGuidance: "Organizations should determine the appropriate level of distribution based on the criticality of the information and the potential impact of a localized disruption. Distributed processing and storage should be implemented in a manner that maintains data consistency and synchronization across locations. Organizations should consider the security implications of distributing information across multiple locations including the need for consistent security controls at all sites.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-37",
    family: "SC",
    title: "Out-of-Band Channels",
    description: "The organization employs defined out-of-band channels for the physical delivery or electronic transmission of defined information, system components, or devices to defined individuals or systems. Out-of-band channels provide an alternative communication path that is separate from the primary communication channels. Using out-of-band channels for sensitive communications reduces the risk of interception on the primary network.",
    supplementalGuidance: "Organizations should identify situations where out-of-band channels are appropriate for the communication of sensitive information such as cryptographic keys, authentication credentials, and critical system updates. Out-of-band channels should be protected with security controls commensurate with the sensitivity of the information being transmitted. Organizations should verify the identity of recipients before transmitting information through out-of-band channels.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-38",
    family: "SC",
    title: "Operations Security",
    description: "The organization employs operations security safeguards to protect key organizational information throughout the system development life cycle. Operations security involves the identification of critical information, the analysis of threats and vulnerabilities, the assessment of risks, and the application of appropriate countermeasures. Operations security protects against the inadvertent disclosure of information that could be exploited by adversaries.",
    supplementalGuidance: "Operations security safeguards include protecting information about system architectures, security configurations, and operational procedures from unauthorized disclosure. Organizations should train personnel on operations security practices and the importance of protecting sensitive information about system configurations and security measures. Operations security should be integrated into the organization's overall security program.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-39",
    family: "SC",
    title: "Process Isolation",
    description: "The system maintains a separate execution domain for each executing system process. Process isolation is achieved through hardware and software mechanisms that enforce separation between executing processes. Process isolation prevents one process from accessing or modifying the memory space, resources, or state of another process without explicit authorization.",
    supplementalGuidance: "Process isolation is a fundamental operating system security mechanism that protects against buffer overflow attacks, code injection, and other process-level exploits. Modern operating systems implement process isolation through virtual memory management, address space layout randomization, and hardware-based memory protection. Organizations should verify that process isolation mechanisms are enabled and properly configured on all system components.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SC-40",
    family: "SC",
    title: "Wireless Link Protection",
    description: "The system protects external and internal wireless links from defined types of signal parameter attacks including jamming, spoofing, and interception. Wireless link protection mechanisms include spread spectrum technologies, directional transmissions, and frequency hopping. These protections ensure the availability, confidentiality, and integrity of wireless communications.",
    supplementalGuidance: "Organizations should select wireless link protection mechanisms based on the sensitivity of the information transmitted and the threat environment. Protection against signal parameter attacks may require specialized wireless equipment and configurations. Organizations should monitor wireless links for indications of signal parameter attacks and implement detection and response procedures.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-41",
    family: "SC",
    title: "Port and I/O Device Access",
    description: "The system disables or removes defined connection ports or input/output devices on defined systems or system components. Disabling or removing unnecessary ports and devices reduces the attack surface by eliminating pathways that could be used to introduce malicious code or exfiltrate information. This applies to USB ports, serial ports, FireWire ports, and other physical connection interfaces.",
    supplementalGuidance: "Organizations should identify and disable all ports and I/O devices that are not needed for the system's operational functions. Port disabling can be accomplished through physical means such as port blockers or through software configuration. Organizations should implement compensating controls for ports that cannot be disabled due to operational requirements.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SC-42",
    family: "SC",
    title: "Sensor Capability and Data",
    description: "The system prohibits the use of devices possessing defined environmental sensing capabilities in defined facilities, areas, or systems. The organization authorizes the use of sensor-equipped devices and defines restrictions on the collection, use, and retention of sensor data. Sensor capabilities include cameras, microphones, GPS receivers, and other data collection technologies embedded in computing devices.",
    supplementalGuidance: "Organizations should establish policies governing the use of sensor-equipped devices in sensitive areas and implement technical controls to enforce those policies. Sensor data collection should be limited to authorized purposes and sensor data should be protected with appropriate security controls. Organizations should provide notice to individuals when sensor data is being collected in their vicinity.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-43",
    family: "SC",
    title: "Usage Restrictions",
    description: "The organization establishes usage restrictions and implementation guidance for defined system components based on the potential to cause damage to the system if used maliciously. The organization authorizes, monitors, and controls the use of such components within the system. Usage restrictions address system components that have the potential to affect system security if improperly used.",
    supplementalGuidance: "Organizations should identify system components that could cause significant damage if misused and implement appropriate restrictions on their use. Restrictions may include limiting access to authorized personnel, requiring approval for use, and monitoring usage patterns. Organizations should provide training to personnel on the proper use of restricted components and the consequences of misuse.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-44",
    family: "SC",
    title: "Detonation Chambers",
    description: "The organization employs a detonation chamber capability within defined systems and system components. Detonation chambers, also known as sandboxes, provide a protected environment where suspicious code can be executed and observed without risk to the production system. The capability enables the analysis of potentially malicious files, emails, and URLs in a controlled environment.",
    supplementalGuidance: "Organizations should deploy detonation chamber capabilities at key network ingress points such as email gateways and web proxies. Detonation chambers should simulate realistic system environments to maximize the likelihood of triggering malicious behavior. Organizations should integrate detonation chamber findings with their threat intelligence and incident response processes.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-45",
    family: "SC",
    title: "System Time Synchronization",
    description: "The system synchronizes system clocks within and between systems and system components. Time synchronization ensures that system clocks across the organization maintain accurate and consistent time, which is essential for event correlation, audit record analysis, and forensic investigations. The system uses authenticated time sources to prevent adversaries from manipulating system time.",
    supplementalGuidance: "Organizations should implement hierarchical time synchronization using authenticated Network Time Protocol or similar protocols. Time sources should be protected from unauthorized modification to prevent adversaries from altering system time to undermine security controls. Organizations should monitor time synchronization status and alert on significant time deviations.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-46",
    family: "SC",
    title: "Cross Domain Policy Enforcement",
    description: "The system implements a policy enforcement mechanism between defined domains that employs defined safeguards to control the flow of information. Cross-domain policy enforcement ensures that information flows between security domains comply with the organization's security policy. The enforcement mechanism validates that all information crossing domain boundaries meets the access and transfer requirements of both domains.",
    supplementalGuidance: "Organizations should deploy validated cross-domain solutions at all boundaries between security domains. Cross-domain solutions should undergo rigorous testing and validation to ensure they correctly enforce information flow policies. Organizations should implement content inspection and filtering as part of the cross-domain enforcement mechanism to prevent unauthorized information transfers.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-47",
    family: "SC",
    title: "Alternate Communications Paths",
    description: "The system establishes alternate communications paths for system operations organizational command and control. Alternate communications paths provide resilience in the event that primary communication channels are disrupted, degraded, or compromised. These paths ensure that critical command and control communications can continue during adverse conditions.",
    supplementalGuidance: "Organizations should establish and test alternate communications paths for critical operational communications. Alternate paths should use different technologies and routes than primary paths to ensure independence. Organizations should regularly test alternate paths to verify their availability and capacity to support required communications during contingency operations.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-48",
    family: "SC",
    title: "Sensor Relocation",
    description: "The organization relocates defined sensors and monitoring capabilities at a defined frequency or when defined events or conditions occur. Sensor relocation complicates adversary efforts to identify and evade detection mechanisms. By periodically changing the location and configuration of sensors, organizations increase the unpredictability of their monitoring capabilities.",
    supplementalGuidance: "Organizations should establish procedures for relocating sensors and monitoring capabilities based on threat intelligence and operational requirements. Sensor relocation should be coordinated with the overall monitoring strategy to ensure continued coverage of critical assets. Organizations should document sensor relocation activities for audit purposes and to support the analysis of monitoring data.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-49",
    family: "SC",
    title: "Hardware-Enforced Separation and Policy Enforcement",
    description: "The system implements hardware-enforced separation and policy enforcement mechanisms to isolate defined security functions and security-relevant information from other system functions. Hardware-enforced separation provides stronger isolation guarantees than software-based mechanisms and is more resistant to software-based attacks. This includes the use of hardware security modules, trusted platform modules, and hardware-based access control mechanisms.",
    supplementalGuidance: "Organizations should implement hardware-enforced separation for critical security functions such as cryptographic operations, key management, and access control enforcement. Hardware-based mechanisms provide a higher level of assurance than software-only implementations. Organizations should ensure that hardware separation mechanisms are properly configured and maintained throughout their operational life.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-50",
    family: "SC",
    title: "Software-Enforced Separation and Policy Enforcement",
    description: "The system implements software-enforced separation and policy enforcement mechanisms to isolate defined security functions and security-relevant information from other system functions and information. Software-enforced separation includes the use of virtualization, containerization, and operating system-level access controls. These mechanisms provide logical isolation between system components and security domains.",
    supplementalGuidance: "Organizations should implement software-enforced separation mechanisms as part of a defense-in-depth strategy, recognizing that software-based mechanisms may be less resistant to compromise than hardware-based alternatives. Virtualization and containerization technologies should be properly configured to enforce separation between workloads. Organizations should regularly update and patch software separation mechanisms to address known vulnerabilities.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SC-51",
    family: "SC",
    title: "Hardware-Based Protection",
    description: "The organization employs hardware-based protection mechanisms in addition to software-based mechanisms to provide additional security for critical system components and functions. Hardware-based protections include hardware security modules, trusted execution environments, secure enclaves, and hardware-based root of trust. These mechanisms provide tamper-resistant protection for cryptographic keys, sensitive data, and critical security functions.",
    supplementalGuidance: "Organizations should deploy hardware-based protection mechanisms for the most critical security functions and sensitive data. Hardware-based protections are more resistant to software-based attacks and can provide a root of trust for other security mechanisms. Organizations should evaluate the cost and operational impact of hardware-based protections against the security benefits they provide.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // SI - System and Information Integrity (SI-1 through SI-23)
  // ---------------------------------------------------------------------------
  {
    id: "SI-1",
    family: "SI",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a system and information integrity policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the system and information integrity policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "System and information integrity policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The policy should address the detection and remediation of information system flaws, the detection of malicious code, and the monitoring of system security. Organizations should ensure that integrity policies cover all system components and information types.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SI-2",
    family: "SI",
    title: "Flaw Remediation",
    description: "The organization identifies, reports, and corrects system flaws. The organization tests software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation. The organization installs security-relevant software and firmware updates within a defined time period of the release of the updates. Flaw remediation addresses the correction of detected vulnerabilities in system software and firmware.",
    supplementalGuidance: "Organizations should establish a patch management process that addresses the identification, evaluation, testing, and deployment of patches for all system components. The time frame for installing patches should be based on the severity of the vulnerability and the risk to the organization. Organizations should maintain an inventory of system components and their patch status to ensure comprehensive patch coverage.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SI-3",
    family: "SI",
    title: "Malicious Code Protection",
    description: "The organization employs malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code. The organization updates malicious code protection mechanisms whenever new releases are available in accordance with organizational configuration management policy and procedures. The organization implements malicious code protection that includes both signature-based and behavior-based detection capabilities.",
    supplementalGuidance: "Organizations should deploy malicious code protection on all system components including servers, workstations, mobile devices, and network boundaries. Protection mechanisms should be configured to perform real-time scanning and periodic full system scans. Organizations should implement centralized management of malicious code protection to ensure consistent configuration and timely signature updates across all system components.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SI-4",
    family: "SI",
    title: "System Monitoring",
    description: "The organization monitors the system to detect attacks and indicators of potential attacks in accordance with the monitoring objectives, unauthorized local, network, and remote connections, and identifies unauthorized use of the system. The organization deploys monitoring devices strategically within the system to collect organization-determined essential information, and at ad hoc locations within the system to track specific types of transactions of interest.",
    supplementalGuidance: "Organizations should implement comprehensive monitoring capabilities that cover network traffic, system events, and user activities. Monitoring should include both automated and manual analysis to identify anomalous behavior and potential security incidents. Organizations should integrate system monitoring with their incident response capability to enable rapid detection and response to security events.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SI-5",
    family: "SI",
    title: "Security Alerts, Advisories, and Directives",
    description: "The organization receives system security alerts, advisories, and directives from defined external organizations on an ongoing basis. The organization generates internal security alerts, advisories, and directives as deemed necessary and disseminates them to defined personnel. The organization implements security directives in accordance with established time frames or notifies the issuing organization of the degree of noncompliance.",
    supplementalGuidance: "Organizations should establish processes for monitoring multiple sources of security alerts and advisories including US-CERT, vendor notifications, and industry-specific information sharing organizations. Alerts should be analyzed for relevance to the organization's systems and prioritized for action. Organizations should track the implementation of security directives and maintain records of compliance actions taken.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SI-6",
    family: "SI",
    title: "Security and Privacy Function Verification",
    description: "The system verifies the correct operation of defined security and privacy functions. The system performs this verification at defined states or upon command by a user with appropriate privilege. The system either shuts the system down, restarts the system, or notifies defined personnel of failed security verification tests. Verification ensures that security mechanisms are functioning as intended.",
    supplementalGuidance: "Organizations should implement automated mechanisms to verify the correct operation of critical security functions such as access control enforcement, audit logging, and encryption. Verification should be performed at system startup, on a scheduled basis, and when changes are made to security-relevant components. Organizations should define the appropriate response to verification failures based on the criticality of the affected function.",
    priority: "P1",
    baseline: "High"
  },
  {
    id: "SI-7",
    family: "SI",
    title: "Software, Firmware, and Information Integrity",
    description: "The organization employs integrity verification tools to detect unauthorized changes to defined software, firmware, and information. The system implements automated tools that provide notification to defined personnel upon discovering discrepancies during integrity verification. Integrity verification detects unauthorized modifications to system components and information that could indicate tampering or compromise.",
    supplementalGuidance: "Organizations should implement file integrity monitoring on critical system files, configuration files, and software components. Integrity baselines should be established and maintained for comparison during integrity checks. Organizations should investigate all integrity violations promptly and take corrective action to restore the integrity of affected components.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SI-8",
    family: "SI",
    title: "Spam Protection",
    description: "The organization employs spam protection mechanisms at system entry and exit points to detect and act on unsolicited messages. The organization updates spam protection mechanisms when new releases are available in accordance with organizational configuration management policy and procedures. Spam protection addresses the detection and filtering of unsolicited bulk electronic messages including phishing emails and other social engineering attacks.",
    supplementalGuidance: "Organizations should implement spam protection at the email gateway, at the mail server, and at the client level to provide defense in depth. Spam protection mechanisms should include both content-based filtering and reputation-based filtering. Organizations should regularly update spam filter rules and configurations to address evolving spam techniques and to minimize false positive detections.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "SI-9",
    family: "SI",
    title: "Information Input Restrictions",
    description: "Withdrawn. This control has been incorporated into AC-2, AC-3, AC-5, and AC-6. Organizations should refer to the account management, access enforcement, separation of duties, and least privilege controls for the information input restriction requirements previously addressed by this control.",
    supplementalGuidance: "This control was withdrawn to consolidate information input restriction requirements under access control controls. Organizations should ensure that their access control implementations address restrictions on who can input information to the system and the conditions under which input is permitted. The consolidation reduces redundancy while maintaining the security intent.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SI-10",
    family: "SI",
    title: "Information Input Validation",
    description: "The system checks the validity of defined information inputs. Information input validation checks ensure that information provided to the system by users or other systems is within the expected range, format, and type before being processed. Input validation prevents the processing of malformed or malicious data that could compromise system integrity or availability.",
    supplementalGuidance: "Organizations should implement input validation at both the client and server sides of the application. Validation should include checking for proper data types, acceptable value ranges, allowed characters, and expected data formats. Organizations should implement whitelisting approaches for input validation wherever possible, rejecting all input that does not match the expected format.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SI-11",
    family: "SI",
    title: "Error Handling",
    description: "The system generates error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries. The system reveals error conditions only to defined personnel or roles. Error handling ensures that error messages do not disclose sensitive implementation details such as stack traces, database queries, or internal system paths that could aid an attacker.",
    supplementalGuidance: "Organizations should implement consistent error handling across all system components to prevent the disclosure of sensitive information through error messages. User-facing error messages should be generic and not reveal implementation details. Detailed error information should be logged for system administrators and developers but should not be displayed to end users.",
    priority: "P2",
    baseline: "Moderate"
  },
  {
    id: "SI-12",
    family: "SI",
    title: "Information Management and Retention",
    description: "The organization manages and retains information within the system and information output from the system in accordance with applicable laws, executive orders, directives, regulations, policies, standards, guidelines, and operational requirements. The organization ensures that information is retained for the required period and is disposed of properly when no longer needed. Information management addresses the full lifecycle of information from creation through disposal.",
    supplementalGuidance: "Organizations should establish information retention schedules that comply with applicable legal and regulatory requirements. Information should be protected throughout its lifecycle with controls appropriate to its sensitivity. Organizations should implement secure disposal methods for information that has reached the end of its retention period.",
    priority: "P2",
    baseline: "Low"
  },
  {
    id: "SI-13",
    family: "SI",
    title: "Predictable Failure Prevention",
    description: "The organization determines mean time to failure for defined system components in specific environments of operation and provides substitute system components and a means to exchange active and standby components. Predictable failure prevention addresses the replacement of system components before they reach their predicted failure point. This proactive approach minimizes unplanned downtime and maintains system availability.",
    supplementalGuidance: "Organizations should track the operational history and condition of system components to predict failures before they occur. Predictive maintenance should be integrated with the organization's maintenance program and spare parts management. Organizations should consider implementing redundant components for critical systems to enable seamless switchover when component failures are predicted.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SI-14",
    family: "SI",
    title: "Non-Persistence",
    description: "The organization implements non-persistent system components and services that are initiated in a known state and terminated on a regular basis or upon specific events. Non-persistent components are refreshed from a trusted, verified source at defined intervals, eliminating any modifications that may have been made by an adversary. This approach limits the persistence of advanced threats and reduces the window of vulnerability exploitation.",
    supplementalGuidance: "Non-persistence can be implemented through virtual machine reversion, container recycling, or the periodic reimaging of system components. Organizations should determine the appropriate refresh frequency based on the risk level and the criticality of the system. Non-persistence is particularly effective for protecting internet-facing systems and systems that are at high risk of compromise.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SI-15",
    family: "SI",
    title: "Information Output Filtering",
    description: "The system validates information output from defined software programs and applications to ensure that the information is consistent with the expected content. Information output filtering detects and prevents the disclosure of unauthorized information, data manipulation, and output that does not conform to expected formats. Output validation is applied before information is transmitted or made available to users.",
    supplementalGuidance: "Organizations should implement output filtering and encoding to prevent cross-site scripting, injection attacks, and unauthorized information disclosure. Output validation should verify that the data returned to users matches the expected format and does not contain unauthorized content. Organizations should implement output encoding appropriate for the context in which the data is rendered.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SI-16",
    family: "SI",
    title: "Memory Protection",
    description: "The system implements defined controls to protect its memory from unauthorized code execution. Memory protection mechanisms include data execution prevention, address space layout randomization, stack protection, and hardware-enforced memory protections. These controls prevent common exploitation techniques such as buffer overflow attacks, code injection, and return-oriented programming.",
    supplementalGuidance: "Organizations should enable memory protection mechanisms on all system components that support them. Memory protection should be implemented at both the operating system and application levels. Organizations should verify that memory protection mechanisms are active and properly configured through security assessments and configuration audits.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SI-17",
    family: "SI",
    title: "Fail-Safe Procedures",
    description: "The system implements defined fail-safe procedures when defined failure conditions occur. Fail-safe procedures ensure that systems transition to a secure state when anomalies or failure conditions are detected. The procedures address various types of failures including hardware failures, software failures, and environmental failures that could affect the security posture of the system.",
    supplementalGuidance: "Organizations should identify the failure conditions that could affect the security of the system and define the appropriate response for each condition. Fail-safe procedures should be tested periodically to verify they operate correctly under various failure scenarios. Organizations should ensure that fail-safe procedures do not result in a denial of service for critical functions unless necessary to maintain security.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SI-18",
    family: "SI",
    title: "Personally Identifiable Information Quality Operations",
    description: "The organization implements processes to check for the accuracy, relevance, timeliness, and completeness of personally identifiable information across the information lifecycle. The organization corrects or deletes inaccurate or outdated personally identifiable information. Data quality operations ensure that personally identifiable information is maintained at a level of quality that supports the intended purpose of the data processing.",
    supplementalGuidance: "Organizations should establish data quality standards and implement automated tools to assist in identifying and correcting data quality issues. Quality checks should be performed at the point of collection and periodically throughout the data lifecycle. Organizations should provide mechanisms for individuals to report and request correction of inaccurate personal information.",
    priority: "P0",
    baseline: "Low"
  },
  {
    id: "SI-19",
    family: "SI",
    title: "De-identification",
    description: "The organization removes personally identifiable information from datasets prior to releasing the data for secondary use including research, analysis, and public disclosure. De-identification techniques include statistical methods, suppression, generalization, and pseudonymization to prevent the re-identification of individuals from the released data. The organization assesses the re-identification risk of de-identified datasets before release.",
    supplementalGuidance: "Organizations should evaluate de-identification techniques based on the specific characteristics of the data and the intended use of the de-identified dataset. De-identification is not a one-size-fits-all approach, and organizations should consider the risk of re-identification through data linkage with other available datasets. Organizations should document the de-identification methods used and the resulting re-identification risk assessment.",
    priority: "P0",
    baseline: "Low"
  },
  {
    id: "SI-20",
    family: "SI",
    title: "Tainting",
    description: "The organization embeds data or capabilities in defined systems or system components that are used to determine if organizational data has been exfiltrated or improperly removed from the organization. Tainting involves marking information with traceable indicators that can be detected if the information appears outside the authorized boundaries. This capability supports the detection of insider threats and data exfiltration activities.",
    supplementalGuidance: "Organizations should implement tainting mechanisms for high-value information that is at risk of exfiltration. Tainting can be accomplished through digital watermarks, steganographic markers, or unique data patterns embedded in documents and files. Organizations should establish monitoring capabilities to detect tainted information that appears outside the authorized boundaries.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SI-21",
    family: "SI",
    title: "Information Refresh",
    description: "The organization refreshes information at defined frequencies to ensure that the information used for critical decisions is current, accurate, and complete. Information refresh addresses the currency of information used in system processing, decision-making, and reporting. Stale or outdated information can lead to incorrect decisions and security vulnerabilities.",
    supplementalGuidance: "Organizations should identify information types that require regular refreshing and establish appropriate refresh frequencies based on the volatility of the information and the criticality of the decisions it supports. Automated mechanisms should be used to refresh frequently changing information. Organizations should verify the integrity and accuracy of refreshed information before it is used in security-critical processes.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SI-22",
    family: "SI",
    title: "Information Diversity",
    description: "The organization identifies alternative information sources for defined essential information and uses those alternative sources when the primary source is compromised, corrupted, or unavailable. Information diversity ensures that organizations are not dependent on a single source for critical information and can validate the accuracy of information through comparison across multiple sources.",
    supplementalGuidance: "Organizations should identify essential information that supports critical decisions and operational activities and establish alternative sources for that information. Alternative sources should be independent of the primary source to reduce the risk of correlated failures or compromises. Organizations should establish procedures for switching to alternative sources and for validating information across multiple sources.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SI-23",
    family: "SI",
    title: "Information Fragmentation",
    description: "The organization fragments information based on defined circumstances into defined information elements. Information fragmentation distributes information across multiple storage locations or systems such that no single location contains the complete information. This technique protects the confidentiality of information by ensuring that the compromise of a single storage location does not result in the disclosure of the complete information.",
    supplementalGuidance: "Organizations should identify high-value information that would benefit from fragmentation and determine the appropriate level of fragmentation based on the sensitivity of the information and the risk of compromise. Fragmentation should be implemented in a manner that allows authorized users to reconstruct the complete information when needed. Organizations should protect the fragmentation scheme itself from unauthorized disclosure.",
    priority: "P0",
    baseline: "High"
  },

  // ---------------------------------------------------------------------------
  // SR - Supply Chain Risk Management (SR-1 through SR-12)
  // ---------------------------------------------------------------------------
  {
    id: "SR-1",
    family: "SR",
    title: "Policy and Procedures",
    description: "The organization develops, documents, and disseminates a supply chain risk management policy that addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance. The organization also develops procedures to facilitate the implementation of the supply chain risk management policy and associated controls. These documents are reviewed and updated at an organization-defined frequency.",
    supplementalGuidance: "Supply chain risk management policy and procedures are consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines. The policy should establish the organization's approach to identifying, assessing, and mitigating supply chain risks throughout the system development lifecycle. Organizations should integrate supply chain risk management with their overall risk management program.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SR-2",
    family: "SR",
    title: "Supply Chain Risk Management Plan",
    description: "The organization develops a plan for managing supply chain risks associated with the research and development, design, manufacturing, acquisition, delivery, integration, operations, maintenance, and disposal of systems, system components, or system services. The plan addresses the identification of personnel with supply chain risk management roles and responsibilities and their training requirements. The plan is reviewed and updated at a defined frequency.",
    supplementalGuidance: "The supply chain risk management plan should be integrated with the organization's overall risk management strategy and should address risks specific to the organization's supply chain. The plan should identify critical supply chain dependencies and single points of failure. Organizations should consider the geographic, economic, and political factors that may affect their supply chain.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SR-3",
    family: "SR",
    title: "Supply Chain Controls and Processes",
    description: "The organization establishes and applies a process for identifying and addressing weaknesses or deficiencies in the supply chain elements and processes in coordination with defined supply chain personnel. The organization employs security and privacy controls to protect against supply chain risks to the system, system component, or system service and to limit the harm from supply chain compromises.",
    supplementalGuidance: "Organizations should implement a systematic approach to identifying and mitigating supply chain risks throughout the acquisition and deployment process. Controls should address the integrity and authenticity of system components, the security practices of suppliers, and the protection of components during transit. Organizations should establish requirements for suppliers regarding the security of their own supply chains.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SR-4",
    family: "SR",
    title: "Provenance",
    description: "The organization documents, monitors, and maintains valid provenance of defined systems, system components, and associated data. Provenance tracking establishes the origin, custody, and chain of possession of system components from their source through delivery and installation. Maintaining provenance information enables organizations to verify that system components are authentic and have not been tampered with.",
    supplementalGuidance: "Organizations should implement provenance tracking for critical system components that are at risk of counterfeiting or tampering. Provenance information should include the manufacturer, supplier chain, and handling history of each component. Organizations should verify provenance information at key points in the supply chain and upon receipt of system components.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SR-5",
    family: "SR",
    title: "Acquisition Strategies, Tools, and Methods",
    description: "The organization employs defined acquisition strategies, contract tools, and procurement methods to protect against, identify, and mitigate supply chain risks. Acquisition strategies include the use of diverse suppliers, the establishment of security requirements in contracts, and the verification of supplier compliance with security requirements. These strategies address both the selection of suppliers and the ongoing management of the supply chain relationship.",
    supplementalGuidance: "Organizations should integrate supply chain risk considerations into their acquisition planning and source selection processes. Contract tools should include clauses that require suppliers to comply with organizational security requirements and to report supply chain incidents. Organizations should evaluate the supply chain risk posture of potential suppliers as part of the source selection evaluation.",
    priority: "P1",
    baseline: "Low"
  },
  {
    id: "SR-6",
    family: "SR",
    title: "Supplier Assessments and Reviews",
    description: "The organization assesses and reviews the supply chain-related risks associated with suppliers or contractors and the system, system component, or system service they provide at a defined frequency. The assessment includes an evaluation of the supplier's security practices, incident response capabilities, and the security of their own supply chain. Assessment results inform acquisition decisions and ongoing supplier management.",
    supplementalGuidance: "Organizations should establish a supplier assessment program that evaluates the security practices of suppliers based on the criticality of the products or services they provide. Assessments may include questionnaires, audits, site visits, and reviews of third-party certifications. Organizations should maintain records of supplier assessments and use the results to identify and mitigate supply chain risks.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SR-7",
    family: "SR",
    title: "Supply Chain Operations Security",
    description: "The organization employs operations security controls and safeguards to protect supply chain-related information. Operations security for supply chain activities includes the protection of information about system configurations, security requirements, acquisition strategies, and supplier relationships. Protecting this information prevents adversaries from targeting specific supply chain elements or exploiting supply chain knowledge.",
    supplementalGuidance: "Organizations should identify supply chain information that is sensitive and could be exploited by adversaries if disclosed. Protection measures include limiting access to acquisition information, using secure communications for supply chain activities, and implementing need-to-know restrictions. Organizations should train personnel involved in supply chain activities on operations security practices.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SR-8",
    family: "SR",
    title: "Notification Agreements",
    description: "The organization establishes agreements and procedures with entities involved in the supply chain for the system, system component, or system service for the notification of supply chain compromises and results of assessments or audits. Notification agreements ensure that organizations are informed of security incidents, vulnerabilities, and other events that may affect the integrity or availability of acquired components or services.",
    supplementalGuidance: "Organizations should include notification requirements in contracts and agreements with suppliers and service providers. Notification agreements should specify the types of events that require notification, the timeframes for notification, and the points of contact for receiving notifications. Organizations should establish procedures for evaluating and responding to supply chain notifications.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SR-9",
    family: "SR",
    title: "Tamper Resistance and Detection",
    description: "The organization implements a tamper protection program for the system, system component, or system service. The program includes the implementation of tamper-resistant and tamper-evident technologies, methods, and techniques on defined system components. Tamper resistance prevents unauthorized physical modifications to system components, while tamper detection mechanisms reveal when tampering has occurred.",
    supplementalGuidance: "Organizations should identify system components that require tamper protection based on their criticality and the risk of physical tampering. Tamper-evident technologies include seals, labels, and coatings that reveal evidence of physical intrusion. Organizations should implement procedures for inspecting system components for evidence of tampering upon receipt and during routine maintenance.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SR-10",
    family: "SR",
    title: "Inspection of Systems or Components",
    description: "The organization inspects defined systems or system components at defined intervals and at random to detect tampering. Inspection activities include physical examination of components, verification of component configuration, and checking for unauthorized modifications. Inspections are conducted by qualified personnel using appropriate tools and procedures to ensure thorough examination.",
    supplementalGuidance: "Organizations should establish inspection procedures that are appropriate for the type and criticality of the system components being inspected. Inspections should include both scheduled and random inspections to increase the likelihood of detecting tampering. Organizations should document inspection activities and findings and take corrective action when evidence of tampering is discovered.",
    priority: "P0",
    baseline: "High"
  },
  {
    id: "SR-11",
    family: "SR",
    title: "Component Authenticity",
    description: "The organization develops and implements anti-counterfeit policies, procedures, and controls that include the means to detect and prevent counterfeit components from entering the system. The organization reports counterfeit system components to defined external reporting organizations. Component authenticity verification ensures that system components are genuine and have not been substituted with counterfeit or malicious versions.",
    supplementalGuidance: "Organizations should implement controls to verify the authenticity of system components at the point of acquisition and upon receipt. Verification methods include checking serial numbers, verifying vendor certificates, using trusted procurement sources, and employing automated authentication technologies. Organizations should establish procedures for handling and reporting suspected counterfeit components.",
    priority: "P1",
    baseline: "Moderate"
  },
  {
    id: "SR-12",
    family: "SR",
    title: "Component Disposal",
    description: "The organization disposes of system components using organization-defined disposal techniques and methods in accordance with applicable laws, executive orders, directives, policies, regulations, and standards. Component disposal ensures that sensitive information stored on system components is properly sanitized before the components are released from organizational control. Disposal methods include physical destruction, degaussing, and secure overwriting.",
    supplementalGuidance: "Organizations should implement component disposal procedures that are appropriate for the sensitivity of the information stored on the components and the type of storage media. Disposal activities should be documented and verified to ensure complete sanitization. Organizations should use certified disposal services when outsourcing component disposal and should verify that disposal has been completed in accordance with organizational requirements.",
    priority: "P1",
    baseline: "Low"
  }
];

const CIS_CONTROLS_V8 = [
  {
    id: "1.1",
    title: "Establish and Maintain Detailed Enterprise Asset Inventory",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, to include end-user devices, network devices, non-computing/IoT devices, and servers. Ensure the inventory records the network address (if static), hardware address, machine name, enterprise asset owner, department for each asset, and whether the asset has been approved to connect to the network. For mobile end-user devices, MDM type tools can support this process where appropriate. This inventory includes assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments. Additionally, it includes assets that are regularly connected to the enterprise network infrastructure, even if they are not under control of the enterprise.",
    implementation: "Deploy automated asset discovery tools that scan network ranges on a regular schedule and reconcile findings against the existing inventory database. Integrate with DHCP, DNS, CMDB, and endpoint management platforms to maintain a living inventory that flags unauthorized or unmanaged devices. Review and update the inventory at least quarterly, and trigger re-scans whenever significant network changes occur."
  },
  {
    id: "1.2",
    title: "Address Unauthorized Assets",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Ensure that a process exists to address unauthorized assets on a weekly basis. The enterprise may choose to remove the asset from the network, deny the asset from connecting remotely to the network, or quarantine the asset. Unauthorized assets must be handled in a timely manner to reduce the window of exposure for potential attackers leveraging rogue devices.",
    implementation: "Configure network access control (NAC) solutions to automatically quarantine or block devices not present in the approved asset inventory. Establish a weekly review workflow where security operations triages newly discovered unauthorized assets and either onboards, isolates, or removes them. Document escalation procedures for persistent unauthorized devices that reappear after remediation."
  },
  {
    id: "1.3",
    title: "Utilize an Active Discovery Tool",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Utilize an active discovery tool to identify assets connected to the enterprise network. Configure the active discovery tool to execute daily, or more frequently. Active discovery tools scan network address ranges and interrogate devices to build or update the asset inventory automatically, reducing reliance on manual processes.",
    implementation: "Deploy network scanning tools such as Nmap, Rumble, or commercial equivalents configured to perform daily sweeps of all enterprise IP ranges including wireless segments and VLANs. Feed scan results into the centralized asset inventory through automated API integrations. Tune scan configurations to minimize disruption to sensitive OT or medical devices while still maintaining visibility."
  },
  {
    id: "1.4",
    title: "Use Dynamic Host Configuration Protocol (DHCP) Logging to Update Enterprise Asset Inventory",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Use DHCP logging on all DHCP servers or Internet Protocol (IP) address management tools to update the enterprise asset inventory. Review and use logs to update the enterprise asset inventory weekly, or more frequently. DHCP logs provide a passive mechanism to detect new devices joining the network without requiring active scanning, complementing other discovery methods.",
    implementation: "Enable verbose DHCP logging on all DHCP servers and forward logs to a centralized SIEM or log management platform. Create automated parsers that extract MAC address, hostname, and IP assignment data from DHCP lease events and reconcile against the asset inventory. Set up alerts for DHCP requests from previously unknown MAC addresses to trigger investigation workflows."
  },
  {
    id: "1.5",
    title: "Use a Passive Asset Discovery Tool",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Use a passive discovery tool to identify assets connected to the enterprise network. Review and use scans to update the enterprise asset inventory at least weekly, or more frequently. Passive discovery tools monitor network traffic to identify devices without generating additional network packets, making them ideal for sensitive environments where active scanning is not feasible.",
    implementation: "Deploy passive network monitoring sensors at key network aggregation points such as core switches, internet egress points, and inter-VLAN routing points. Configure the passive tool to analyze traffic patterns including ARP, DNS queries, and HTTP user-agent strings to fingerprint devices. Integrate passive discovery findings with the asset inventory system via API to continuously enrich device records."
  },
  {
    id: "2.1",
    title: "Establish and Maintain a Software Inventory",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a detailed inventory of all licensed software installed on enterprise assets. The software inventory must document the title, publisher, initial install/use date, and business purpose for each entry; where appropriate, include the Uniform Resource Locator (URL), app store(s), version(s), deployment mechanism, and decommission date. Review and update the software inventory bi-annually, or more frequently.",
    implementation: "Deploy endpoint management agents that automatically collect installed software information including version numbers, publishers, and installation dates from all managed devices. Aggregate this data into a centralized software inventory database and cross-reference with procurement records and license entitlements. Conduct bi-annual reviews comparing the inventory against approved software lists to identify unauthorized or end-of-life applications."
  },
  {
    id: "2.2",
    title: "Ensure Authorized Software is Currently Supported",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Ensure that only currently supported software is designated as authorized in the software inventory. If software is unsupported yet necessary for the fulfillment of the enterprise mission, document an exception detailing mitigating controls and a timeline for transition. Review the software inventory for unsupported software at least monthly, or more frequently.",
    implementation: "Maintain a reference database of vendor end-of-life and end-of-support dates for all software in the inventory and set automated alerts 90 days before support expiration. Establish a formal exception process requiring security risk assessment, compensating controls documentation, and executive sign-off for any unsupported software that must remain in use. Prioritize migration plans for unsupported software and track progress against defined timelines."
  },
  {
    id: "2.3",
    title: "Address Unauthorized Software",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Ensure that unauthorized software is either removed from use on enterprise assets or receives a documented exception. Review the software inventory monthly, or more frequently, to detect unauthorized software installations. Unauthorized software increases the attack surface and may introduce vulnerabilities or licensing compliance risks.",
    implementation: "Configure endpoint management tools to generate alerts when software not on the approved list is detected on any managed asset. Establish a remediation workflow that triggers automatic or manual removal of unauthorized software within a defined SLA, typically 72 hours. Provide a streamlined software request process so users can obtain approved alternatives rather than installing unauthorized tools."
  },
  {
    id: "2.4",
    title: "Utilize Automated Software Inventory Tools",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Utilize automated software inventory tools throughout the enterprise to detect and catalog installed software. These tools provide comprehensive visibility into all software on managed endpoints, including version details and installation metadata, reducing reliance on manual reporting.",
    implementation: "Deploy software inventory agents across all endpoint types including workstations, servers, and virtual machines, ensuring coverage of all operating system platforms in use. Configure the tools to perform at least daily scans and report findings to the centralized inventory system. Validate tool coverage regularly by comparing agent deployment counts against the hardware asset inventory to identify gaps."
  },
  {
    id: "2.5",
    title: "Allowlist Authorized Software",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Use technical controls such as application allowlisting to ensure that only authorized software can execute on enterprise assets. Reassess bi-annually, or more frequently, to ensure the allowlist is current. Application allowlisting prevents execution of unauthorized programs including malware, reducing the risk of compromise from untrusted code.",
    implementation: "Implement application control solutions such as Windows Defender Application Control, AppLocker, or third-party equivalents configured in enforcement mode on critical assets. Start with audit mode on general endpoints to identify legitimate applications, then transition to enforcement after tuning the allowlist. Establish a change management process for adding or removing applications from the allowlist tied to the software request workflow."
  },
  {
    id: "2.6",
    title: "Allowlist Authorized Libraries",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Use technical controls to ensure that only authorized software libraries, such as specific .dll, .ocx, .so, etc. files, are allowed to load into a system process. Block unauthorized libraries from loading into system processes. This control prevents DLL hijacking, side-loading attacks, and the use of malicious libraries to achieve code execution.",
    implementation: "Configure application control policies to include library-level restrictions, validating digital signatures and file hashes of DLLs and shared objects before allowing them to load. Use code integrity policies on Windows and similar mechanisms on Linux to enforce library allowlisting at the kernel level. Test library restrictions thoroughly in a staging environment before deployment to prevent breaking legitimate application dependencies."
  },
  {
    id: "2.7",
    title: "Allowlist Authorized Scripts",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Use technical controls such as digital signatures and version control to ensure that only authorized scripts, such as specific .ps1, .py, etc. files, are allowed to execute. Block unauthorized scripts from executing. This prevents attackers from using scripting engines to execute malicious payloads while still allowing approved automation and administration scripts.",
    implementation: "Implement script execution policies that require code signing for PowerShell, VBScript, and other scripting languages, using enterprise-managed code signing certificates. Deploy constrained language modes and just-enough-administration configurations to limit script capabilities even when execution is allowed. Maintain signed scripts in a version-controlled repository and use CI/CD pipelines to sign and distribute approved scripts to endpoints."
  },
  {
    id: "3.1",
    title: "Establish and Maintain a Data Management Process",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a data management process that addresses data sensitivity, data owner, handling of data, data retention limits, and disposal requirements based on sensitivity and retention standards for the enterprise. Review and update documentation annually, or when significant enterprise changes occur that could impact this safeguard. A formal data management process ensures consistent handling of information throughout its lifecycle.",
    implementation: "Document a comprehensive data management policy that defines data classification levels, assigns data ownership roles and responsibilities, and specifies retention and disposal requirements for each classification tier. Integrate the data management process with the enterprise risk management framework and ensure alignment with applicable regulatory requirements such as GDPR, HIPAA, or PCI-DSS. Train data owners and custodians on their responsibilities and conduct annual reviews to account for organizational changes."
  },
  {
    id: "3.2",
    title: "Establish and Maintain a Data Inventory",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a data inventory based on the enterprise data management process. Inventory sensitive data at a minimum. Review and update inventory annually, at a minimum, with a priority on sensitive data. The data inventory should catalog where sensitive data is stored, processed, and transmitted across enterprise systems and services.",
    implementation: "Use data discovery and classification tools to scan file shares, databases, cloud storage, and email systems to identify and catalog sensitive data such as PII, financial records, and intellectual property. Map data flows between systems to understand how sensitive data moves through the organization including third-party transfers. Maintain the inventory in a centralized register and assign review responsibilities to data owners for their respective domains."
  },
  {
    id: "3.3",
    title: "Configure Data Access Control Lists",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Configure data access control lists based on a user need to know. Apply data access control lists, also known as access permissions, to local and remote file systems, databases, and applications. Access control lists should enforce the principle of least privilege ensuring that users can only access the data required for their role.",
    implementation: "Implement role-based access control on all data repositories, mapping permissions to job functions and data classification levels rather than granting broad access to individuals. Use security groups and access control lists on file servers, SharePoint sites, databases, and cloud storage buckets to enforce need-to-know restrictions. Conduct quarterly access reviews with data owners to validate that permissions remain appropriate and revoke access for users who no longer require it."
  },
  {
    id: "3.4",
    title: "Enforce Data Retention",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Retain data according to the enterprise data management process. Data retention must include both minimum and maximum timelines. Proper data retention reduces unnecessary data accumulation, which in turn reduces the impact of potential data breaches and ensures compliance with legal and regulatory requirements.",
    implementation: "Configure automated retention policies in email systems, file storage platforms, databases, and backup solutions that enforce both minimum retention periods and maximum disposal timelines defined in the data management policy. Implement automated deletion workflows that remove data past its maximum retention date after verification that no legal holds apply. Audit retention policy compliance quarterly and document any deviations or exceptions."
  },
  {
    id: "3.5",
    title: "Securely Dispose of Data",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Securely dispose of data as outlined in the enterprise data management process. Ensure the disposal process and method are commensurate with the data sensitivity. Secure disposal prevents recovery of sensitive information from decommissioned media, retired storage systems, and end-of-life devices.",
    implementation: "Establish certified data destruction procedures that include cryptographic erasure for encrypted storage, NIST 800-88 compliant media sanitization for unencrypted media, and physical destruction for highly sensitive assets. Maintain chain-of-custody documentation and certificates of destruction for all disposed media containing sensitive data. Contract with certified e-waste vendors for physical destruction and audit their processes annually."
  },
  {
    id: "3.6",
    title: "Encrypt Data on End-User Devices",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Encrypt data on end-user devices containing sensitive data. Example implementations can include Windows BitLocker, Apple FileVault, Linux dm-crypt. Full disk encryption protects data at rest from unauthorized access in the event of device loss or theft, which is particularly important for laptops and mobile devices.",
    implementation: "Enable full-disk encryption on all end-user devices using platform-native solutions such as BitLocker for Windows, FileVault for macOS, and LUKS/dm-crypt for Linux, enforced through endpoint management policies. Store encryption recovery keys in a centralized enterprise key management system with appropriate access controls and audit logging. Verify encryption compliance through regular endpoint compliance checks and block non-compliant devices from accessing enterprise resources."
  },
  {
    id: "3.7",
    title: "Establish and Maintain a Data Classification Scheme",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and maintain an overall data classification scheme for the enterprise. Enterprises may use labels such as Sensitive, Confidential, and Public, and classify their data according to those labels. Review and update the classification scheme annually, or when significant enterprise changes occur that could impact this safeguard. A consistent classification scheme enables appropriate security controls to be applied based on data sensitivity.",
    implementation: "Define a tiered classification scheme with clear criteria for each level, such as Public, Internal, Confidential, and Restricted, along with handling requirements and examples for each tier. Deploy data classification tools that allow users to label documents at creation and automatically apply labels based on content inspection rules. Train all employees on the classification scheme and integrate labeling requirements into document templates and email clients."
  },
  {
    id: "3.8",
    title: "Document Data Flows",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Document data flows that include service provider data flows and maintain documentation of enterprise data flows. Review and update documentation annually, or when significant enterprise changes occur that could impact this safeguard. Data flow documentation provides visibility into how sensitive data traverses internal and external systems, enabling proper controls and risk assessment.",
    implementation: "Create data flow diagrams for all systems processing sensitive data, documenting source, destination, transport mechanism, encryption in transit, and any intermediary processing or storage points including third-party services. Use standardized notation such as DFD or STRIDE-compatible formats to ensure consistency and facilitate threat modeling exercises. Store data flow documentation in a centralized repository accessible to security, compliance, and architecture teams for reference during change management reviews."
  },
  {
    id: "3.9",
    title: "Encrypt Data on Removable Media",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Encrypt data on removable media. Removable media includes USB drives, external hard drives, optical media, and similar portable storage devices. Encrypting removable media prevents unauthorized access to sensitive data if the media is lost, stolen, or improperly disposed of.",
    implementation: "Deploy endpoint DLP solutions that enforce mandatory encryption on any data written to removable media using tools such as BitLocker To Go or third-party USB encryption solutions. Configure group policies to restrict removable media write access to only enterprise-approved encrypted devices. Consider blocking removable media entirely for roles that do not have a legitimate business need and provide secure file transfer alternatives."
  },
  {
    id: "3.10",
    title: "Encrypt Sensitive Data in Transit",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Encrypt sensitive data in transit using protocols with validated cryptographic implementations. Examples include TLS 1.2 or higher and IPsec tunnels. Encryption in transit protects data from interception and eavesdropping as it traverses networks, including internal networks which may be subject to lateral movement by attackers.",
    implementation: "Enforce TLS 1.2 or higher on all web services, APIs, and email transport paths, disabling legacy protocols such as SSLv3, TLS 1.0, and TLS 1.1 across the enterprise. Use IPsec or WireGuard VPN tunnels for site-to-site connectivity and remote access where TLS is not applicable. Regularly scan internet-facing and internal services for deprecated cipher suites and protocols using tools such as SSL Labs or testssl.sh."
  },
  {
    id: "3.11",
    title: "Encrypt Sensitive Data at Rest",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Encrypt sensitive data at rest on servers, applications, and databases containing sensitive data. Storage-layer encryption, also known as server-side encryption, meets the minimum requirement of this safeguard. Additional encryption of sensitive data within application databases provides defense in depth against unauthorized access even if storage-level controls are bypassed.",
    implementation: "Enable encryption at rest on all storage systems containing sensitive data including database transparent data encryption, cloud storage service encryption, and SAN/NAS volume encryption. Use enterprise key management solutions such as HashiCorp Vault or cloud-native KMS services to manage encryption keys with proper rotation schedules. Verify encryption status as part of system provisioning checklists and continuous compliance monitoring."
  },
  {
    id: "3.12",
    title: "Segment Data Processing and Storage Based on Sensitivity",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Segment data processing and storage based on the sensitivity of the data. Do not process sensitive data on enterprise assets intended for lower sensitivity data. Network segmentation and access controls between data sensitivity zones reduce the blast radius of a potential breach and support regulatory compliance requirements for data isolation.",
    implementation: "Implement network segmentation using VLANs, firewalls, and micro-segmentation to isolate systems processing sensitive data from general-purpose networks. Deploy dedicated infrastructure or cloud accounts for regulated data such as PCI cardholder data or HIPAA protected health information. Enforce segmentation with firewall rules, security group policies, and regular validation through network penetration testing."
  },
  {
    id: "3.13",
    title: "Deploy a Data Loss Prevention Solution",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Implement a data loss prevention (DLP) solution on enterprise assets to detect and prevent unauthorized transfer of sensitive data. The DLP solution should monitor data in use on endpoints, data in transit across the network, and data at rest in storage repositories to provide comprehensive coverage against data exfiltration through multiple channels.",
    implementation: "Deploy enterprise DLP solutions covering endpoint, network, and cloud channels with policies tuned to detect sensitive data patterns such as credit card numbers, social security numbers, and classified document markings. Start in monitor-only mode to establish baselines and reduce false positives before transitioning to enforcement mode that blocks or quarantines policy violations. Integrate DLP alerts with the SIEM and incident response workflow to ensure timely investigation of potential data exfiltration events."
  },
  {
    id: "3.14",
    title: "Log Sensitive Data Access",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Log sensitive data access, including modification and disposal. Access logging for sensitive data provides accountability, supports forensic investigation of potential breaches, and enables detection of anomalous access patterns that may indicate insider threats or compromised accounts.",
    implementation: "Enable auditing on all repositories containing sensitive data including database audit logging, file access auditing, and cloud storage access logging. Forward access logs to the centralized SIEM and create correlation rules to detect anomalous patterns such as bulk downloads, access outside business hours, or access from unusual locations. Retain sensitive data access logs according to the data retention policy with integrity protections to prevent tampering."
  },
  {
    id: "4.1",
    title: "Establish and Maintain a Secure Configuration Process",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a secure configuration process for enterprise assets including end-user devices, servers, and network devices, and software including operating systems and applications. Review and update documentation annually, or when significant enterprise changes occur that could impact this safeguard. The secure configuration process should address initial configuration, ongoing maintenance, and exception handling.",
    implementation: "Develop secure configuration baselines for each technology platform in use, referencing industry benchmarks such as CIS Benchmarks, DISA STIGs, or vendor security guides. Document the configuration process in a standard operating procedure that covers initial hardening during provisioning, ongoing drift detection, and exception management. Assign ownership of configuration baselines to technology teams and schedule annual reviews aligned with technology refresh cycles."
  },
  {
    id: "4.2",
    title: "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a secure configuration process for network infrastructure, including firewalls, routers, and switches. Review and update documentation annually, or when significant enterprise changes occur. Network devices are frequent targets because they control traffic flow and their compromise can grant broad access to the enterprise environment.",
    implementation: "Create hardened configuration templates for each class of network device including routers, switches, firewalls, and load balancers based on CIS Benchmarks or vendor hardening guides. Store golden configuration templates in version control and use automated configuration management tools to detect and remediate drift from approved baselines. Implement change management procedures requiring peer review and approval before any network device configuration changes are applied to production."
  },
  {
    id: "4.3",
    title: "Configure Automatic Session Locking on Enterprise Assets",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Configure automatic session locking on enterprise assets after a defined period of inactivity. For general purpose operating systems, the period must not exceed 15 minutes. For mobile end-user devices, the period must not exceed 2 minutes. Automatic session locking prevents unauthorized physical access to unattended devices.",
    implementation: "Deploy group policy settings or MDM configuration profiles that enforce screen lock after no more than 15 minutes of inactivity on workstations and 2 minutes on mobile devices. Require password or biometric authentication to unlock sessions and disable options for users to extend or override the timeout. Verify compliance through endpoint management reporting and flag non-compliant devices for remediation."
  },
  {
    id: "4.4",
    title: "Implement and Manage a Firewall on Servers",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Implement and manage a firewall on servers where supported and applicable. Example implementations include a virtual firewall, operating system firewall, or a third-party firewall agent. Host-based firewalls provide defense in depth by restricting network access to only required services and ports, limiting lateral movement even if network-level controls are bypassed.",
    implementation: "Enable and configure host-based firewalls on all servers using platform-native capabilities such as Windows Firewall with Advanced Security or iptables/nftables on Linux. Define rules that allow only required inbound and outbound connections based on documented service dependencies, following a default-deny approach. Manage firewall rules through centralized configuration management tools and audit rule sets quarterly to remove stale or overly permissive entries."
  },
  {
    id: "4.5",
    title: "Implement and Manage a Firewall on End-User Devices",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Implement and manage a host-based firewall or port-filtering tool on end-user devices with a default-deny rule that drops all traffic except those services and ports that are explicitly allowed. End-user device firewalls protect against network-based attacks, particularly when devices connect to untrusted networks such as public Wi-Fi.",
    implementation: "Configure host-based firewalls on all end-user devices through group policy or endpoint management profiles, enforcing a default-deny inbound policy with exceptions only for required services. Prevent end users from modifying firewall rules by restricting local administrator privileges and locking down firewall management interfaces. Monitor firewall status as part of endpoint compliance checks and remediate disabled firewalls automatically."
  },
  {
    id: "4.6",
    title: "Securely Manage Enterprise Assets and Software",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Securely manage enterprise assets and software. Example implementations include managing configuration through version-controlled infrastructure-as-code and accessing administrative interfaces over secure network protocols such as SSH and HTTPS. Do not use insecure management protocols such as Telnet and HTTP for administrative access.",
    implementation: "Disable insecure management protocols including Telnet, HTTP, SNMPv1/v2c, and unencrypted FTP on all enterprise assets and replace them with their secure equivalents such as SSH, HTTPS, SNMPv3, and SFTP. Implement infrastructure-as-code practices using tools like Ansible, Terraform, or Puppet to manage configurations through version-controlled repositories. Restrict administrative interface access to dedicated management networks or require VPN connectivity for remote administration."
  },
  {
    id: "4.7",
    title: "Manage Default Accounts on Enterprise Assets and Software",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Manage default accounts on enterprise assets and software such as root, administrator, and other preconfigured vendor accounts. Example implementations can include disabling default accounts or making them unusable. Default accounts with known credentials are among the first targets attackers attempt and must be secured or disabled during initial system configuration.",
    implementation: "Disable or rename default accounts on all enterprise assets during the provisioning process and change default passwords to strong, unique values stored in the enterprise password vault. Create named individual administrative accounts for all personnel requiring elevated access to maintain accountability. Include default account verification in system hardening checklists and validate compliance through automated configuration scanning."
  },
  {
    id: "4.8",
    title: "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Uninstall or disable unnecessary services on enterprise assets and software such as an unused file sharing service, web application module, or service function. Reducing the number of running services minimizes the attack surface by eliminating potential entry points that attackers could exploit, particularly for services that may have unpatched vulnerabilities.",
    implementation: "Establish a baseline of required services for each system role and document approved services in the secure configuration standard. Use configuration management tools to audit running services and disable or uninstall those not on the approved list. Regularly review listening ports and running processes on servers and workstations to identify newly installed or re-enabled unnecessary services."
  },
  {
    id: "4.9",
    title: "Configure Trusted DNS Servers on Enterprise Assets",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Configure trusted DNS servers on enterprise assets. Example implementations include configuring assets to use enterprise-controlled DNS servers or reputable externally accessible DNS servers. Trusted DNS servers help prevent DNS-based attacks such as DNS poisoning and ensure that DNS logging captures resolution activity for security monitoring.",
    implementation: "Configure all enterprise assets to use enterprise-managed DNS servers or vetted external DNS services such as those with DNSSEC validation and DNS-over-HTTPS/TLS support. Use DHCP to distribute DNS settings automatically and prevent manual overrides through group policy or endpoint management restrictions. Monitor for DNS traffic directed to unauthorized DNS servers as an indicator of compromise or policy violation."
  },
  {
    id: "4.10",
    title: "Enforce Automatic Device Lockout on Portable End-User Devices",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Enforce automatic device lockout following a predetermined threshold of local failed authentication attempts on portable end-user devices where supported. For laptops, do not allow more than 20 failed authentication attempts; for tablets and smartphones, no more than 10 failed authentication attempts. Account lockout defends against brute-force password guessing attacks on lost or stolen portable devices.",
    implementation: "Configure account lockout policies through group policy for Windows laptops and MDM profiles for mobile devices, setting thresholds at 20 failed attempts for laptops and 10 for mobile devices. For mobile devices, consider enabling automatic device wipe after a higher threshold of consecutive failed attempts to protect data on stolen devices. Monitor lockout events centrally to detect targeted brute-force attacks across multiple devices."
  },
  {
    id: "4.11",
    title: "Enforce Remote Wipe Capability on Portable End-User Devices",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Remotely wipe enterprise data from enterprise-owned portable end-user devices when deemed appropriate such as lost or stolen devices, or when an individual no longer supports the enterprise. Remote wipe capability ensures that sensitive enterprise data can be removed from devices that are no longer under physical control of the organization.",
    implementation: "Enroll all portable enterprise devices in an MDM solution that supports remote wipe commands for both full device wipe and selective enterprise data wipe. Document and test remote wipe procedures regularly to ensure they function correctly when needed in an emergency. Establish clear criteria and authorization processes for initiating remote wipe, including scenarios such as employee termination, reported loss, or detected compromise."
  },
  {
    id: "4.12",
    title: "Separate Enterprise Workspaces on Mobile End-User Devices",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Ensure separate enterprise workspaces are used on mobile end-user devices where supported. Example implementations include using an MDM tool with containerization features or Apple User Enrollment for BYOD devices. Workspace separation isolates enterprise data from personal data, reducing the risk of data leakage through personal applications or device compromise.",
    implementation: "Deploy containerization solutions such as Android Work Profiles, Samsung Knox, or iOS managed app configurations to create isolated enterprise workspaces on mobile devices. Configure policies that prevent data sharing between the enterprise container and personal applications including restricting copy/paste, screenshots, and file sharing across boundaries. Apply enterprise security policies including encryption and access controls exclusively to the work container without affecting personal device usage."
  },
  {
    id: "5.1",
    title: "Establish and Maintain an Inventory of Accounts",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain an inventory of all accounts managed in the enterprise. The inventory must include both user and administrator accounts. The inventory at a minimum should contain the person name, username, start/stop dates, and department. Validate that all active accounts are authorized on a recurring schedule at a minimum quarterly, or more frequently.",
    implementation: "Extract account lists from all identity providers including Active Directory, cloud IAM platforms, and application-specific directories into a centralized account inventory. Implement automated reconciliation between the account inventory and HR records to detect orphaned accounts from departed employees and accounts without assigned owners. Conduct quarterly access certification campaigns where managers validate that accounts assigned to their team members are still needed and appropriately permissioned."
  },
  {
    id: "5.2",
    title: "Use Unique Passwords",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Use unique passwords for all enterprise assets. Best practice implementation includes at a minimum an 8-character password for accounts using MFA and a 14-character password for accounts without MFA. Unique passwords prevent credential stuffing attacks where credentials compromised from one service are used to access other systems.",
    implementation: "Configure password policies in identity providers to enforce minimum length requirements of 8 characters with MFA or 14 characters without MFA, and check passwords against known breached password lists. Deploy an enterprise password manager to enable employees to generate and store unique, complex passwords for each system without resorting to password reuse. Implement password breach monitoring services that alert when enterprise credentials appear in publicly leaked datasets."
  },
  {
    id: "5.3",
    title: "Disable Dormant Accounts",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Delete or disable any dormant accounts after a period of 45 days of inactivity where supported. Dormant accounts represent a significant security risk as they may belong to former employees or contractors and can be exploited by attackers without triggering suspicion from their legitimate owner.",
    implementation: "Configure automated workflows in the identity provider to flag accounts with no authentication activity for 30 days and automatically disable them after 45 days of inactivity. Send automated notifications to account owners and their managers at the 30-day mark to provide an opportunity to confirm the account is still needed before automatic disablement. Review disabled accounts quarterly and delete accounts that have remained disabled for an extended period with no reactivation request."
  },
  {
    id: "5.4",
    title: "Restrict Administrator Privileges to Dedicated Administrator Accounts",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Restrict administrator privileges to dedicated administrator accounts on enterprise assets. Conduct general computing activities such as internet browsing, email, and productivity suite use from the user primary non-privileged account. Separating administrative and standard user accounts reduces the risk of credential theft through phishing or malware executed during routine activities compromising privileged access.",
    implementation: "Provision separate administrative accounts for all IT personnel that are used exclusively for elevated tasks, with naming conventions that clearly distinguish them from standard accounts. Enforce conditional access policies that prevent administrative accounts from being used for email, web browsing, and general productivity applications. Implement privileged access workstations or jump servers for administrative tasks, ensuring that elevated credentials are only entered on hardened, dedicated systems."
  },
  {
    id: "5.5",
    title: "Establish and Maintain an Inventory of Service Accounts",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and maintain an inventory of service accounts. The inventory at a minimum must contain department owner, review date, and purpose. Perform service account reviews to validate that all active accounts are authorized on a recurring schedule at a minimum quarterly, or more frequently. Service accounts often have elevated privileges and their compromise can provide attackers with persistent, unmonitored access.",
    implementation: "Catalog all service accounts across Active Directory, cloud platforms, and application databases, documenting the owning team, associated application, privilege level, and password rotation schedule for each. Implement automated detection of new service account creation through directory audit logs and require approval workflows before new service accounts are provisioned. Conduct quarterly reviews with application owners to validate that each service account remains necessary and that its privileges are appropriately scoped."
  },
  {
    id: "5.6",
    title: "Centralize Account Management",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Centralize account management through a directory service or identity provider. Centralized account management simplifies provisioning and deprovisioning, enables consistent security policy enforcement, and provides unified audit logging across enterprise systems. It reduces the risk of orphaned accounts across disparate systems.",
    implementation: "Federate authentication for all enterprise applications through a centralized identity provider using protocols such as SAML, OAuth, or OpenID Connect. Implement automated provisioning and deprovisioning workflows triggered by HR lifecycle events such as hiring, role changes, and termination. Conduct a periodic inventory of applications to identify any that still use local accounts and develop migration plans to bring them under centralized identity management."
  },
  {
    id: "6.1",
    title: "Establish an Access Granting Process",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and follow a process, preferably automated, for granting access to enterprise assets upon new hire, rights grant, or role change of a user. A formal access granting process ensures that access is authorized, documented, and traceable, preventing unauthorized privilege accumulation over time.",
    implementation: "Implement an automated access request and approval workflow integrated with the HR system that provisions role-based access upon hire or role change based on predefined access templates for each job function. Require manager and data owner approvals for access requests outside the standard role template, with all approvals documented in the identity governance platform. Configure automatic notifications to security teams when access is granted to high-sensitivity systems or administrative roles."
  },
  {
    id: "6.2",
    title: "Establish an Access Revoking Process",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and follow a process, preferably automated, for revoking access to enterprise assets, through disabling accounts rather than deleting, upon termination, rights revocation, or role change of a user. Timely deprovisioning is critical to prevent former employees or personnel who changed roles from retaining inappropriate access. Accounts should be disabled rather than deleted to preserve audit trail integrity.",
    implementation: "Integrate the identity management system with HR to trigger automated account disablement within 24 hours of termination and access adjustment within 48 hours of role changes. Implement a termination checklist that covers all access types including VPN, cloud services, physical access badges, and third-party SaaS applications. Test the deprovisioning process regularly by conducting tabletop exercises simulating employee departure scenarios."
  },
  {
    id: "6.3",
    title: "Require MFA for Externally-Exposed Applications",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Require all externally-exposed enterprise or third-party applications to enforce MFA where supported. Enforcing MFA adds a second factor of authentication that significantly reduces the risk of unauthorized access from stolen credentials for internet-facing applications, which are exposed to a broad range of attackers.",
    implementation: "Enable MFA on all externally-accessible applications including VPN gateways, webmail, cloud platforms, and SaaS tools, using phishing-resistant methods such as FIDO2/WebAuthn where possible. Configure conditional access policies to require MFA for all authentication attempts originating from outside the corporate network. Inventory all external-facing applications and validate MFA enforcement status quarterly, escalating any gaps to application owners for remediation."
  },
  {
    id: "6.4",
    title: "Require MFA for Remote Network Access",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Require MFA for remote network access. Remote network access provides a pathway into the enterprise from potentially untrusted locations and devices, making strong authentication essential to prevent unauthorized entry through compromised credentials.",
    implementation: "Configure VPN concentrators and remote access gateways to require MFA for all connections, integrating with the enterprise identity provider for centralized enforcement. Support multiple MFA methods including hardware tokens, authenticator apps, and push notifications to accommodate different user scenarios while avoiding SMS-based MFA where possible due to SIM-swap risks. Monitor for VPN connections that bypass MFA enforcement and investigate them immediately as potential security incidents."
  },
  {
    id: "6.5",
    title: "Require MFA for Administrative Access",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Require MFA for all administrative access accounts where supported on all enterprise assets whether managed on-site or through a third-party provider. Administrative accounts have elevated privileges that make them high-value targets, and MFA provides a critical safeguard against unauthorized use even if administrative credentials are compromised.",
    implementation: "Enforce MFA on all administrative account authentications across domain controllers, cloud management consoles, network device management interfaces, and application admin panels. Deploy phishing-resistant MFA methods such as FIDO2 hardware security keys for administrative accounts as a priority over less secure methods. Configure just-in-time administrative access solutions that require MFA approval for each elevation session, limiting standing administrative privileges."
  },
  {
    id: "6.6",
    title: "Establish and Maintain an Inventory of Authentication and Authorization Systems",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and maintain an inventory of the enterprise authentication and authorization systems, including those hosted on-site or at a remote service provider. Review and update the inventory, at a minimum, annually, or more frequently. Understanding all authentication and authorization systems is fundamental to ensuring consistent security controls and identifying single points of failure or gaps in coverage.",
    implementation: "Catalog all authentication and authorization systems including Active Directory, LDAP directories, RADIUS servers, SAML/OIDC identity providers, and application-specific authentication databases. Document the systems and applications relying on each authentication source, the protocols used, and the security controls in place such as MFA enforcement and certificate validation. Review the inventory annually and after any infrastructure changes to ensure completeness and identify consolidation opportunities."
  },
  {
    id: "6.7",
    title: "Centralize Access Control",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Centralize access control for all enterprise assets through a directory service or SSO provider where supported. Centralized access control provides a single pane of visibility into who has access to what, simplifies policy enforcement, and ensures that deprovisioning actions propagate across all integrated systems.",
    implementation: "Federate all enterprise applications through a centralized SSO platform using SAML 2.0 or OpenID Connect, eliminating application-specific credentials wherever possible. Implement attribute-based or role-based access control policies centrally that are enforced across all integrated applications. Prioritize federation of high-risk applications first and maintain a backlog for migrating remaining applications that still use local authentication."
  },
  {
    id: "6.8",
    title: "Define and Maintain Role-Based Access Control",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Define and maintain role-based access control by determining and documenting the access rights necessary for each role within the enterprise to successfully carry out its assigned duties. Perform access control reviews of enterprise assets to validate that all privileges are authorized on a recurring schedule at a minimum annually, or more frequently, if the enterprise deems it necessary. Role-based access control ensures consistent, auditable assignment of permissions based on job function rather than ad-hoc individual grants.",
    implementation: "Define a role hierarchy aligned with organizational job functions, documenting the specific system access, data access, and privilege level required for each role in collaboration with business unit leaders. Implement the role definitions in the identity governance platform and use them as the basis for all access provisioning, ensuring new access requests reference approved roles. Conduct annual role mining exercises to validate that role definitions remain current and recertify role assignments with business owners."
  },
  {
    id: "7.1",
    title: "Establish and Maintain a Vulnerability Management Process",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a documented vulnerability management process for enterprise assets. Review and update documentation annually, or when significant enterprise changes occur that could impact this safeguard. The process should define scanning frequency, risk rating methodology, remediation timelines, exception handling, and roles and responsibilities.",
    implementation: "Document a vulnerability management policy that defines scanning scope and frequency, vulnerability severity rating criteria aligned with CVSS or a risk-based methodology, remediation SLAs by severity level, and escalation procedures for overdue findings. Assign clear roles including vulnerability scanning operators, remediation owners by technology domain, and a governance function to track compliance with SLAs. Review and update the process annually and after any significant incidents that reveal gaps in vulnerability management coverage."
  },
  {
    id: "7.2",
    title: "Establish and Maintain a Remediation Process",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a risk-based remediation strategy documented in a remediation process with monthly or more frequent reviews. The remediation strategy should define timelines for remediation based on vulnerability severity and asset criticality. Establish SLAs for remediation and track compliance against those targets to ensure vulnerabilities are addressed in a timely manner.",
    implementation: "Define remediation SLAs based on a matrix of vulnerability severity and asset criticality, such as critical vulnerabilities on internet-facing assets within 48 hours and high severity within 14 days. Implement automated ticketing integration that creates and assigns remediation tasks to system owners when vulnerabilities are identified, with escalation workflows for overdue items. Track remediation metrics including mean time to remediate and SLA compliance rates, reporting monthly to security leadership."
  },
  {
    id: "7.3",
    title: "Perform Automated Operating System Patch Management",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Perform operating system updates on enterprise assets through automated patch management on a monthly or more frequent basis. Timely operating system patching addresses known vulnerabilities that attackers actively exploit, and automation ensures consistent coverage across the environment without relying on manual intervention.",
    implementation: "Deploy enterprise patch management solutions such as WSUS, SCCM, or cloud-native update services configured to automatically download and install OS security patches within the remediation SLA windows. Implement a phased rollout strategy testing patches in a pilot group before broad deployment to balance speed with stability. Monitor patch compliance rates across the environment and investigate systems that consistently fail to patch for underlying issues."
  },
  {
    id: "7.4",
    title: "Perform Automated Application Patch Management",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Perform application updates on enterprise assets through automated patch management on a monthly or more frequent basis. Third-party application vulnerabilities are a common attack vector, and keeping applications patched is equally important as operating system updates for maintaining a strong security posture.",
    implementation: "Deploy third-party patch management tools that cover the full range of applications in the software inventory, including browsers, productivity suites, PDF readers, and development tools. Configure automated deployment of application patches following testing validation, with emergency out-of-cycle deployment procedures for actively exploited vulnerabilities. Track application patching compliance separately from OS patching and address any gaps in coverage for applications not supported by the patch management platform."
  },
  {
    id: "7.5",
    title: "Perform Automated Vulnerability Scans of Internal Enterprise Assets",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Perform automated vulnerability scans of internal enterprise assets on a quarterly or more frequent basis. Conduct both authenticated and agent-based scanning. Regular internal vulnerability scanning identifies weaknesses that could be exploited during lateral movement and ensures that patch management and configuration management processes are effective.",
    implementation: "Deploy authenticated vulnerability scanning using credentialed agents or scan accounts with sufficient privileges to enumerate installed software, configurations, and missing patches across all internal assets. Schedule quarterly full scans at a minimum with more frequent scanning of high-value assets and newly provisioned systems. Correlate scan results with the asset inventory to identify coverage gaps and ensure all assets are being scanned."
  },
  {
    id: "7.6",
    title: "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Perform automated vulnerability scans of externally-exposed enterprise assets using a SCAP-compatible vulnerability scanning tool on a monthly or more frequent basis. Conduct both authenticated and unauthenticated scans. External assets face the greatest threat exposure and require more frequent scanning to detect vulnerabilities before they can be exploited by external attackers.",
    implementation: "Configure external vulnerability scanning from outside the network perimeter targeting all internet-facing IP addresses and hostnames, running at least monthly with additional scans after any changes to external-facing infrastructure. Use both authenticated and unauthenticated scan profiles to identify vulnerabilities visible to anonymous attackers as well as those detectable only with credentials. Integrate external scan results with the remediation workflow and prioritize findings on external assets for accelerated remediation."
  },
  {
    id: "7.7",
    title: "Remediate Detected Vulnerabilities",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Remediate detected vulnerabilities in software through processes and tooling on a monthly or more frequent basis based on the remediation process. When remediation is not possible, document and implement compensating controls. Vulnerability detection without effective remediation provides no security benefit; the goal is to reduce the window of exposure by closing identified gaps promptly.",
    implementation: "Integrate vulnerability scan results with the IT service management platform to automatically generate remediation tickets assigned to system owners with priority based on vulnerability severity and asset criticality. Track remediation progress against SLAs and escalate overdue items through management chains with increasing urgency. For vulnerabilities where patching is not feasible, require documented compensating controls reviewed and approved by the security team with a defined re-evaluation date."
  },
  {
    id: "8.1",
    title: "Establish and Maintain an Audit Log Management Process",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain an audit log management process that defines the enterprise logging requirements. At a minimum address the collection, review, and retention of audit logs for enterprise assets. Review and update documentation annually, or when significant enterprise changes occur that could impact this safeguard. A documented logging process ensures consistent capture of security-relevant events across the enterprise.",
    implementation: "Document a logging policy that specifies which event types must be logged across different asset categories, minimum retention periods, log integrity requirements, and review responsibilities. Define log collection architecture including which events are forwarded to the SIEM versus retained locally, and establish performance and reliability requirements for the logging infrastructure. Review and update the logging policy annually and whenever new systems or regulatory requirements are introduced."
  },
  {
    id: "8.2",
    title: "Collect Audit Logs",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Collect audit logs. Ensure that logging per the enterprise audit log management process is enforced on each enterprise asset. Audit logs provide the evidentiary basis for detecting, investigating, and responding to security incidents and are essential for maintaining accountability.",
    implementation: "Configure audit logging on all enterprise assets including servers, workstations, network devices, and cloud services, capturing at minimum authentication events, privilege changes, system changes, and access to sensitive data. Deploy log collection agents or configure syslog forwarding to centralize logs in the SIEM platform. Monitor log collection health and alert on gaps where expected log sources stop sending events."
  },
  {
    id: "8.3",
    title: "Ensure Adequate Audit Log Storage",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Ensure that logging destinations maintain adequate storage to comply with the enterprise audit log management process. Insufficient storage can result in log loss which undermines forensic capability and compliance. Storage capacity planning should account for normal log volume growth and potential spikes during security incidents.",
    implementation: "Size log storage based on current daily log ingestion rates with a growth buffer and ensure capacity meets the retention requirements defined in the logging policy. Implement automated monitoring of storage utilization with alerts at defined thresholds such as 70% and 90% capacity to enable proactive expansion. Consider tiered storage strategies moving older logs from hot storage to cost-effective cold or archive storage while maintaining search and retrieval capability."
  },
  {
    id: "8.4",
    title: "Standardize Time Synchronization",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Standardize time synchronization. Configure at least two synchronized time sources across enterprise assets where supported. Accurate and consistent timestamps are critical for correlating events across multiple systems during incident investigation and for maintaining the legal admissibility of log evidence.",
    implementation: "Configure all enterprise assets to synchronize time with at least two reliable NTP sources, preferably enterprise-managed NTP servers that themselves synchronize with authoritative time sources such as NIST or GPS receivers. Deploy NTP monitoring to detect and alert on time drift exceeding acceptable thresholds, typically 1 second for general assets and tighter for financial or regulated systems. Document the time synchronization architecture and ensure all log sources including cloud services are aligned to the same time standard."
  },
  {
    id: "8.5",
    title: "Collect Detailed Audit Logs",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Configure detailed audit logging for enterprise assets containing sensitive data. Include event source, date, username, timestamp, source addresses, destination addresses, and other useful elements per the enterprise audit log management process. Detailed logs enable more effective threat detection, forensic analysis, and compliance reporting compared to basic logging.",
    implementation: "Configure verbose audit policies on systems processing sensitive data to capture detailed event metadata including source and destination IP addresses, user identifiers, process names, file paths, and command-line arguments where applicable. Tune logging verbosity to balance security visibility with storage and performance considerations, focusing detailed logging on authentication, authorization, data access, and configuration change events. Validate log detail by periodically reviewing sample events to ensure all required fields are populated and usable for analysis."
  },
  {
    id: "8.6",
    title: "Collect DNS Query Audit Logs",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Collect DNS query audit logs on enterprise assets where appropriate and supported. DNS query logs provide visibility into domain resolution activity that can reveal malware command-and-control communications, data exfiltration through DNS tunneling, and access to known malicious domains.",
    implementation: "Enable query logging on enterprise DNS servers and configure DNS resolvers to forward query logs to the SIEM platform. Deploy DNS-layer security solutions that log and analyze all DNS queries in real-time, blocking known malicious domains and flagging suspicious patterns. Create SIEM correlation rules to detect indicators such as high-volume queries to newly registered domains, DNS tunneling patterns, and queries to known threat intelligence indicators."
  },
  {
    id: "8.7",
    title: "Collect URL Request Audit Logs",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Collect URL request audit logs on enterprise assets where appropriate and supported. URL logging provides visibility into web browsing activity that can identify visits to malicious sites, unauthorized cloud service usage, and data exfiltration attempts through web channels.",
    implementation: "Configure web proxy servers and secure web gateways to log all URL requests including the full URL, requesting user identity, timestamp, response code, and bytes transferred. For encrypted HTTPS traffic, deploy TLS inspection where legally and technically appropriate to gain visibility into encrypted web communications. Forward web access logs to the SIEM and create alerting rules for access to known malicious URLs, newly categorized domains, and anomalous browsing patterns."
  },
  {
    id: "8.8",
    title: "Collect Command-Line Audit Logs",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Collect command-line audit logs. Example implementations include collecting audit logs from PowerShell, BASH, and remote administrative terminals. Command-line logging captures the specific actions executed by users and processes, providing critical forensic evidence and enabling detection of living-off-the-land attack techniques that use legitimate system tools.",
    implementation: "Enable PowerShell script block logging, module logging, and transcription on Windows systems through group policy, and configure auditd or syslog to capture command execution on Linux systems. Deploy endpoint detection and response solutions that capture process creation events with full command-line arguments across all endpoints. Forward command-line logs to the SIEM and create detection rules for suspicious patterns such as encoded PowerShell commands, use of credential dumping tools, and unusual scripting activity."
  },
  {
    id: "8.9",
    title: "Centralize Audit Logs",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Centralize, to the extent possible, audit log collection and retention across enterprise assets. Log centralization enables correlation of events across multiple systems, provides a single source of truth for investigations, and protects log integrity by storing copies outside the systems that generated them where they could be tampered with by an attacker.",
    implementation: "Deploy a centralized SIEM or log management platform and configure all enterprise assets to forward security-relevant logs in near real-time. Implement redundant log forwarding paths to prevent log loss during network disruptions and validate log delivery through automated completeness checks. Establish role-based access controls on the centralized log platform to prevent unauthorized modification or deletion of log data."
  },
  {
    id: "8.10",
    title: "Retain Audit Logs",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Retain audit logs across enterprise assets for a minimum of 90 days. Adequate log retention ensures that security teams have sufficient historical data to investigate incidents that may not be detected immediately, and supports compliance with regulatory requirements that often specify minimum retention periods.",
    implementation: "Configure log retention policies in the SIEM and log management platforms to maintain at least 90 days of searchable hot storage, with longer retention in cold or archive storage as required by regulatory obligations. Implement automated lifecycle management that transitions logs from hot to cold storage based on age while maintaining indexing for search and retrieval. Validate retention compliance through periodic audits checking that the oldest available logs meet or exceed the required retention period."
  },
  {
    id: "8.11",
    title: "Conduct Audit Log Reviews",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Conduct reviews of audit logs to detect anomalies or abnormal events that could indicate a potential threat. Conduct reviews on a weekly or more frequent basis. Log review transforms raw log data into actionable intelligence by identifying suspicious patterns that automated detection rules may miss, providing a human analytical layer to the monitoring program.",
    implementation: "Establish a structured log review process where security analysts review SIEM dashboards, alert queues, and summary reports on at least a weekly cadence, focusing on authentication anomalies, privilege escalation events, and unusual data access patterns. Develop review checklists tailored to high-value asset types and create saved searches or dashboards that highlight deviations from baseline activity. Document review findings and track identified anomalies through the incident response process."
  },
  {
    id: "8.12",
    title: "Collect Service Provider Logs",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Collect service provider logs where supported. Example implementations include collecting authentication and authorization events, data creation and disposal events, and user management events. Service provider logs extend visibility beyond enterprise-owned infrastructure to cloud and SaaS environments where an increasing share of enterprise data and processing resides.",
    implementation: "Enable and configure audit logging in all cloud and SaaS service providers including IaaS management plane logs, SaaS admin activity logs, and authentication event logs. Use cloud-native log export capabilities such as AWS CloudTrail, Azure Activity Logs, or Google Cloud Audit Logs to forward events to the enterprise SIEM. Negotiate logging requirements in service provider contracts and validate that log coverage meets enterprise security monitoring needs."
  },
  {
    id: "9.1",
    title: "Ensure Use of Only Fully Supported Browsers and Email Clients",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Ensure only fully supported browsers and email clients are allowed to execute in the enterprise, only using the latest version of browsers and email clients provided through the vendor. Unsupported browsers and email clients do not receive security patches, leaving known vulnerabilities unaddressed and exposing the enterprise to exploitation through routine web browsing and email usage.",
    implementation: "Maintain a list of approved browser and email client versions and enforce their use through application control policies or endpoint management configurations. Configure automated browser and email client updates through enterprise patch management or built-in auto-update mechanisms. Monitor endpoint compliance for outdated browser and email client versions and block or flag non-compliant installations for remediation."
  },
  {
    id: "9.2",
    title: "Use DNS Filtering Services",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Use DNS filtering services on all enterprise assets to block access to known malicious domains. DNS filtering provides a network-level control that prevents connections to malicious infrastructure regardless of the application or protocol used, offering broad protection against malware, phishing, and command-and-control communications.",
    implementation: "Configure enterprise DNS resolvers or deploy cloud-based DNS filtering services that block resolution of domains categorized as malicious, phishing, or newly registered with insufficient reputation. Apply DNS filtering to all network segments including guest and IoT networks, and configure endpoint DNS settings to prevent bypass of enterprise DNS controls. Review DNS filtering block logs regularly to identify trends and tune policies to reduce false positives while maintaining security coverage."
  },
  {
    id: "9.3",
    title: "Maintain and Enforce Network-Based URL Filters",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Enforce and update network-based URL filters to limit an enterprise asset from connecting to potentially malicious or unapproved websites. Example implementations include category-based filtering, reputation-based filtering, or through the use of block lists. URL filtering provides granular control over web access beyond DNS-level blocking, enabling policy enforcement at the full URL level including path and parameter inspection.",
    implementation: "Deploy secure web gateways or next-generation firewalls with URL filtering capabilities configured to block categories associated with security risk such as malware, phishing, newly registered domains, and anonymizers. Enable HTTPS inspection where legally and technically feasible to extend URL filtering to encrypted traffic. Establish a process for users to request exceptions for blocked legitimate sites, with security review before approval."
  },
  {
    id: "9.4",
    title: "Restrict Unnecessary or Unauthorized Browser and Email Client Extensions",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Restrict, either through uninstalling or disabling, any unauthorized or unnecessary browser or email client plugins, extensions, and add-on applications. Browser extensions can access sensitive data including credentials and browsing history, and malicious or compromised extensions have been used in numerous attacks to steal data or inject malicious content.",
    implementation: "Use browser management policies through group policy or endpoint management to define an allowlist of approved extensions and block all others from being installed. Audit currently installed browser extensions across the environment and remove unauthorized extensions through endpoint management actions. Educate users on the risks of browser extensions and provide an approved extension request process for legitimate business needs."
  },
  {
    id: "9.5",
    title: "Implement DMARC",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Implement DMARC to lower the chance of spoofed or modified emails from valid domains. Begin by implementing a DMARC policy of none on the enterprise domain before moving to quarantine and then reject as anomalies are resolved. DMARC, along with SPF and DKIM, provides a technical mechanism to verify email sender authenticity and reduce the effectiveness of phishing campaigns using spoofed enterprise domains.",
    implementation: "Publish SPF, DKIM, and DMARC DNS records for all enterprise email domains, starting with a DMARC policy of p=none to monitor authentication results without impacting mail delivery. Analyze DMARC aggregate and forensic reports to identify legitimate email sources that need SPF/DKIM alignment before progressively tightening the policy to quarantine and then reject. Ensure all authorized email sending services including marketing platforms, ticketing systems, and transactional email providers are properly authenticated through SPF includes and DKIM signing."
  },
  {
    id: "9.6",
    title: "Block Unnecessary File Types",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Block unnecessary file types attempting to enter the enterprise email gateway. Blocking dangerous attachment types at the email gateway prevents common malware delivery mechanisms such as executable files, script files, and malicious document types from reaching end users. This reduces reliance on endpoint controls and user awareness as the sole defense.",
    implementation: "Configure the email security gateway to block high-risk attachment types including executables, scripts, shortcut files, ISO images, and other file types commonly used for malware delivery based on both file extension and content type analysis. Implement file type analysis that inspects file headers rather than relying solely on extensions to prevent simple extension-renaming bypass techniques. Maintain and regularly update the blocked file type list based on current threat intelligence and emerging attack techniques."
  },
  {
    id: "9.7",
    title: "Deploy and Maintain Email Server Anti-Malware Protections",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Deploy and maintain email server anti-malware protections such as attachment scanning and sandboxing. Email remains the most common initial attack vector for malware and ransomware delivery. Server-side anti-malware scanning provides a critical layer of defense before malicious content reaches end-user devices.",
    implementation: "Deploy email security solutions that scan all inbound and outbound email attachments using multi-engine anti-malware scanning and behavioral sandboxing to detect zero-day threats. Configure the solution to quarantine suspicious attachments for analysis before delivery and alert the security team on confirmed malicious content. Integrate email security telemetry with the SIEM and incident response workflow to enable rapid investigation of email-borne threats that may have reached users before detection."
  },
  {
    id: "10.1",
    title: "Deploy and Maintain Anti-Malware Software",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Deploy and maintain anti-malware software on all enterprise assets. Anti-malware software provides real-time protection against known and emerging malware threats through signature-based detection, heuristic analysis, and behavioral monitoring on endpoints.",
    implementation: "Deploy enterprise anti-malware or endpoint protection platform (EPP) agents on all workstations and servers, managed through a centralized console that provides visibility into deployment coverage, detection events, and agent health. Configure real-time protection including on-access scanning, behavior monitoring, and exploit prevention, with automatic signature updates at least daily. Monitor deployment coverage against the asset inventory to identify and remediate gaps where protection is missing."
  },
  {
    id: "10.2",
    title: "Configure Automatic Anti-Malware Signature Updates",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Configure automatic updates for anti-malware signature files on all enterprise assets. Outdated signatures significantly reduce the effectiveness of anti-malware software by failing to detect recently identified malware variants. Automatic updates ensure that protection remains current without relying on manual intervention.",
    implementation: "Configure anti-malware agents to check for and apply signature updates at least daily, with the ability to perform more frequent checks during active threat campaigns. Distribute updates through enterprise update distribution points to reduce bandwidth consumption and ensure availability even when internet connectivity is limited. Monitor signature currency across the environment and alert on agents with signatures older than 48 hours for investigation."
  },
  {
    id: "10.3",
    title: "Disable Autorun and Autoplay for Removable Media",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Disable autorun and autoplay auto-execute functionality for removable media. Autorun and autoplay allow automatic execution of programs on removable media when connected, which has been a well-known malware propagation vector. Disabling these features prevents malware from automatically executing when users insert USB drives or other removable media.",
    implementation: "Deploy group policy settings on Windows systems to disable autorun and autoplay for all drive types including removable media, network drives, and optical media. Verify the settings are enforced through endpoint compliance checks and cannot be overridden by local administrators. Apply equivalent controls on non-Windows platforms where removable media auto-execution capabilities exist."
  },
  {
    id: "10.4",
    title: "Configure Automatic Anti-Malware Scanning of Removable Media",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Configure anti-malware software to automatically scan removable media. Removable media can introduce malware to the enterprise network by bypassing perimeter defenses. Automatic scanning of removable media provides a defense layer that detects malicious files on external storage before they can be executed or spread to network shares.",
    implementation: "Configure endpoint protection software to perform automatic on-access scanning of all files on removable media when mounted, including USB drives, external hard drives, and optical media. Enable the setting through the centralized anti-malware management console and verify enforcement through policy compliance reporting. Consider additional DLP controls that restrict removable media usage to approved, encrypted devices for users who require portable storage."
  },
  {
    id: "10.5",
    title: "Enable Anti-Exploitation Features",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Enable anti-exploitation features on enterprise assets and software where possible such as Microsoft Data Execution Prevention (DEP), Windows Defender Exploit Guard (WDEG), or Apple System Integrity Protection (SIP) and Gatekeeper. Anti-exploitation features protect against memory corruption attacks, code injection, and other exploitation techniques used to compromise applications and operating systems even when specific vulnerability patches are not yet available.",
    implementation: "Enable Windows Defender Exploit Guard with attack surface reduction rules, controlled folder access, and exploit protection on all Windows endpoints through group policy or Intune. Configure System Integrity Protection and Gatekeeper on macOS systems and ensure they are not disabled by administrators. Deploy address space layout randomization, stack canaries, and other OS-level exploit mitigations on Linux systems through kernel parameter configuration and compiler flags."
  },
  {
    id: "10.6",
    title: "Centrally Manage Anti-Malware Software",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Centrally manage anti-malware software. Centralized management enables consistent policy deployment, unified threat visibility, coordinated response actions, and comprehensive reporting on malware detection and prevention across the entire enterprise.",
    implementation: "Deploy and configure a centralized anti-malware management console that provides unified policy management, alerting, and reporting across all protected endpoints. Establish tiered alert handling procedures where common detections are auto-remediated while advanced threats trigger security analyst investigation. Generate regular reports on detection trends, coverage gaps, and agent health for security management review."
  },
  {
    id: "10.7",
    title: "Use Behavior-Based Anti-Malware Software",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Use behavior-based anti-malware software on all enterprise assets. Behavior-based detection identifies malicious activity by analyzing the actions of processes rather than relying solely on known signatures, providing protection against zero-day threats, fileless malware, and polymorphic malware that evade traditional signature-based detection.",
    implementation: "Deploy endpoint detection and response (EDR) solutions that use behavioral analysis, machine learning, and threat intelligence to detect malicious activity patterns such as credential access, lateral movement, and data staging. Configure behavioral detection policies to monitor for techniques mapped to the MITRE ATT&CK framework and tune detection sensitivity to balance security coverage with operational false positive rates. Integrate EDR telemetry with the SIEM and threat intelligence platforms for enhanced correlation and automated response capabilities."
  },
  {
    id: "11.1",
    title: "Establish and Maintain a Data Recovery Process",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a data recovery process. In the process, address the scope of data recovery activities, recovery prioritization, and the security of backup data. Review and update documentation annually, or when significant enterprise changes occur that could impact this safeguard. A documented recovery process ensures consistent and timely restoration of critical data and systems following disruption.",
    implementation: "Document a comprehensive data recovery policy that defines recovery point objectives and recovery time objectives for each data criticality tier, assigns backup and recovery responsibilities, and specifies backup security requirements including encryption and access control. Align the recovery process with the business continuity plan and ensure that recovery priorities reflect current business impact assessments. Review and update the policy annually, after significant infrastructure changes, and after any recovery exercise or actual recovery event."
  },
  {
    id: "11.2",
    title: "Perform Automated Backups",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Perform automated backups of in-scope enterprise assets. Run backups weekly or more frequently based on the sensitivity and criticality of the enterprise asset. Automated backups ensure reliable, consistent data protection without depending on manual processes that may be forgotten or executed inconsistently.",
    implementation: "Configure automated backup schedules for all in-scope assets using enterprise backup solutions, with frequency aligned to defined RPO targets, typically daily for most assets and more frequent for critical databases and systems. Implement incremental backup strategies to optimize storage and bandwidth while maintaining the ability to perform full restores. Monitor backup job completion and alert on failures, ensuring that backup operators investigate and resolve failures within the same business day."
  },
  {
    id: "11.3",
    title: "Protect Recovery Data",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Protect recovery data with equivalent controls to the original data. Reference encryption or data separation based on requirements of the enterprise data management process. Backup data contains the same sensitive information as production data and must be protected with equivalent security controls to prevent it from becoming an easier target for data theft.",
    implementation: "Encrypt all backup data both in transit and at rest using strong encryption with keys managed separately from the backup infrastructure. Implement access controls on backup systems and repositories that are at least as restrictive as production data access controls, with separate administrative accounts for backup management. Store encryption keys for backup data in a key management system that is independent of the backup infrastructure to prevent a single compromise from exposing both backups and keys."
  },
  {
    id: "11.4",
    title: "Establish and Maintain an Isolated Instance of Recovery Data",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain an isolated instance of recovery data using physically separate storage media or cloud-based solutions. This is sometimes referred to as an air-gapped backup. Isolated recovery data protects against ransomware and destructive attacks that target both production systems and connected backup repositories, ensuring that at least one copy of data survives a complete environment compromise.",
    implementation: "Maintain at least one backup copy on storage that is physically or logically isolated from the production network and primary backup infrastructure, such as offline tape, immutable cloud storage, or an air-gapped vault. Configure immutability settings on cloud backup storage to prevent modification or deletion even by administrators for a defined retention period. Test restoration from isolated backups regularly to verify data integrity and ensure that recovery procedures work when the primary backup infrastructure is unavailable."
  },
  {
    id: "11.5",
    title: "Test Data Recovery",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Test backup recovery quarterly, or more frequently, for a sampling of in-scope enterprise assets. Backup restoration testing validates that backup data is complete, uncorrupted, and that recovery procedures work as expected. Untested backups provide false confidence and may fail when needed most during an actual recovery scenario.",
    implementation: "Establish a quarterly backup restoration testing schedule that rotates through different system types and data classifications to achieve broad coverage over the course of a year. Document each test including the systems restored, time to recover, data integrity validation results, and any issues encountered during the process. Track restoration test results over time to identify trends and improve recovery procedures and documentation based on lessons learned."
  },
  {
    id: "12.1",
    title: "Ensure Network Infrastructure is Up-to-Date",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Ensure network infrastructure is kept up-to-date. Example implementations include running the latest stable release of software and/or using currently supported network-as-a-service (NaaS) offerings. Review software versions monthly, or more frequently, to verify software support. Network devices running outdated firmware contain known vulnerabilities that can be exploited to gain control of critical infrastructure components.",
    implementation: "Maintain a network device inventory that tracks current firmware versions and maps them to vendor support timelines and known vulnerability advisories. Establish a monthly review cadence comparing installed firmware versions against vendor-recommended releases and security advisories. Implement a network device patching process with change management controls including testing in lab environments before production deployment."
  },
  {
    id: "12.2",
    title: "Establish and Maintain a Secure Network Architecture",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a secure network architecture. A secure network architecture must address segmentation, least privilege, and availability at a minimum. A well-designed network architecture limits the blast radius of security incidents through segmentation while ensuring that legitimate business communications can flow efficiently and reliably.",
    implementation: "Design the network architecture with clearly defined security zones separated by firewalls, implementing a defense-in-depth model with DMZ segments for internet-facing services, internal segments for business operations, and restricted segments for sensitive data processing. Document the network architecture including zone definitions, allowed traffic flows, and segmentation enforcement points, and maintain the documentation as a living artifact updated with all changes. Conduct periodic architecture reviews against current threats and business requirements to identify needed improvements."
  },
  {
    id: "12.3",
    title: "Securely Manage Network Infrastructure",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Securely manage network infrastructure. Example implementations include version-controlled infrastructure-as-code and the use of secure network protocols such as SSH and HTTPS. Insecure management of network infrastructure can lead to unauthorized configuration changes, credential interception, and compromise of network devices that control traffic flow.",
    implementation: "Restrict network device management access to dedicated management VLANs or out-of-band management networks accessible only from authorized jump servers. Use only encrypted management protocols such as SSH, HTTPS, and SNMPv3, disabling Telnet, HTTP, and SNMPv1/v2c on all network devices. Store network device configurations in version control and implement change management workflows requiring peer review and approval before configuration changes are applied."
  },
  {
    id: "12.4",
    title: "Establish and Maintain Architecture Diagram(s)",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and maintain architecture diagram(s) and/or other network documentation. Review and update documentation annually, or when significant enterprise changes occur that could impact this safeguard. Accurate network documentation is essential for effective security operations, incident response, and change management, enabling teams to understand data flows and identify potential attack paths.",
    implementation: "Create and maintain detailed network architecture diagrams that document all network segments, interconnections, firewall placement, traffic flow directions, and external connectivity points. Use standardized diagramming tools and notation, store diagrams in a centralized repository accessible to security and operations teams, and assign ownership for keeping each diagram current. Include both logical and physical topology views, and update diagrams as part of the change management process for any network modifications."
  },
  {
    id: "12.5",
    title: "Centralize Network Authentication, Authorization, and Auditing (AAA)",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Centralize network AAA. Centralized AAA for network devices provides consistent authentication policies, unified authorization based on role, and comprehensive audit trails across all network infrastructure. It eliminates the security risks of managing local accounts on individual network devices.",
    implementation: "Implement RADIUS or TACACS+ servers integrated with the enterprise directory service for all network device authentication and authorization, eliminating reliance on locally configured accounts except for emergency break-glass access. Configure authorization profiles that map directory group memberships to specific network device privilege levels, enforcing least privilege. Enable accounting on all AAA servers and forward logs to the SIEM for monitoring of network device access and administrative actions."
  },
  {
    id: "12.6",
    title: "Use of Secure Network Management and Communication Protocols",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Use secure network management and communication protocols such as 802.1X, Wi-Fi Protected Access 3 (WPA3) Enterprise or greater. Use of insecure network protocols exposes management credentials and configuration data to interception and enables man-in-the-middle attacks that can compromise network infrastructure or intercept sensitive communications.",
    implementation: "Deploy 802.1X network access control on both wired and wireless networks, authenticating devices and users before granting network access based on identity and device compliance. Configure enterprise wireless networks with WPA3-Enterprise or at minimum WPA2-Enterprise with strong cipher suites, and disable any legacy wireless security modes. Verify that all network management protocols in use are encrypted and authenticated, and audit network configurations for any remaining insecure protocol usage."
  },
  {
    id: "12.7",
    title: "Ensure Remote Devices Utilize a VPN and are Connecting to an Enterprise's AAA Infrastructure",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Require users to authenticate to enterprise-managed VPN and authentication infrastructure prior to accessing enterprise resources on end-user devices. VPN connectivity ensures that remote device communications are encrypted and that remote users are authenticated through the enterprise AAA infrastructure before accessing internal resources, maintaining security controls for remote work scenarios.",
    implementation: "Deploy enterprise VPN solutions that require authentication through the centralized identity provider with MFA enforcement before granting access to internal network resources. Configure split-tunnel or full-tunnel VPN based on security requirements, with full tunnel preferred for devices accessing sensitive resources. Implement always-on VPN configurations or conditional access policies that require VPN connectivity before enterprise applications and data can be accessed from remote locations."
  },
  {
    id: "12.8",
    title: "Establish and Maintain Dedicated Computing Resources for All Administrative Work",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Establish and maintain dedicated computing resources, either physically or logically separated, for all administrative tasks or tasks requiring administrative access. The computing resources should be segmented from the enterprise primary network and not be allowed internet access. Privileged access workstations reduce the risk of credential theft by isolating administrative activities from general-purpose computing where exposure to phishing, malware, and web-based attacks is highest.",
    implementation: "Deploy dedicated privileged access workstations (PAWs) for all personnel performing administrative tasks, configured with hardened operating systems, restricted internet access, and limited application installations. Implement network segmentation that restricts PAWs to management network segments with access only to administrative interfaces of target systems. Use conditional access policies to enforce that administrative actions can only be performed from registered PAWs, blocking administrative authentication from general-purpose workstations."
  },
  {
    id: "13.1",
    title: "Centralize Security Event Alerting",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Centralize security event alerting across enterprise assets for log correlation and analysis. Best practice implementation requires the use of a SIEM which includes vendor-defined event correlation alerts. A centralized alerting system correlates events across multiple sources to detect attack patterns that would be invisible when viewing individual log sources in isolation.",
    implementation: "Deploy a SIEM platform configured to receive security events from all enterprise asset categories including endpoints, network devices, servers, cloud services, and identity providers. Enable vendor-provided correlation rules and alert templates as a baseline, then customize and tune rules based on the enterprise threat landscape and common false positive patterns. Establish alert triage procedures that prioritize investigation of correlated alerts and define escalation paths for confirmed security incidents."
  },
  {
    id: "13.2",
    title: "Deploy a Host-Based Intrusion Detection Solution",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Deploy a host-based intrusion detection solution on enterprise assets where appropriate and supported. Host-based intrusion detection monitors system-level activity including file integrity, registry changes, and process behavior to detect malicious actions that may bypass network-level controls, providing visibility into threats operating within the host.",
    implementation: "Deploy host-based intrusion detection capabilities through EDR agents or dedicated HIDS solutions on all servers and critical workstations, configured to monitor file integrity of critical system files, registry changes, and suspicious process activity. Tune detection rules to the specific role of each system, applying stricter monitoring on servers processing sensitive data. Integrate host-based detection alerts with the centralized SIEM for correlation with network-level events."
  },
  {
    id: "13.3",
    title: "Deploy a Network Intrusion Detection Solution",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Deploy a network intrusion detection solution on enterprise assets where appropriate. Example implementations include the use of a network intrusion detection system (NIDS) or equivalent cloud service provider (CSP) service. Network intrusion detection provides visibility into malicious traffic patterns, exploitation attempts, and lateral movement activity traversing the network.",
    implementation: "Deploy NIDS sensors or cloud-native network detection capabilities at key network chokepoints including internet egress, inter-segment boundaries, and in front of critical server segments. Configure detection rules using vendor-provided signatures supplemented by custom rules based on enterprise-specific threat intelligence and known attack patterns. Feed NIDS alerts into the SIEM for correlation and establish investigation procedures for network-based alerts."
  },
  {
    id: "13.4",
    title: "Perform Traffic Filtering Between Network Segments",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Perform traffic filtering between network segments where appropriate. Traffic filtering between segments enforces the security architecture by restricting lateral movement, ensuring that compromised systems in one segment cannot freely communicate with systems in other segments without traversing security inspection points.",
    implementation: "Implement firewall rules or access control lists at all inter-segment boundaries that allow only documented and authorized traffic flows, following a default-deny approach. Define allowed traffic based on documented application dependencies and data flow diagrams, blocking all unnecessary inter-segment communication. Review and audit inter-segment firewall rules quarterly to remove stale rules and ensure alignment with the current network architecture."
  },
  {
    id: "13.5",
    title: "Manage Access Control for Remote Assets",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Manage access control for assets remotely connecting to enterprise resources. Determine amount of access to enterprise resources based on up-to-date anti-malware software installed, configuration compliance with the enterprise secure configuration process, and ensuring the operating system and applications are up-to-date. Remote device posture assessment ensures that devices connecting from outside the enterprise perimeter meet minimum security requirements before being granted access to enterprise resources.",
    implementation: "Deploy network access control or zero-trust network access solutions that evaluate device posture including OS patch level, anti-malware status, and configuration compliance before granting access to enterprise resources. Implement tiered access policies where non-compliant devices receive limited access to remediation resources while fully compliant devices receive appropriate role-based access. Continuously monitor device posture throughout the session and revoke or restrict access if the device falls out of compliance."
  },
  {
    id: "13.6",
    title: "Collect Network Traffic Flow Logs",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Collect network traffic flow logs and/or network traffic to review and alert upon from network devices. Network flow data provides metadata about communications between systems including source, destination, protocol, ports, and volume, enabling detection of anomalous traffic patterns, data exfiltration, and command-and-control communications without the overhead of full packet capture.",
    implementation: "Enable NetFlow, sFlow, or IPFIX on core network devices and configure export to a centralized flow collection and analysis platform. Create baseline traffic profiles for normal network behavior and configure alerts for deviations such as unusual data volumes, communication with unexpected destinations, or use of uncommon protocols and ports. Retain flow data for at least 90 days to support incident investigation and historical analysis."
  },
  {
    id: "13.7",
    title: "Deploy a Host-Based Intrusion Prevention Solution",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Deploy a host-based intrusion prevention solution on enterprise assets where appropriate and supported. Example implementations include use of an Endpoint Detection and Response (EDR) client or host-based IPS agent. Host-based intrusion prevention actively blocks malicious activity detected on the host, providing automated response capabilities that stop attacks in progress without waiting for human intervention.",
    implementation: "Deploy EDR or HIPS agents in prevention mode on all enterprise endpoints and servers, configured to automatically block detected malicious behaviors such as credential dumping, process injection, and ransomware file encryption patterns. Tune prevention policies carefully, testing in detection-only mode before enabling blocking to avoid disrupting legitimate operations. Establish rapid response procedures for prevention events that may indicate an active attack requiring broader investigation."
  },
  {
    id: "13.8",
    title: "Deploy a Network Intrusion Prevention Solution",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Deploy a network intrusion prevention solution where appropriate. Example implementations include the use of a network intrusion prevention system (NIPS) or equivalent CSP service. Network intrusion prevention actively blocks malicious network traffic in-line, stopping exploitation attempts and malware communications before they reach target systems.",
    implementation: "Deploy inline network intrusion prevention at key network boundaries including internet ingress/egress and in front of critical server segments, configured to block known attack signatures and anomalous traffic patterns. Tune IPS policies to the specific traffic profile of each deployment point to minimize false positives that could disrupt legitimate traffic. Maintain IPS signatures with automatic updates and supplement vendor signatures with custom rules based on threat intelligence relevant to the enterprise."
  },
  {
    id: "13.9",
    title: "Deploy Port-Level Access Control",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Deploy port-level access control. Port-level access control utilizes 802.1X, or similar network access control (NAC) protocols such as certificates, and may incorporate user and/or device authentication. Port-level access control prevents unauthorized devices from connecting to the network at the physical layer, ensuring that only authenticated and authorized devices can communicate on enterprise network segments.",
    implementation: "Implement 802.1X port-based access control on all wired network access ports, authenticating connecting devices against the enterprise directory using machine certificates or user credentials. Configure dynamic VLAN assignment based on device type and user role to place authenticated devices on appropriate network segments automatically. Implement MAC Authentication Bypass for devices that do not support 802.1X, such as printers and IoT devices, with placement on restricted network segments."
  },
  {
    id: "13.10",
    title: "Perform Application Layer Filtering",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Perform application layer filtering. Example implementations include a filtering proxy, application layer firewall, or gateway. Application layer filtering inspects traffic content at the application level rather than just network headers, enabling detection and blocking of threats embedded within permitted protocols such as malicious files within HTTP or exploitation attempts within application-specific protocols.",
    implementation: "Deploy next-generation firewalls or web application firewalls configured to perform deep packet inspection and application-level traffic analysis at network boundaries and in front of web-facing applications. Configure application identification policies that recognize and control traffic by application regardless of port number, blocking unauthorized applications and enforcing usage policies. Enable SSL/TLS inspection at application layer filtering points to maintain visibility into encrypted traffic where legally and technically appropriate."
  },
  {
    id: "13.11",
    title: "Tune Security Event Alerting Thresholds",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Tune security event alerting thresholds monthly, or more frequently. Alert tuning optimizes the signal-to-noise ratio of security monitoring by reducing false positives that waste analyst time while ensuring that true positive alerts are not missed due to overly permissive thresholds or poorly configured rules.",
    implementation: "Establish a monthly alert tuning cycle where security analysts review alert volumes, false positive rates, and missed detection reports to identify rules requiring adjustment. Implement a feedback loop where investigation outcomes inform alert tuning, suppressing known benign patterns while expanding detection for observed attack techniques. Document tuning decisions including the rationale for each change and maintain version control of detection rules to enable rollback if tuning changes inadvertently reduce detection capability."
  },
  {
    id: "14.1",
    title: "Establish and Maintain a Security Awareness Program",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a security awareness program. The purpose of a security awareness program is to educate the enterprise workforce on how to interact with enterprise assets and data in a secure manner. Conduct the training at hire and at a minimum annually. Review and update content annually, or when significant enterprise changes occur that could impact this safeguard.",
    implementation: "Develop a comprehensive security awareness program that covers topics including phishing recognition, password hygiene, data handling, social engineering, physical security, and incident reporting. Deliver training through a combination of methods including online modules, in-person sessions, and periodic micro-learning campaigns to accommodate different learning styles and maintain engagement. Track training completion rates and target 100% compliance through automated reminders and management escalation for non-compliant employees."
  },
  {
    id: "14.2",
    title: "Train Workforce Members to Recognize Social Engineering Attacks",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Train workforce members to recognize social engineering attacks such as phishing, pre-texting, and tailgating. Social engineering remains the most common initial attack vector, and training employees to recognize and report these attacks is one of the most effective defenses. Training should cover current attack techniques and provide realistic examples relevant to the enterprise.",
    implementation: "Deliver focused social engineering awareness training that covers phishing emails, vishing phone calls, smishing text messages, pretexting, and physical social engineering such as tailgating and impersonation. Supplement formal training with regular simulated phishing campaigns that measure susceptibility rates and provide immediate coaching to employees who engage with simulated attacks. Share anonymized examples of real social engineering attempts targeting the enterprise to make training content directly relevant and engaging."
  },
  {
    id: "14.3",
    title: "Train Workforce Members on Authentication Best Practices",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Train workforce members on authentication best practices. Example topics include MFA, password composition, and credential management. Training should explain why authentication controls matter and provide practical guidance on using enterprise-provided tools such as password managers and MFA applications correctly.",
    implementation: "Include authentication best practices in the onboarding training and annual refresher program, covering topics such as creating strong unique passwords, using the enterprise password manager, enrolling in and using MFA, recognizing MFA fatigue attacks, and never sharing credentials. Provide hands-on guidance during training sessions on setting up authenticator apps, registering security keys, and using the password manager effectively. Reinforce training through regular communications when new authentication features are deployed or authentication-related threats emerge."
  },
  {
    id: "14.4",
    title: "Train Workforce on Data Handling Best Practices",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Train workforce members on how to identify and properly store, transfer, archive, and destroy sensitive data. This also includes training workforce members on clear screen and clear desk best practices such as locking their screen when they step away from their enterprise asset, erasing physical and virtual whiteboards at the end of meetings, and not leaving sensitive data in plain sight.",
    implementation: "Develop role-specific data handling training that covers the enterprise data classification scheme, proper storage locations for each classification level, approved methods for sharing sensitive data, and secure disposal procedures. Include practical scenarios and real-world examples demonstrating consequences of improper data handling such as regulatory fines, breach notifications, and reputational damage. Assess comprehension through quizzes and periodic audits of data handling practices in the workplace."
  },
  {
    id: "14.5",
    title: "Train Workforce Members on Causes of Unintentional Data Exposure",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Train workforce members to be aware of causes for unintentional data exposure. Example topics include mis-delivery of sensitive data, losing a portable end-user device, or publishing data to unintended audiences. Unintentional data exposure through human error causes a significant portion of data breaches and can be reduced through awareness of common mistake patterns.",
    implementation: "Include training on common unintentional exposure scenarios such as email misdirection, accidental public sharing of cloud documents, loss of unencrypted portable devices, and inadvertent disclosure in public venues or social media. Teach practical verification steps such as double-checking email recipients before sending sensitive information and verifying sharing permissions on cloud documents. Share anonymized examples of actual unintentional exposures within the enterprise to demonstrate how easily these incidents can occur."
  },
  {
    id: "14.6",
    title: "Train Workforce Members on Recognizing and Reporting Security Incidents",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Train workforce members to be able to recognize a potential incident and be able to report such an incident. Early detection and reporting of security incidents by frontline employees can significantly reduce the impact of an attack by enabling faster response. Employees should know what constitutes a potential security incident and how to report one through established channels.",
    implementation: "Train all employees on how to identify indicators of potential security incidents including unexpected pop-ups, suspicious emails, unusual system behavior, unauthorized access attempts, and social engineering contacts. Provide clear, easy-to-remember reporting channels such as a dedicated security hotline, email alias, or chat channel, and ensure employees know they will not be penalized for good-faith reports. Recognize and reward employees who report genuine security incidents or phishing attempts to reinforce a positive security culture."
  },
  {
    id: "14.7",
    title: "Train Workforce on How to Identify and Report if Their Enterprise Assets are Missing Security Updates",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Train workforce to understand how to verify and report out-of-date software patches or any failures in automated processes and tools. End users can serve as an additional detection layer for systems that may have fallen through gaps in automated patch management, helping to identify and remediate vulnerable systems faster.",
    implementation: "Include guidance in security awareness training on how employees can check their device patch status through the enterprise endpoint management portal or built-in system update tools. Provide a simple reporting mechanism for employees to flag devices that appear to be missing updates or displaying update error messages. Create quick-reference guides showing how to verify patch status on each platform in use and distribute them through the enterprise intranet."
  },
  {
    id: "14.8",
    title: "Train Workforce on the Dangers of Connecting to and Transmitting Enterprise Data Over Insecure Networks",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Train workforce members on the dangers of connecting to, and transmitting data over, insecure networks for enterprise activities. If the enterprise has remote workers and/or a mobile workforce, training should include guidance to ensure that all users securely configure their home network infrastructure. Insecure networks expose enterprise data to interception and man-in-the-middle attacks.",
    implementation: "Educate employees on the risks of using public Wi-Fi, unsecured home networks, and unencrypted connections for enterprise activities, emphasizing the importance of VPN usage when working remotely. Provide specific guidance on securing home network routers including changing default passwords, enabling WPA3 encryption, updating firmware, and disabling remote management. Distribute a home network security checklist and offer IT support resources for employees who need help securing their remote work environment."
  },
  {
    id: "14.9",
    title: "Conduct Role-Specific Security Awareness and Skills Training",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Conduct role-specific security awareness and skills training. Example implementations include secure system administration courses for IT professionals, OWASP Top 10 vulnerability awareness and prevention training for developers, or advanced social engineering awareness training for high-profile roles. Generic security training is insufficient for roles with specific security responsibilities; role-specific training addresses the unique threats and required competencies for specialized positions.",
    implementation: "Identify roles with elevated security responsibilities or unique threat profiles and develop targeted training curricula, such as secure coding training for developers, incident response procedures for SOC analysts, and executive-targeted social engineering awareness for senior leadership. Partner with specialized training providers for technical security training and track completion through learning management system integrations. Assess effectiveness through role-specific exercises such as capture-the-flag events for technical staff and tabletop exercises for incident responders."
  },
  {
    id: "15.1",
    title: "Establish and Maintain an Inventory of Service Providers",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain an inventory of service providers. The inventory is to list all known service providers, include classification(s), and designate an enterprise contact for each service provider. Review and update the inventory annually, or when significant enterprise changes occur that could impact this safeguard. A comprehensive service provider inventory enables effective management of third-party risk across the enterprise supply chain.",
    implementation: "Catalog all service providers including cloud services, SaaS applications, managed services, outsourced functions, and professional services in a centralized third-party risk management register. Document the classification of data each provider accesses or processes, the enterprise relationship owner, contract terms, and security assessment status. Integrate the service provider inventory with procurement workflows to ensure new providers are registered before onboarding and reviewed before contract renewal."
  },
  {
    id: "15.2",
    title: "Establish and Maintain a Service Provider Management Policy",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a service provider management policy. Ensure the policy addresses the classification, inventory, assessment, monitoring, and decommissioning of service providers. Review and update the policy annually, or when significant enterprise changes occur that could impact this safeguard. A formal policy provides a consistent framework for managing security risk introduced through third-party relationships throughout the engagement lifecycle.",
    implementation: "Develop a third-party risk management policy that defines requirements for service provider security assessments, contractual security provisions, ongoing monitoring, incident notification obligations, and secure decommissioning procedures. Establish risk-tiered assessment requirements where providers accessing sensitive data undergo more rigorous evaluation than those providing low-risk services. Assign policy ownership to a dedicated third-party risk management function and ensure the policy is socialized with procurement, legal, and business unit stakeholders."
  },
  {
    id: "15.3",
    title: "Classify Service Providers",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Classify service providers. Classification consideration may include one or more characteristics such as data sensitivity, data volume, availability requirements, applicable regulations, inherent risk, and mitigated risk. Update and review classifications annually, or when significant enterprise changes occur that could impact this safeguard. Service provider classification enables risk-proportionate security requirements and assessment rigor.",
    implementation: "Develop a service provider classification framework that categorizes providers into risk tiers based on the sensitivity of data they access, the criticality of services they provide, their access to enterprise networks, and applicable regulatory requirements. Apply the classification framework to all providers in the inventory and use the resulting tier to determine the depth of security assessment, contractual requirements, and ongoing monitoring frequency. Review classifications annually and reclassify when there are material changes to the service scope or data access."
  },
  {
    id: "15.4",
    title: "Ensure Service Provider Contracts Include Security Requirements",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Ensure service provider contracts include security requirements. Example requirements may include minimum security program requirements, security incident and/or data breach notification and response, data encryption requirements, and data disposal commitments. Contractual security requirements establish legally enforceable security obligations and provide the enterprise with the ability to hold providers accountable for security performance.",
    implementation: "Develop standardized security contract clauses and addenda for inclusion in all service provider agreements, covering areas such as data protection, access controls, vulnerability management, incident notification timelines, audit rights, and subcontractor management. Work with legal and procurement to ensure security requirements are included in new contracts and renewals, with clause severity scaled to the provider risk classification. Maintain a library of approved security contract language and update it as security standards and regulatory requirements evolve."
  },
  {
    id: "15.5",
    title: "Assess Service Providers",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Assess service providers consistent with the enterprise service provider management policy. Assessment scope may vary based on classification(s) and may include review of standardized assessment reports such as SOC 2 and SIG Lite, custom questionnaires, or other appropriately rigorous processes. Reassess service providers annually, at a minimum, or with new and renewed contracts. Security assessments validate that service providers meet enterprise security requirements and identify risks that require mitigation.",
    implementation: "Conduct initial security assessments of all new service providers before contract execution, with assessment rigor aligned to the provider risk classification, ranging from self-assessment questionnaires for low-risk providers to on-site audits for critical providers. Review independent assessment reports such as SOC 2 Type II, ISO 27001 certifications, and penetration test results as part of the evaluation. Track assessment findings and require remediation of identified gaps within agreed timelines, with reassessment performed annually or upon contract renewal."
  },
  {
    id: "15.6",
    title: "Monitor Service Providers",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Monitor service providers consistent with the enterprise service provider management policy. Monitoring may include periodic reassessment of service provider compliance, monitoring service provider release notes, and dark web monitoring. Ongoing monitoring ensures that service provider security posture does not degrade between formal assessments and enables early detection of security issues that could affect the enterprise.",
    implementation: "Implement continuous monitoring of critical service providers through a combination of automated security rating services, periodic compliance attestation reviews, and monitoring of provider security advisories and breach notifications. Subscribe to threat intelligence feeds that monitor for service provider compromises, data exposures, and dark web mentions of provider credentials or data. Establish escalation procedures for significant changes in provider security posture that may require immediate assessment or remediation actions."
  },
  {
    id: "15.7",
    title: "Securely Decommission Service Providers",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Securely decommission service providers. Example considerations include user and service account deactivation, termination of data flows, and secure disposal of enterprise data within the service provider environment. Improper decommissioning can leave enterprise data exposed in provider environments and active integrations that create ongoing security risk after the business relationship has ended.",
    implementation: "Develop a service provider decommissioning checklist covering revocation of all access credentials, API keys, and network connectivity, verification of enterprise data deletion or return, and termination of all data processing agreements. Coordinate decommissioning activities with IT, security, legal, and the business relationship owner to ensure comprehensive coverage of all integration points. Obtain written confirmation of data destruction from the provider and verify through the audit rights established in the service agreement where appropriate."
  },
  {
    id: "16.1",
    title: "Establish and Maintain a Secure Application Development Process",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a secure application development process. In the process, address such items as secure application design standards, secure coding practices, developer training, vulnerability management, security of third-party code, and application security testing procedures. Review and update documentation annually, or when significant enterprise changes occur that could impact this safeguard.",
    implementation: "Document a secure software development lifecycle (SSDLC) that integrates security activities into each phase from requirements through deployment, including threat modeling during design, secure coding standards during development, and security testing before release. Provide developers with secure coding training specific to the languages and frameworks in use and maintain coding standards documentation as a living reference. Review and update the SSDLC annually based on lessons learned from security incidents, vulnerability trends, and industry best practice evolution."
  },
  {
    id: "16.2",
    title: "Establish and Maintain a Process to Accept and Address Software Vulnerabilities",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a process to accept and address reports of software vulnerabilities, including providing a means for external entities to report. The process is to include such items as a vulnerability handling policy that identifies reporting process, responsible party for handling vulnerability reports, and a process for intake, assignment, remediation, and remediation verification. A formal vulnerability disclosure process enables responsible reporting of security issues by researchers and users, leading to faster identification and remediation of software flaws.",
    implementation: "Publish a vulnerability disclosure policy on the enterprise website that provides clear instructions for external researchers to report security vulnerabilities, including a dedicated security contact email and expected response timelines. Establish an internal vulnerability triage process that assigns reported vulnerabilities to development teams based on affected components, prioritizes remediation based on severity and exploitability, and tracks resolution through completion. Consider implementing a bug bounty program for externally-facing applications to incentivize responsible disclosure and expand the pool of security testers."
  },
  {
    id: "16.3",
    title: "Perform Root Cause Analysis on Security Vulnerabilities",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Perform root cause analysis on security vulnerabilities. When reviewing vulnerabilities, root cause analysis is the task of evaluating underlying issues that create vulnerabilities in code and allows development teams to move beyond just fixing individual vulnerabilities as they arise. Root cause analysis identifies systemic weaknesses in development practices, enabling preventative improvements that reduce the rate of future vulnerabilities.",
    implementation: "Require root cause analysis documentation for all high and critical severity vulnerabilities discovered in enterprise-developed software, identifying the coding pattern, design decision, or process gap that led to the vulnerability. Aggregate root cause data across vulnerabilities to identify patterns and systemic issues, feeding findings back into secure coding training content and development standards. Track whether root cause remediation actions such as framework changes, library updates, or training initiatives effectively reduce the recurrence of similar vulnerability types."
  },
  {
    id: "16.4",
    title: "Establish and Manage an Inventory of Third-Party Software Components",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and manage an updated inventory of third-party components used in development, often referred to as a bill of materials, as well as components planned for future use. This inventory is to include any risks that each third-party component could pose. Evaluate the security of third-party components and their maintenance status, and determine whether to update, fork, or replace them. A software bill of materials enables rapid response when vulnerabilities are disclosed in third-party components and supports license compliance management.",
    implementation: "Implement software composition analysis (SCA) tools integrated into CI/CD pipelines that automatically generate and maintain a software bill of materials for each application, identifying all third-party libraries, frameworks, and components with their versions. Configure SCA tools to alert on known vulnerabilities in third-party components and block builds that include components with critical unresolved vulnerabilities. Establish governance procedures for evaluating new third-party component adoption including security assessment, license review, and maintenance activity evaluation."
  },
  {
    id: "16.5",
    title: "Use Up-to-Date and Trusted Third-Party Software Components",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Use up-to-date and trusted third-party software components. When possible, choose established and proven frameworks and libraries that provide adequate security. Purchase or build from trusted sources and use third-party software components from reputable repositories. Using current, well-maintained components reduces exposure to known vulnerabilities and ensures ongoing security patches are available.",
    implementation: "Configure package managers to pull dependencies exclusively from vetted private registries or mirrored repositories rather than directly from public sources. Implement dependency update automation tools that create pull requests when new versions of third-party components are available, with automated testing to validate compatibility. Establish criteria for component selection including minimum maintenance activity levels, vulnerability response history, and community or commercial support availability."
  },
  {
    id: "16.6",
    title: "Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a severity rating system and process for application vulnerabilities that facilitates prioritizing the order in which discovered vulnerabilities are fixed. This process includes setting a minimum level of security acceptable for releasing code or applications. Effort can be prioritized based on the severity and/or potential impact of the vulnerability. A consistent severity rating system ensures objective, repeatable prioritization of vulnerability remediation that aligns development resources with security risk.",
    implementation: "Adopt or adapt a vulnerability severity rating framework such as CVSS supplemented with enterprise-specific context including asset criticality, data sensitivity, and exploit availability. Define minimum security thresholds for each release stage, such as no critical or high severity findings for production releases, with a formal exception process for justified overrides. Integrate severity rating into the development workflow through automated scanning tools that assign severity ratings and enforce release gates."
  },
  {
    id: "16.7",
    title: "Use Standard Hardening Configuration Templates for Application Infrastructure",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Use standard, industry-recommended hardening configuration templates for application infrastructure components. This includes underlying servers, databases, and web servers, and applies to cloud containers, Platform-as-a-Service (PaaS) components, and SaaS components. Do not allow in-house developed software to weaken configuration hardening. Standardized hardening templates ensure consistent security baselines across the application infrastructure stack.",
    implementation: "Develop hardening templates for each application infrastructure component type based on CIS Benchmarks or vendor hardening guides, covering operating systems, web servers, application servers, databases, and container runtimes. Implement infrastructure-as-code templates that embed hardening configurations, ensuring that new infrastructure deployments are hardened by default. Validate hardening compliance through automated configuration scanning integrated into deployment pipelines and continuous compliance monitoring."
  },
  {
    id: "16.8",
    title: "Separate Production and Non-Production Systems",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Maintain separate environments for production and non-production systems. Developers should not have unmonitored access to production environments. Separating production from development and test environments prevents accidental or malicious changes to production, protects production data from unauthorized access, and ensures that untested code does not impact service availability.",
    implementation: "Implement distinct environments for development, testing, staging, and production with network segmentation and separate access controls for each. Restrict production access to operations personnel and automated deployment pipelines, requiring additional authentication and approval for any manual production access. Use synthetic or anonymized data in non-production environments rather than copies of production data to prevent sensitive data exposure in less-secured development systems."
  },
  {
    id: "16.9",
    title: "Train Developers in Application Security Concepts and Secure Coding",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Ensure that all software development personnel receive training in writing secure code for their specific development environment and responsibilities. Training can include general security principles and application security standard practices. Conduct training at least annually and design it in a way to promote security within the development team and build a culture of application security amongst the developers. Developer training on secure coding practices addresses the root cause of many application vulnerabilities by equipping developers with the knowledge to avoid introducing security flaws.",
    implementation: "Provide annual secure coding training tailored to the specific programming languages, frameworks, and platforms used by development teams, covering the OWASP Top 10 and common vulnerability patterns relevant to the technology stack. Supplement formal training with hands-on learning through secure coding exercises, capture-the-flag competitions, and code review pairing sessions between developers and security engineers. Track training completion and measure effectiveness through metrics such as vulnerability density trends in developed applications."
  },
  {
    id: "16.10",
    title: "Apply Secure Design Principles in Application Architectures",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Apply secure design principles in application architectures. Secure design principles include the concept of least privilege and enforcing mediation to validate every operation that the user makes, promoting the concept of never trusting user input. Examples include ensuring that explicit error checking is performed and documented for all input, including for size, data type, and acceptable ranges or formats. Secure design principles also include the concept of attack surface minimization. Building security into application architecture from the design phase is more effective and less costly than retrofitting security controls after development.",
    implementation: "Integrate threat modeling into the application design process for all new applications and significant feature additions, using methodologies such as STRIDE or PASTA to identify and mitigate design-level security risks. Establish architectural security patterns and reference architectures for common application types that embed security best practices including input validation, output encoding, authentication, authorization, and error handling. Review application architecture designs through a security architecture review board before development begins to catch and correct design flaws early."
  },
  {
    id: "16.11",
    title: "Leverage Vetted Modules or Services for Application Security Components",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Leverage vetted modules or services for application security components such as identity management, encryption, and auditing and logging. Using well-tested, vetted security components instead of custom implementations reduces the likelihood of introducing vulnerabilities through incorrect implementation of complex security functions like cryptography and authentication. Vetted modules benefit from broader security review and testing than custom code typically receives.",
    implementation: "Maintain an approved library of vetted security modules covering authentication, authorization, input validation, cryptography, session management, and logging that development teams are required to use rather than building custom implementations. Evaluate and approve security modules through a formal review process that includes code review, vulnerability history assessment, and penetration testing. Provide developer documentation and code examples demonstrating proper integration of approved security modules into common application patterns."
  },
  {
    id: "16.12",
    title: "Implement Code-Level Security Checks",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Apply static and dynamic analysis tools within the application lifecycle to verify that secure coding practices are being followed. Static analysis examines source code without execution to identify potential vulnerabilities, while dynamic analysis tests running applications to discover runtime security issues. Automated code-level security checks provide consistent, scalable vulnerability detection that catches issues before they reach production.",
    implementation: "Integrate static application security testing (SAST) tools into the CI/CD pipeline to automatically scan code for security vulnerabilities on every commit or pull request, with findings reported directly to developers. Deploy dynamic application security testing (DAST) tools to scan running applications in staging environments before production deployment, testing for runtime vulnerabilities such as injection flaws and authentication bypasses. Establish quality gates that prevent code with high-severity findings from progressing through the pipeline without remediation or documented exception."
  },
  {
    id: "16.13",
    title: "Conduct Application Penetration Testing",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Conduct application penetration testing. For critical applications, penetration testing is done annually. At a minimum, this is a black-box or gray-box testing in which an assessor has no or limited prior knowledge of the application. Penetration testing simulates real-world attacks against applications to discover vulnerabilities that automated tools may miss and validate the effectiveness of security controls under realistic conditions.",
    implementation: "Engage qualified penetration testers to perform annual assessments of critical applications, providing them with appropriate access levels based on the desired testing depth ranging from black-box external testing to gray-box testing with authenticated access. Scope penetration tests to cover the OWASP Testing Guide methodology including authentication, authorization, session management, input validation, and business logic testing. Track penetration test findings through the vulnerability management process with defined remediation SLAs and verify fixes through retesting."
  },
  {
    id: "16.14",
    title: "Conduct Threat Modeling",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Conduct threat modeling. Threat modeling is the process of identifying and addressing application security design flaws within a design, before code is created. It is conducted through specially trained individuals who evaluate the application design and gauge security risks for each entry point and access level. The goal is to map out the application, architecture, and infrastructure in a structured way to understand its weaknesses. Threat modeling identifies design-level security issues that cannot be found through code analysis or testing alone.",
    implementation: "Train development and security teams on threat modeling methodologies such as STRIDE, PASTA, or attack trees, and integrate threat modeling as a mandatory activity in the design phase of all new applications and major feature additions. Use threat modeling tools or structured documentation templates to systematically identify assets, trust boundaries, data flows, and potential threats for each application component. Review and update threat models when significant changes are made to application architecture, and track identified threats through remediation or acceptance with documented justification."
  },
  {
    id: "17.1",
    title: "Designate Personnel to Manage Incident Handling",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Designate one key person and at least one backup who will manage the enterprise incident handling process. Management personnel are responsible for the coordination and documentation of incident response and recovery efforts and can consist of employees internal to the enterprise, third-party vendors, or a hybrid approach. Designated incident management personnel ensure clear accountability and coordination during security incidents when rapid, organized response is critical.",
    implementation: "Formally designate a primary incident response manager and at least one backup with clearly documented roles, responsibilities, authority levels, and contact information. Ensure designated personnel have appropriate training, certifications, and experience in incident handling, and provide ongoing professional development opportunities. Publish the incident response contact chain in a readily accessible location and verify that on-call rotation schedules ensure 24/7 coverage for incident escalation."
  },
  {
    id: "17.2",
    title: "Establish and Maintain Contact Information for Reporting Security Incidents",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain contact information for parties that need to be informed of security incidents. Contacts may include internal staff, third-party vendors, law enforcement, cyber insurance providers, relevant government agencies, Information Sharing and Analysis Center (ISAC) partners, or other stakeholders. Verify contacts annually to ensure that information is up-to-date. Pre-established contact lists enable rapid notification during incidents when time is critical and communication must be precise.",
    implementation: "Maintain a comprehensive incident notification contact list that includes internal stakeholders such as executive leadership, legal counsel, communications, and IT, as well as external contacts including law enforcement, regulatory bodies, cyber insurance carriers, and relevant ISACs. Store the contact list in multiple accessible locations including printed copies in the incident response plan, a secure digital repository, and the incident management platform. Review and update the contact list quarterly and after any personnel or vendor changes."
  },
  {
    id: "17.3",
    title: "Establish and Maintain an Enterprise Process for Reporting Incidents",
    ig1: true,
    ig2: true,
    ig3: true,
    description: "Establish and maintain an enterprise process for the workforce to report security incidents. The process includes reporting timeframe, personnel to report to, mechanism for reporting, and the minimum information to be reported. Ensure the process is publicly available to all of the workforce. Review annually, or when significant enterprise changes occur that could impact this safeguard. A clear, accessible reporting process ensures that potential security incidents are communicated to the right people quickly, reducing response time.",
    implementation: "Document and publish a security incident reporting procedure that specifies what constitutes a reportable incident, the reporting timeframe, required information to include in a report, and multiple reporting channels such as phone, email, web form, and chat. Make the reporting procedure easily accessible through the enterprise intranet, security awareness training materials, and quick-reference cards distributed to all employees. Test the reporting process regularly through tabletop exercises and simulated incidents to verify that reports are received and processed correctly."
  },
  {
    id: "17.4",
    title: "Establish and Maintain an Incident Response Process",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and maintain an incident response process that addresses roles and responsibilities, compliance requirements, and a communication plan. Review annually, or when significant enterprise changes occur that could impact this safeguard. A comprehensive incident response process ensures that the organization can respond to security incidents in a structured, repeatable manner that minimizes impact and supports legal and regulatory obligations.",
    implementation: "Develop a detailed incident response plan aligned with NIST SP 800-61 or a similar framework covering preparation, detection and analysis, containment, eradication, recovery, and post-incident activities. Define specific roles and responsibilities for each incident response team member, escalation criteria and timelines, evidence preservation procedures, and internal and external communication protocols. Review and update the incident response plan annually, after significant incidents, and after organizational changes that affect response capabilities."
  },
  {
    id: "17.5",
    title: "Assign Key Roles and Responsibilities",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Assign key roles and responsibilities for incident response, including staff from legal, IT, information security, facilities, public relations, human resources, incident responders, and analysts as applicable. Review annually, or when significant enterprise changes occur that could impact this safeguard. Cross-functional role assignments ensure that all aspects of incident response are covered, from technical investigation to legal obligations and public communications.",
    implementation: "Document a RACI matrix for incident response activities that maps specific responsibilities to named individuals or roles across all relevant departments including security, IT, legal, HR, communications, and executive leadership. Ensure that all assigned personnel understand their incident response responsibilities through annual training and participation in tabletop exercises. Maintain backup personnel for all critical incident response roles and verify that role documentation is current and accessible during incidents."
  },
  {
    id: "17.6",
    title: "Define Mechanisms for Communicating During Incident Response",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Determine which primary and secondary mechanisms will be used to communicate and report during a security incident. Mechanisms can include phone calls, emails, or letters. Keep in mind that certain mechanisms such as emails may be affected during a security incident. In-band communication channels may be compromised during an incident, making pre-planned out-of-band communication mechanisms essential for maintaining coordination during response.",
    implementation: "Establish primary and backup communication channels for incident response that include out-of-band options not dependent on enterprise email or network infrastructure, such as dedicated phone bridges, encrypted messaging applications, or satellite communications for severe scenarios. Document communication protocols specifying which channels to use for different severity levels and audience types, including templates for executive briefings, technical team coordination, and external notifications. Test communication channels during incident response exercises to verify availability and accessibility under simulated incident conditions."
  },
  {
    id: "17.7",
    title: "Conduct Routine Incident Response Exercises",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Plan and conduct routine incident response exercises and scenarios for key personnel involved in the incident response process to prepare for handling real-world incidents. Exercises need to test communication channels, decision-making, and workflows. Conduct testing on an annual basis, at a minimum. Regular exercises build muscle memory, identify gaps in the incident response plan, and improve team coordination before a real incident occurs.",
    implementation: "Conduct at least annual tabletop exercises involving all key incident response stakeholders, using realistic scenarios based on current threat intelligence and recent industry incidents. Supplement tabletop exercises with more technical exercises such as purple team engagements or simulated incident drills where security analysts practice detection, analysis, and containment in a controlled environment. Document lessons learned from each exercise and track remediation of identified gaps in the incident response plan, procedures, tools, or skills."
  },
  {
    id: "17.8",
    title: "Conduct Post-Incident Reviews",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Conduct post-incident reviews. Post-incident reviews help prevent incident recurrence through identifying lessons learned and follow-up action items. Post-incident reviews also provide a structured opportunity to identify what worked well, what needs improvement, and what systemic changes would prevent similar incidents in the future.",
    implementation: "Require post-incident reviews for all significant security incidents within 10 business days of incident closure, involving all key participants from the response effort. Structure reviews to cover timeline reconstruction, root cause analysis, effectiveness of detection and response procedures, communication effectiveness, and specific improvement recommendations. Track post-incident action items through the enterprise issue tracking system and report on completion rates to security leadership."
  },
  {
    id: "17.9",
    title: "Establish and Maintain Security Incident Thresholds",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Establish and maintain security incident thresholds including at a minimum distinguishing between an incident and an event. Examples can include differentiating by severity, priority, classification, source and destination, and/or other criteria. Review annually, or when significant enterprise changes occur that could impact this safeguard. Clear thresholds ensure consistent classification and response to security events, preventing both over-response to minor events and under-response to genuine incidents.",
    implementation: "Define a security incident classification framework that establishes clear criteria for distinguishing security events from incidents and categorizes incidents by severity based on factors such as data impact, system criticality, scope of compromise, and business disruption potential. Map each severity level to specific response procedures, escalation requirements, notification obligations, and target response timelines. Train all security operations personnel on the classification framework and review classifications during post-incident reviews to ensure thresholds remain appropriate."
  },
  {
    id: "18.1",
    title: "Establish and Maintain a Penetration Testing Program",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Establish and maintain a penetration testing program appropriate to the size, complexity, and maturity of the enterprise. Penetration testing program characteristics include scope, such as network, web application, Application Programming Interface (API), hosted services, and physical premise controls; frequency; limitations such as acceptable hours and excluded attack types; point of contact information; remediation such as how findings will be routed internally; and retrospective requirements. A formal penetration testing program ensures systematic, repeatable evaluation of enterprise security controls through simulated adversary techniques.",
    implementation: "Document a penetration testing program charter that defines scope covering external and internal networks, applications, wireless, and social engineering, along with testing frequency, rules of engagement, qualified tester requirements, and finding remediation processes. Establish a minimum annual testing cadence for external network and critical application assessments, with additional testing triggered by significant infrastructure changes or after major security incidents. Integrate penetration testing findings with the vulnerability management process and track remediation against defined SLAs."
  },
  {
    id: "18.2",
    title: "Perform Periodic External Penetration Tests",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Perform periodic external penetration tests based on program requirements, no less than annually. External penetration tests must include both broad and targeted, and should include attempts to identify and exploit weaknesses and vulnerabilities across the enterprise perimeter. External penetration tests simulate real-world attacks from the internet against the enterprise perimeter, identifying exploitable vulnerabilities that could provide initial access to an attacker.",
    implementation: "Engage qualified external penetration testing firms to conduct annual assessments that simulate realistic adversary techniques against the enterprise internet-facing attack surface including network services, web applications, VPN gateways, and email infrastructure. Ensure test scope covers the complete external footprint including cloud-hosted services, CDN-fronted applications, and partner-accessible portals. Remediate critical and high findings within 30 days and verify remediation through retesting before closing findings."
  },
  {
    id: "18.3",
    title: "Remediate Penetration Test Findings",
    ig1: false,
    ig2: true,
    ig3: true,
    description: "Remediate penetration test findings based on the enterprise policy for remediation scope and prioritization. Penetration testing is only valuable if identified vulnerabilities are actually remediated. Findings should be tracked through the established vulnerability management process with remediation timelines aligned to the severity and exploitability of each finding.",
    implementation: "Integrate penetration test findings into the enterprise vulnerability management platform and assign remediation to appropriate system owners with timelines based on the vulnerability severity rating and asset criticality. Track remediation progress through regular status meetings and escalate overdue items through management channels. Schedule retesting of remediated findings to validate that fixes are effective and have not introduced new vulnerabilities."
  },
  {
    id: "18.4",
    title: "Validate Security Measures",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Validate security measures after each penetration test. If deemed necessary, modify rulesets and capabilities to detect the techniques used during testing on an ongoing basis. Penetration test results should be used to improve detective and preventive controls, closing gaps that allowed testers to succeed and strengthening the overall security posture beyond just fixing specific vulnerabilities.",
    implementation: "After each penetration test, review the attack techniques used and verify that security monitoring tools detected the testing activity, investigating and remediating any detection gaps. Update SIEM correlation rules, IDS/IPS signatures, and EDR detection policies to identify the techniques that were not detected during testing. Document security control improvements made based on penetration test results and validate their effectiveness in subsequent testing cycles."
  },
  {
    id: "18.5",
    title: "Perform Periodic Internal Penetration Tests",
    ig1: false,
    ig2: false,
    ig3: true,
    description: "Perform periodic internal penetration tests based on program requirements, no less than annually. The testing may be clear box or opaque box. Internal penetration testing simulates an attacker who has gained initial access to the internal network, evaluating the effectiveness of internal segmentation, access controls, and detection capabilities against lateral movement and privilege escalation.",
    implementation: "Conduct annual internal penetration tests that simulate post-compromise scenarios including lateral movement, privilege escalation, and access to sensitive data from an assumed breach starting point on the internal network. Test from multiple starting positions representing different compromise scenarios such as a compromised workstation, a guest network device, or a VPN-connected remote worker. Use internal penetration test results to validate network segmentation effectiveness, identify overly permissive access controls, and test the security operations team ability to detect internal threat activity."
  }
];

const PCI_DSS_V4 = [
  // ============================================================
  // REQUIREMENT 1: Install and Maintain Network Security Controls
  // ============================================================
  {
    id: "1.1.1",
    title: "All security policies and operational procedures identified in Requirement 1 are documented, kept up to date, in use, and known to all affected parties",
    description: "Organizations must maintain formal documentation of all network security policies and operational procedures. These documents must be reviewed periodically, updated when the environment changes, and distributed to all relevant personnel. Without current documentation, security controls may be inconsistently applied or misunderstood.",
    testingProcedure: "Examine documentation to verify that security policies and operational procedures for Requirement 1 are documented, dated, and signed off by management. Interview personnel to confirm they are aware of and follow the documented policies and procedures."
  },
  {
    id: "1.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 1 are documented, assigned, and understood",
    description: "Specific roles and responsibilities for managing network security controls must be formally assigned and documented. Personnel assigned these roles must understand their responsibilities and have the authority and resources to fulfill them. This ensures accountability and prevents gaps in security control management.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for activities in Requirement 1 are explicitly assigned. Interview responsible personnel to confirm they understand their assigned roles and responsibilities."
  },
  {
    id: "1.2.1",
    title: "Configuration standards for network security controls are defined, implemented, and maintained",
    description: "Network security control configuration standards must be established and documented for all types of network security controls in use. These standards must specify allowed services, protocols, and ports, along with justification for each. The standards ensure consistent and secure configuration across the entire cardholder data environment.",
    testingProcedure: "Examine configuration standards for network security controls and verify they address all elements specified in this requirement. Compare actual configurations of network security controls against the documented standards to verify they are implemented as defined."
  },
  {
    id: "1.2.2",
    title: "All changes to network connections and to configurations of network security controls are approved and managed in accordance with the change control process defined at Requirement 6.5.1",
    description: "All changes to network connections and network security control configurations must follow a formal change management process. This includes documenting the business justification, obtaining proper authorization, and testing changes before deployment. Uncontrolled changes to network configurations are a common cause of security breaches.",
    testingProcedure: "Examine change control records for network security control configurations and verify that changes are formally authorized and documented. Verify that changes include business justification, testing results, and management sign-off prior to implementation."
  },
  {
    id: "1.2.3",
    title: "An accurate network diagram is maintained that shows all connections between the cardholder data environment and other networks, including any wireless networks",
    description: "A current and accurate network diagram must document all connections to and from the cardholder data environment, including connections to wireless networks, third-party networks, and the internet. The diagram must be kept up to date and reviewed whenever network changes occur. Accurate diagrams are essential for understanding data flows and identifying potential security gaps.",
    testingProcedure: "Examine the network diagram and verify it accurately reflects all connections between the CDE and other networks. Interview network administrators and compare the diagram to the actual network topology to confirm accuracy and completeness."
  },
  {
    id: "1.2.4",
    title: "An accurate data-flow diagram is maintained that meets the following: shows all account data flows across systems and networks, and is updated as needed upon changes to the environment",
    description: "A data-flow diagram must document all flows of account data across systems and networks, including ingress, processing, storage, and egress points. The diagram must be updated whenever changes to data flows occur to ensure it remains accurate. Understanding data flows is critical to ensuring all locations where account data is present are adequately protected.",
    testingProcedure: "Examine the data-flow diagram and verify it documents all flows of account data. Compare the diagram to actual system configurations and interview personnel to confirm it accurately represents current data flows."
  },
  {
    id: "1.2.5",
    title: "All services, protocols, and ports allowed are identified, approved, and have a defined business need",
    description: "All services, protocols, and ports permitted through network security controls must be explicitly identified and documented with an associated business justification. Insecure services, protocols, and ports must have additional security features documented and implemented. This prevents unnecessary network exposure that could be exploited by attackers.",
    testingProcedure: "Examine documentation of approved services, protocols, and ports and verify each has a defined business need. Compare the documented list against actual network security control configurations to ensure only approved traffic is permitted."
  },
  {
    id: "1.2.6",
    title: "Security features are defined and implemented for all services, protocols, and ports that are in use and considered to be insecure",
    description: "Where insecure services, protocols, or ports are in use, additional security features must be defined and implemented to mitigate the associated risks. This includes using encryption for data transmitted over insecure protocols and implementing additional monitoring. The risk of using insecure services must be formally accepted by management with documented compensating controls.",
    testingProcedure: "Examine documentation to identify insecure services, protocols, and ports in use and the security features implemented to address their risks. Examine system configurations to verify the documented security features are implemented and functioning."
  },
  {
    id: "1.2.7",
    title: "Configurations of network security controls are reviewed at least once every six months to confirm they are relevant and effective",
    description: "Network security control configurations must be formally reviewed at least every six months to ensure rules remain relevant and effective. The review must identify and remove any obsolete or unnecessary rules. Regular reviews prevent rule bloat and ensure the network security posture remains aligned with business requirements.",
    testingProcedure: "Examine documentation of network security control reviews and verify reviews occur at least every six months. Verify that reviews result in the identification and removal of obsolete or unnecessary rules."
  },
  {
    id: "1.2.8",
    title: "Configuration files for network security controls are secured from unauthorized access and kept consistent with active network configurations",
    description: "Configuration files for network security controls such as firewalls and routers must be secured to prevent unauthorized access or modification. Running configurations must be synchronized with startup configurations to ensure consistency after a reboot. Unsecured configuration files could allow attackers to understand and bypass network security controls.",
    testingProcedure: "Examine configuration file access controls and verify they are restricted to authorized personnel only. Compare running and startup configurations to verify they are synchronized and consistent."
  },
  {
    id: "1.3.1",
    title: "Inbound traffic to the cardholder data environment is restricted to only necessary traffic and all other traffic is specifically denied",
    description: "Network security controls must be configured to restrict inbound traffic to the cardholder data environment to only that which is necessary for authorized business purposes. All other inbound traffic must be explicitly denied by default. This principle of least privilege at the network level minimizes the attack surface of the CDE.",
    testingProcedure: "Examine network security control configurations and verify that inbound traffic to the CDE is restricted to only necessary and documented traffic. Verify that a default deny rule exists for all other inbound traffic."
  },
  {
    id: "1.3.2",
    title: "Outbound traffic from the cardholder data environment is restricted to only necessary traffic and all other traffic is specifically denied",
    description: "Network security controls must be configured to restrict outbound traffic from the cardholder data environment to only that which is necessary for authorized business purposes. All other outbound traffic must be explicitly denied by default. Restricting outbound traffic helps prevent data exfiltration and limits the ability of attackers to communicate with command-and-control servers.",
    testingProcedure: "Examine network security control configurations and verify that outbound traffic from the CDE is limited to only necessary and documented traffic. Verify that a default deny rule exists for all other outbound traffic."
  },
  {
    id: "1.3.3",
    title: "Network security controls are installed between all wireless networks and the cardholder data environment, and these controls are configured to deny or control only authorized traffic",
    description: "Network security controls must be deployed between any wireless networks and the cardholder data environment regardless of the stated purpose of the wireless network. Wireless traffic must be filtered so that only authorized traffic can pass between wireless networks and the CDE. Wireless networks are inherently less secure and require additional controls to protect the CDE.",
    testingProcedure: "Examine network diagrams and network security control configurations to verify controls exist between all wireless networks and the CDE. Verify that the controls are configured to permit only authorized traffic between wireless networks and the CDE."
  },
  {
    id: "1.4.1",
    title: "Network security controls are implemented between trusted and untrusted networks",
    description: "Network security controls must be deployed at boundaries between trusted internal networks and untrusted external networks, such as the internet. These controls must enforce access control policies to protect internal systems from external threats. The boundary protection must include both inbound and outbound filtering to control traffic flow.",
    testingProcedure: "Examine network diagrams and configurations to verify that network security controls are implemented at all boundaries between trusted and untrusted networks. Verify that the controls are actively filtering traffic according to defined security policies."
  },
  {
    id: "1.4.2",
    title: "Inbound traffic from untrusted networks to trusted networks is restricted to communications with system components that are authorized to provide publicly accessible services, protocols, and ports",
    description: "Inbound traffic from untrusted networks must only be permitted to reach system components in a DMZ or equivalent that provide publicly accessible services. Direct inbound traffic from untrusted networks to the internal trusted network or CDE must be prohibited. This layered approach ensures that even if a publicly accessible component is compromised, the attacker does not have direct access to the CDE.",
    testingProcedure: "Examine network security control configurations to verify that inbound traffic from untrusted networks is restricted to system components providing publicly accessible services. Verify that no direct connections are permitted from untrusted networks to the CDE or internal trusted network."
  },
  {
    id: "1.4.3",
    title: "Anti-spoofing measures are implemented to detect and block forged source IP addresses from entering the trusted network",
    description: "Network security controls must include anti-spoofing measures to prevent packets with forged source addresses from entering the trusted network. Ingress filtering should be implemented to verify that the source address of incoming packets is valid and expected. IP address spoofing is commonly used in denial-of-service attacks and to bypass access controls.",
    testingProcedure: "Examine network security control configurations to verify that anti-spoofing measures such as ingress filtering are implemented. Test the effectiveness of the anti-spoofing controls by attempting to send packets with spoofed source addresses."
  },
  {
    id: "1.4.4",
    title: "System components that store cardholder data are not directly accessible from untrusted networks",
    description: "System components that store cardholder data must not be placed in network segments that are directly accessible from untrusted networks like the internet. Such systems must be located in internal network segments protected by multiple layers of network security controls. This defense-in-depth approach ensures that compromising a single control does not expose stored cardholder data.",
    testingProcedure: "Examine network diagrams and configurations to verify that systems storing cardholder data are not directly accessible from untrusted networks. Trace network paths from untrusted networks to verify that multiple layers of network security controls separate untrusted networks from stored cardholder data."
  },
  {
    id: "1.4.5",
    title: "The disclosure of internal IP addresses and routing information is limited to only authorized parties",
    description: "Internal IP addresses and routing information must not be disclosed to external or unauthorized parties. Techniques such as network address translation, proxy servers, and DNS restrictions should be employed to prevent the exposure of internal network topology. Disclosure of internal addressing enables attackers to map the internal network and plan targeted attacks.",
    testingProcedure: "Examine network security control configurations to verify that measures are in place to restrict disclosure of internal IP addresses and routing information. Test from external networks to confirm that internal addressing details are not exposed."
  },
  {
    id: "1.5.1",
    title: "Security controls are implemented on any computing devices that connect to both untrusted networks and the CDE, to prevent threats from being introduced into the entity's network",
    description: "Computing devices that connect to both untrusted networks and the CDE, such as employee laptops or mobile devices, must have security controls to prevent threats from being introduced. These controls include personal firewalls, endpoint protection, and host-based intrusion detection. Dual-homed devices represent a significant risk because they can serve as a bridge for attackers to reach the CDE.",
    testingProcedure: "Examine policies and configurations for computing devices that connect to both untrusted networks and the CDE. Verify that personal firewall or equivalent controls are active, not alterable by the user, and configured to deny unauthorized traffic."
  },

  // ============================================================
  // REQUIREMENT 2: Apply Secure Configurations to All System Components
  // ============================================================
  {
    id: "2.1.1",
    title: "All security policies and operational procedures identified in Requirement 2 are documented, kept up to date, in use, and known to all affected parties",
    description: "All security policies and operational procedures related to secure configurations must be formally documented, periodically reviewed, and kept current. These documents must be distributed and accessible to all personnel responsible for system configuration. This ensures consistent application of secure configuration standards across the environment.",
    testingProcedure: "Examine documentation to verify that security policies and operational procedures for Requirement 2 exist, are current, and are signed off by management. Interview personnel to confirm they are aware of and follow the documented policies."
  },
  {
    id: "2.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 2 are documented, assigned, and understood",
    description: "Specific roles and responsibilities related to applying secure configurations must be formally assigned and documented. Personnel must understand their responsibilities for maintaining secure configurations and be held accountable. This prevents gaps in configuration management that could lead to security vulnerabilities.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for Requirement 2 activities are explicitly assigned. Interview assigned personnel to confirm they understand their responsibilities."
  },
  {
    id: "2.2.1",
    title: "Configuration standards are developed, implemented, and maintained for all system components that address all known security vulnerabilities and are consistent with industry-accepted system hardening standards",
    description: "System configuration standards must be developed for all types of system components in the environment, based on industry-accepted hardening guidelines such as CIS benchmarks, NIST, or vendor recommendations. These standards must address all known security vulnerabilities and be updated as new vulnerabilities are discovered. Standardized configurations reduce the attack surface of system components.",
    testingProcedure: "Examine system configuration standards and verify they are based on industry-accepted hardening sources. Compare actual system configurations to the documented standards to verify compliance."
  },
  {
    id: "2.2.2",
    title: "Vendor default accounts are managed as follows: if the vendor default account(s) will be used, the default password is changed, and if the vendor default account(s) will not be used, the account is removed or disabled",
    description: "All vendor-supplied default accounts must be addressed before a system is deployed into the environment. Default passwords must be changed to strong, unique passwords, or the default accounts must be removed or disabled if they are not needed. Default accounts and passwords are well-known to attackers and represent one of the easiest paths for unauthorized access.",
    testingProcedure: "Examine vendor documentation and system configurations to identify all vendor default accounts. Verify that default passwords have been changed or that unused default accounts have been removed or disabled."
  },
  {
    id: "2.2.3",
    title: "Primary functions requiring different security levels are managed to ensure that only one primary function exists on each system component, or that primary functions with differing security levels are isolated",
    description: "Each system component should perform only one primary function to prevent functions that require different security levels from coexisting on the same system. If multiple functions must exist on a single system, they must be isolated from each other to prevent a compromise of one function from affecting another. This principle of separation of duties at the system level limits the impact of a security breach.",
    testingProcedure: "Examine system configurations to verify that each system component performs only one primary function or that functions with different security levels are properly isolated. Interview system administrators to confirm the rationale for any multi-function systems."
  },
  {
    id: "2.2.4",
    title: "Only necessary services, protocols, daemons, and functions are enabled, and all unnecessary functionality is removed or disabled",
    description: "System components must be configured to enable only those services, protocols, daemons, and functions that are required for the system to perform its defined role. All unnecessary services, protocols, and functionality must be removed or disabled. Reducing the number of running services minimizes the potential attack surface.",
    testingProcedure: "Examine system configurations and verify that only necessary services, protocols, and daemons are enabled. Verify that all unnecessary functionality has been removed or disabled and that enabled services are documented with business justification."
  },
  {
    id: "2.2.5",
    title: "If any insecure services, protocols, or daemons are present, business justification is documented, and additional security features are documented and implemented that reduce the risk of using insecure services, protocols, or daemons",
    description: "Where insecure services, protocols, or daemons are necessary for business operations, the business justification and associated risks must be formally documented. Additional security features must be implemented to reduce the risk, such as using encrypted tunnels or implementing additional access controls. Management must formally accept the residual risk.",
    testingProcedure: "Examine documentation of insecure services in use and verify business justification exists for each. Verify that additional security features are implemented as documented and that risk acceptance is formally recorded."
  },
  {
    id: "2.2.6",
    title: "System security parameters are configured to prevent misuse",
    description: "System security parameters must be configured to enforce security best practices and prevent misuse by users or processes. This includes settings related to password policies, session timeouts, audit logging, and access controls. Proper security parameter configuration helps enforce the principle of least privilege and maintains system integrity.",
    testingProcedure: "Examine system configuration parameters and verify they are set according to security best practices and documented standards. Test key security parameters to confirm they function as intended to prevent misuse."
  },
  {
    id: "2.2.7",
    title: "All non-console administrative access is encrypted using strong cryptography",
    description: "All administrative access to system components that does not use a physical console connection must be encrypted using strong cryptographic protocols. Technologies such as SSH, TLS, or VPN must be used for remote administration. Unencrypted administrative access can be intercepted, revealing credentials and configuration data to attackers.",
    testingProcedure: "Examine system configurations to verify that all non-console administrative access methods use strong encryption. Observe administrative sessions to confirm that encryption is active during remote management activities."
  },
  {
    id: "2.3.1",
    title: "For wireless environments connected to the CDE or transmitting account data, all wireless vendor defaults are changed at installation or are confirmed to be secure",
    description: "All wireless vendor defaults must be changed prior to deploying wireless access points in environments connected to the CDE. This includes default SSID names, encryption keys, SNMP community strings, and administrative passwords. Default wireless settings are widely known and easily exploitable by attackers using readily available tools.",
    testingProcedure: "Examine wireless access point configurations and verify that vendor default settings have been changed. Verify that default SSID names, encryption keys, SNMP strings, and passwords have been replaced with secure values."
  },
  {
    id: "2.3.2",
    title: "For wireless environments connected to the CDE or transmitting account data, wireless encryption keys are changed whenever personnel with knowledge of the keys leave the company or change roles",
    description: "Wireless encryption keys must be changed whenever any personnel who had knowledge of the keys leave the organization or transfer to a different role that no longer requires access. This prevents former or transferred personnel from using their knowledge to gain unauthorized access to the wireless network. Key rotation procedures should be documented and followed consistently.",
    testingProcedure: "Examine key management procedures and records to verify that wireless encryption keys are changed when personnel with key knowledge depart or change roles. Interview personnel to confirm the key change process is followed."
  },

  // ============================================================
  // REQUIREMENT 3: Protect Stored Account Data
  // ============================================================
  {
    id: "3.1.1",
    title: "All security policies and operational procedures identified in Requirement 3 are documented, kept up to date, in use, and known to all affected parties",
    description: "All policies and procedures for protecting stored account data must be documented, current, actively enforced, and communicated to all relevant personnel. Documentation must be reviewed and updated when changes to the data storage environment occur. Comprehensive documentation ensures that all personnel understand their responsibilities for protecting stored data.",
    testingProcedure: "Examine documentation to verify that all Requirement 3 policies and procedures exist, are current, and are signed off by management. Interview personnel to confirm awareness and adherence to the documented policies."
  },
  {
    id: "3.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 3 are documented, assigned, and understood",
    description: "Specific roles and responsibilities for protecting stored account data must be formally assigned and documented. Personnel assigned these roles must be qualified and understand their responsibilities. Clear role assignment ensures accountability for the protection of stored account data.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for Requirement 3 activities are assigned. Interview responsible personnel to confirm understanding of their duties."
  },
  {
    id: "3.2.1",
    title: "Account data storage is kept to a minimum through implementation of data retention and disposal policies, procedures, and processes",
    description: "The organization must define data retention requirements that limit storage amount and retention time to only what is required for legal, regulatory, or business purposes. A quarterly process must identify and securely delete stored account data that exceeds defined retention requirements. Minimizing stored data reduces the scope and impact of a potential data breach.",
    testingProcedure: "Examine data retention policies and verify they define retention periods and disposal requirements. Examine storage locations and verify that stored account data does not exceed the defined retention period and that quarterly deletion processes are documented."
  },
  {
    id: "3.3.1",
    title: "Sensitive authentication data (SAD) is not retained after authorization, even if encrypted, unless there is a documented and justified business need, and the data is stored securely",
    description: "Sensitive authentication data including full track data, card verification codes, and PINs must not be stored after transaction authorization is complete. Even encrypted SAD must not be retained unless there is an explicit business need documented with justification and risk acceptance. The prohibition against storing SAD after authorization is one of the most fundamental PCI DSS requirements.",
    testingProcedure: "Examine data stores and system configurations to verify that sensitive authentication data is not retained after authorization. For any exceptions, verify documented business justification and secure storage mechanisms."
  },
  {
    id: "3.3.1.1",
    title: "The full contents of any track from the magnetic stripe on the back of the card are not retained upon completion of the authorization process",
    description: "Full track data from the magnetic stripe must not be stored after the authorization process is complete. Track data contains the cardholder name, primary account number, expiration date, and service code, all of which can be used to create counterfeit cards. Any system that processes track data must be verified to not retain this data after authorization.",
    testingProcedure: "Examine data stores, system logs, and history files to verify that full track data is not retained after authorization. Examine incoming and outgoing transaction data to verify track data is not stored at any point after authorization."
  },
  {
    id: "3.3.1.2",
    title: "The card verification code or value (three-digit or four-digit number printed on the front or back of a payment card) is not retained upon completion of the authorization process",
    description: "The card verification code (CVV2, CVC2, CID, or CAV2) must not be stored after the authorization process is complete. This code is used specifically for card-not-present transactions to verify that the person making the transaction has physical possession of the card. Storing the verification code after authorization increases fraud risk significantly.",
    testingProcedure: "Examine data stores and system configurations to verify that card verification codes are not retained after authorization. Test payment processing systems to confirm verification codes are purged after the authorization response."
  },
  {
    id: "3.3.1.3",
    title: "The personal identification number (PIN) and the PIN block are not retained upon completion of the authorization process",
    description: "PINs and encrypted PIN blocks must not be stored after the transaction authorization is complete. PINs provide direct access to cardholder funds and their compromise can lead to immediate financial loss. Even encrypted PINs must be securely deleted after the authorization process to prevent potential decryption by attackers.",
    testingProcedure: "Examine data stores and system configurations to verify that PINs and PIN blocks are not retained after authorization. Test systems involved in PIN processing to confirm PINs are purged after the authorization response is received."
  },
  {
    id: "3.3.2",
    title: "SAD that is stored electronically prior to completion of authorization is encrypted using strong cryptography",
    description: "Any sensitive authentication data that must be stored temporarily during the authorization process must be encrypted using strong cryptography. The encryption must be implemented with industry-accepted algorithms and strong key management. This provides protection for SAD during the brief period it must exist before the authorization process completes.",
    testingProcedure: "Examine system configurations to verify that SAD stored prior to authorization completion is encrypted using strong cryptography. Verify that the encryption algorithms and key lengths meet industry standards."
  },
  {
    id: "3.3.3",
    title: "An issuer or company that supports issuing services and stores SAD has a documented business justification for storage of SAD and secures the data",
    description: "Issuers and issuing processors that have a legitimate business reason to store sensitive authentication data must document the business justification and implement appropriate security controls. The stored SAD must be encrypted using strong cryptography with proper key management. Regular reviews must verify that the business need for storing SAD continues to exist.",
    testingProcedure: "Examine documentation to verify the business justification for storing SAD and verify it is approved by management. Examine the security controls protecting stored SAD to verify they meet PCI DSS encryption and key management requirements."
  },
  {
    id: "3.4.1",
    title: "PAN is masked when displayed, such that only personnel with a legitimate business need can see more than the first six and last four digits of the PAN",
    description: "The primary account number must be masked when displayed on screens, receipts, reports, or other outputs so that only authorized personnel with a documented business need can view the full PAN. The maximum number of digits that may be displayed is the first six and last four. Masking requirements must be enforced consistently across all display channels.",
    testingProcedure: "Examine policies and system configurations to verify that PAN masking is applied wherever PAN is displayed. Verify that only roles with documented business need can access the full PAN."
  },
  {
    id: "3.4.2",
    title: "PAN is secured with strong cryptography whenever it is sent via end-user messaging technologies such as e-mail, instant messaging, SMS, chat, etc.",
    description: "When PAN is transmitted using end-user messaging technologies, it must be protected using strong cryptography. End-user messaging technologies are not designed for transmitting sensitive data and may store data in multiple locations outside the sender's control. The organization should have policies that prohibit or strictly control the transmission of PAN via these channels.",
    testingProcedure: "Examine policies regarding transmission of PAN via messaging technologies. Test messaging systems to verify that PAN is encrypted using strong cryptography when transmitted through these channels."
  },
  {
    id: "3.5.1",
    title: "PAN is rendered unreadable anywhere it is stored by using any of the following approaches: one-way hashes, truncation, index tokens, or strong cryptography",
    description: "Stored PAN must be rendered unreadable using one of the specified methods: one-way hashes based on strong cryptography, truncation preserving no more than the first six and last four digits, index tokens and pads stored separately, or strong cryptography with associated key management. This is one of the most critical controls for protecting stored cardholder data.",
    testingProcedure: "Examine data repositories and verify that PAN is rendered unreadable using one of the specified methods. Examine system configurations and cryptographic key management processes to verify the protection method is properly implemented."
  },
  {
    id: "3.5.1.1",
    title: "Hashes used to render PAN unreadable are keyed cryptographic hashes of the entire PAN, with associated key management processes and procedures",
    description: "If hashing is used to render PAN unreadable, the hashes must be keyed cryptographic hashes that use the entire PAN as input. The cryptographic keys used for hashing must be managed in accordance with Requirements 3.6 and 3.7. Simple non-keyed hashes can be vulnerable to rainbow table attacks and are not sufficient for protecting PAN.",
    testingProcedure: "Examine hashing configurations and verify that keyed cryptographic hashes are used with the entire PAN as input. Examine key management processes to verify they comply with Requirements 3.6 and 3.7."
  },
  {
    id: "3.5.1.2",
    title: "If disk-level or partition-level encryption is used to render PAN unreadable, it is implemented only as follows: on removable electronic media, or if used for non-removable electronic media, PAN is also rendered unreadable via another mechanism",
    description: "Disk-level or partition-level encryption alone is only acceptable for rendering PAN unreadable on removable electronic media such as USB drives or backup tapes. For non-removable media, disk-level encryption must be supplemented by another method such as file-level encryption or tokenization. This is because disk-level encryption decrypts data automatically when the system is running, providing no protection against a logical compromise.",
    testingProcedure: "Examine storage systems using disk-level encryption and verify that removable media uses this method appropriately. For non-removable media, verify that an additional mechanism renders PAN unreadable independently of the disk-level encryption."
  },
  {
    id: "3.5.1.3",
    title: "If disk-level or partition-level encryption is used to render PAN unreadable, it is managed independently of the native operating system's access control and authentication mechanisms",
    description: "When disk-level or partition-level encryption is used, the decryption keys must not be associated with user accounts or the operating system authentication mechanism. The encryption must be managed independently so that compromising the operating system does not automatically provide access to the decrypted data. This separation ensures that the encryption provides an independent layer of protection.",
    testingProcedure: "Examine encryption configurations and verify that decryption keys are managed independently of the operating system. Verify that accessing the encrypted data requires authentication separate from the operating system login."
  },
  {
    id: "3.6.1",
    title: "Procedures are defined and implemented to protect cryptographic keys used to protect stored account data against disclosure and misuse",
    description: "Comprehensive key management procedures must be documented and implemented for all cryptographic keys used to protect stored account data. These procedures must cover the entire key lifecycle including generation, distribution, storage, rotation, and destruction. Strong key management is essential because the security of encrypted data depends entirely on the protection of the encryption keys.",
    testingProcedure: "Examine key management procedures and verify they address all aspects of the key lifecycle. Interview key custodians to confirm procedures are followed and verify implementation of key protection mechanisms."
  },
  {
    id: "3.6.1.1",
    title: "Additional requirement for service providers only: A documented description of the cryptographic architecture is maintained that includes all algorithms, protocols, and keys used for the protection of stored account data, including key strength and expiry date",
    description: "Service providers must maintain a documented cryptographic architecture that details all cryptographic algorithms, protocols, key strengths, and key expiry dates used to protect stored account data. This documentation must be updated whenever changes occur and reviewed periodically. The cryptographic architecture documentation provides a comprehensive view of how data is protected and helps identify potential weaknesses.",
    testingProcedure: "Examine the documented cryptographic architecture and verify it includes all required elements. Verify the documentation is current and reflects the actual cryptographic implementations in use."
  },
  {
    id: "3.6.1.2",
    title: "Secret and private keys used to encrypt/decrypt stored account data are stored in one of the following forms at all times: encrypted with a key-encrypting key, within a secure cryptographic device, as at least two full-length key components or key shares",
    description: "Cryptographic keys used to protect stored account data must themselves be protected by storing them in encrypted form using a key-encrypting key, within a hardware security module or similar device, or split into at least two components held by separate custodians. The key-encrypting key must be at least as strong as the data-encrypting key. This prevents a single point of compromise from exposing the encryption keys.",
    testingProcedure: "Examine key storage mechanisms and verify that cryptographic keys are protected using one of the specified methods. Verify that key-encrypting keys are at least as strong as the keys they protect."
  },
  {
    id: "3.6.1.3",
    title: "Access to cleartext cryptographic key components is restricted to the fewest number of custodians necessary",
    description: "Access to cleartext cryptographic key components must be restricted to the minimum number of custodians necessary for key management operations. Each custodian must have a signed acknowledgment of their key custodian responsibilities. Limiting access to key components reduces the risk of unauthorized key compromise.",
    testingProcedure: "Examine access control lists and verify that access to cleartext key components is restricted to the minimum necessary custodians. Verify that signed custodian acknowledgment forms exist for all key custodians."
  },
  {
    id: "3.6.1.4",
    title: "Cryptographic keys are stored in the fewest possible locations",
    description: "Cryptographic keys must be stored in as few locations as possible to minimize the risk of compromise. Each storage location must be documented and secured. Concentrating key storage reduces the attack surface and simplifies the implementation of strong key protection controls.",
    testingProcedure: "Examine documentation of key storage locations and verify that keys are stored in the minimum number of locations. Verify that all key storage locations are properly documented and secured."
  },
  {
    id: "3.7.1",
    title: "Key management policies and procedures are implemented to include generation of strong cryptographic keys",
    description: "Cryptographic key generation must use strong random number generation and produce keys of appropriate length for the algorithm in use. Keys must be generated in a secure manner using approved key generation methods. Weak key generation can undermine even the strongest encryption algorithms.",
    testingProcedure: "Examine key generation procedures and verify that strong random number generation is used. Verify that generated keys meet the minimum key length requirements for the algorithms in use."
  },
  {
    id: "3.7.2",
    title: "Key management policies and procedures are implemented to include secure cryptographic key distribution",
    description: "Cryptographic keys must be distributed securely using methods that prevent unauthorized interception or disclosure. Keys must never be distributed in cleartext form outside of a secure cryptographic device. The distribution method must provide assurance that the key was received by the intended recipient without compromise.",
    testingProcedure: "Examine key distribution procedures and records to verify that keys are distributed securely. Verify that cleartext keys are never transmitted outside of secure cryptographic devices or key management systems."
  },
  {
    id: "3.7.3",
    title: "Key management policies and procedures are implemented to include secure cryptographic key storage",
    description: "Cryptographic keys must be stored securely at all times, whether at rest or in transit. Storage mechanisms must prevent unauthorized access to the keys and protect them from disclosure. The security of the key storage must be commensurate with the sensitivity of the data the keys protect.",
    testingProcedure: "Examine key storage mechanisms and verify they protect keys from unauthorized access. Verify that key storage meets the requirements specified in Requirement 3.6.1.2."
  },
  {
    id: "3.7.4",
    title: "Key management policies and procedures are implemented for cryptographic key changes for keys that have reached the end of their cryptoperiod",
    description: "Cryptographic keys must be retired and replaced when they reach the end of their defined cryptoperiod as determined by the organization's key management policy. The cryptoperiod must be defined based on industry best practices and the sensitivity of the data being protected. Using keys beyond their cryptoperiod increases the risk of key compromise due to cryptanalysis.",
    testingProcedure: "Examine key management procedures and verify that cryptoperiods are defined for all keys. Examine key rotation records to verify that keys are replaced at the end of their defined cryptoperiod."
  },
  {
    id: "3.7.5",
    title: "Key management policies and procedures are implemented to include the retirement, replacement, or destruction of keys as deemed necessary when the integrity of the key has been weakened or keys are suspected of being compromised",
    description: "Procedures must exist for the immediate retirement, replacement, or destruction of cryptographic keys when their integrity is weakened or compromise is suspected. This includes keys used by departed employees or keys that may have been exposed through a security incident. Timely key replacement limits the window of exposure when a key compromise is detected.",
    testingProcedure: "Examine key management procedures and verify they address key compromise scenarios. Examine records to verify that compromised or weakened keys have been promptly retired, replaced, or destroyed."
  },
  {
    id: "3.7.6",
    title: "If manual cleartext cryptographic key management operations are used by the key custodian, such operations are managed using split knowledge and dual control",
    description: "Manual cryptographic key management operations involving cleartext key material must implement split knowledge so that no single person knows the entire key, and dual control so that at least two people are required to perform key management operations. This prevents any single individual from being able to compromise the full encryption key.",
    testingProcedure: "Examine key management procedures for manual operations and verify that split knowledge and dual control are required. Interview key custodians and observe key management operations to confirm these controls are implemented."
  },
  {
    id: "3.7.7",
    title: "Key management policies and procedures are implemented to include the prevention of unauthorized substitution of cryptographic keys",
    description: "Controls must be in place to prevent the unauthorized substitution of cryptographic keys, which could allow an attacker to decrypt previously encrypted data or encrypt data with a key they control. Key integrity must be verified through mechanisms such as key checksums or digital signatures. Unauthorized key substitution can completely undermine the cryptographic protection of stored data.",
    testingProcedure: "Examine key management procedures and verify that controls exist to prevent unauthorized key substitution. Examine system configurations to verify that key integrity verification mechanisms are implemented."
  },
  {
    id: "3.7.8",
    title: "Key management policies and procedures are implemented to include that cryptographic key custodians formally acknowledge that they understand and accept their key-custodian responsibilities",
    description: "All cryptographic key custodians must formally acknowledge their understanding of and responsibilities for key management. This acknowledgment must be documented and retained. Formal acknowledgment ensures that custodians are aware of the importance of their role and the procedures they must follow.",
    testingProcedure: "Examine key custodian acknowledgment records and verify that all current custodians have signed acknowledgments. Verify that acknowledgments cover the specific responsibilities of the key custodian role."
  },
  {
    id: "3.7.9",
    title: "Additional requirement for service providers only: Where a service provider shares cryptographic keys with its customers for transmission or storage of account data, documentation is provided to customers that includes guidance on how to securely transmit, store, and update such keys",
    description: "Service providers that share cryptographic keys with customers must provide documentation describing how to securely handle those keys. The documentation must cover secure transmission, storage, and update procedures for the shared keys. This ensures that the security chain is maintained even when key management responsibilities are shared with customers.",
    testingProcedure: "Examine documentation provided to customers regarding shared cryptographic keys. Verify that the documentation includes guidance on secure key transmission, storage, and update procedures."
  },

  // ============================================================
  // REQUIREMENT 4: Protect Cardholder Data with Strong Cryptography During Transmission
  // ============================================================
  {
    id: "4.1.1",
    title: "All security policies and operational procedures identified in Requirement 4 are documented, kept up to date, in use, and known to all affected parties",
    description: "All policies and procedures for protecting cardholder data during transmission must be documented, current, and distributed to relevant personnel. These documents must be reviewed periodically and updated when the environment changes. Proper documentation ensures consistent application of transmission security controls.",
    testingProcedure: "Examine documentation to verify that all Requirement 4 policies and procedures exist and are current. Interview personnel to confirm awareness and adherence to the documented policies."
  },
  {
    id: "4.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 4 are documented, assigned, and understood",
    description: "Specific roles and responsibilities for protecting data during transmission must be formally assigned and documented. Personnel must understand their responsibilities for implementing and maintaining transmission security. Clear assignment prevents gaps in protecting data in transit.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for Requirement 4 are explicitly assigned. Interview responsible personnel to confirm understanding of their duties."
  },
  {
    id: "4.2.1",
    title: "Strong cryptography and security protocols are implemented to safeguard PAN during transmission over open, public networks",
    description: "Cardholder data must be encrypted using strong cryptography whenever it is transmitted over open, public networks such as the internet, wireless technologies, cellular networks, and satellite communications. Only trusted keys and certificates must be accepted, and the protocol in use must support only secure versions and configurations. Open, public networks are inherently insecure and interception of data is straightforward without encryption.",
    testingProcedure: "Examine system configurations and observe data transmissions to verify that strong cryptography is used for all PAN transmitted over open, public networks. Verify that only secure protocol versions and cipher suites are enabled."
  },
  {
    id: "4.2.1.1",
    title: "An inventory of the entity's trusted keys and certificates used to protect PAN during transmission is maintained",
    description: "The organization must maintain a current inventory of all trusted keys and certificates used to protect PAN during transmission over open, public networks. The inventory must be updated when changes occur and reviewed periodically. A current inventory enables the organization to quickly identify and respond to compromised certificates or expired keys.",
    testingProcedure: "Examine the inventory of trusted keys and certificates and verify it is current and complete. Compare the inventory against actual configurations to verify that all keys and certificates in use are documented."
  },
  {
    id: "4.2.1.2",
    title: "Certificates used to safeguard PAN during transmission over open, public networks are confirmed as valid and are not expired or revoked",
    description: "Digital certificates used to protect PAN during transmission must be verified to ensure they are valid, not expired, and not revoked. Certificate validation must include checking the certificate chain of trust and verifying the certificate has not been revoked by the issuing certificate authority. Using invalid or revoked certificates can expose data to interception through man-in-the-middle attacks.",
    testingProcedure: "Examine certificate validation configurations and verify that certificates are checked for validity, expiration, and revocation status. Test certificate validation by examining actual certificates in use across the environment."
  },
  {
    id: "4.2.2",
    title: "PAN is secured with strong cryptography whenever it is sent via end-user messaging technologies",
    description: "PAN must be encrypted using strong cryptography before being transmitted via end-user messaging technologies such as email, instant messaging, SMS, or chat applications. These messaging technologies often store messages in multiple locations that may not be controlled by the sender, creating additional exposure risk. Organizations should implement policies that strongly discourage the transmission of PAN via these channels.",
    testingProcedure: "Examine policies regarding PAN transmission via messaging technologies and verify strong cryptography requirements are defined. Test messaging systems to verify that PAN is encrypted when transmitted through end-user messaging channels."
  },

  // ============================================================
  // REQUIREMENT 5: Protect All Systems and Networks from Malicious Software
  // ============================================================
  {
    id: "5.1.1",
    title: "All security policies and operational procedures identified in Requirement 5 are documented, kept up to date, in use, and known to all affected parties",
    description: "All policies and procedures for protecting against malicious software must be documented, current, and distributed to all relevant personnel. These documents must address the deployment, maintenance, and monitoring of anti-malware solutions. Regular review and updates ensure the policies remain effective against evolving threats.",
    testingProcedure: "Examine documentation to verify that all Requirement 5 policies and procedures exist and are current. Interview personnel to confirm they are aware of and follow the documented anti-malware policies."
  },
  {
    id: "5.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 5 are documented, assigned, and understood",
    description: "Specific roles and responsibilities for anti-malware management must be formally assigned and documented. Personnel must understand their responsibilities for deploying, maintaining, and monitoring anti-malware solutions. Clear accountability ensures consistent protection against malicious software.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for Requirement 5 activities are assigned. Interview responsible personnel to confirm understanding of their anti-malware management duties."
  },
  {
    id: "5.2.1",
    title: "An anti-malware solution(s) is deployed on all system components, except for those system components identified in periodic evaluations that concludes the system components are not at risk from malware",
    description: "Anti-malware solutions must be deployed on all system components that are commonly affected by malicious software. Systems considered not at risk from malware must be evaluated periodically to confirm the risk assessment remains valid. The evaluation must consider evolving threats and any changes to the system that might introduce new malware risks.",
    testingProcedure: "Examine system components and verify that anti-malware solutions are deployed on all components commonly affected by malware. For systems without anti-malware, verify documented periodic evaluations confirming they are not at risk."
  },
  {
    id: "5.2.2",
    title: "The deployed anti-malware solution(s) detects all known types of malware and removes, blocks, or contains all known types of malware",
    description: "The anti-malware solution must be capable of detecting all known types of malware including viruses, worms, trojans, ransomware, spyware, and rootkits. The solution must be configured to take appropriate action upon detection, such as removing, blocking, or containing the malware. Detection and response capabilities must be verified through regular testing.",
    testingProcedure: "Examine anti-malware configurations and verify the solution is configured to detect all known malware types. Verify the solution is configured to automatically remove, block, or contain detected malware."
  },
  {
    id: "5.2.3",
    title: "Any system components that are not at risk for malware are evaluated periodically to include: a documented list of all system components not at risk, identification and evaluation of evolving malware threats, and confirmation whether such system components continue to not require anti-malware protection",
    description: "System components that are determined to not be at risk from malware must undergo periodic reevaluation. The evaluation must consider new and evolving malware threats that could affect the previously exempt systems. A documented list of exempt systems with the rationale for exemption must be maintained and reviewed regularly.",
    testingProcedure: "Examine the list of systems without anti-malware and verify periodic evaluations are performed. Verify that evaluations consider evolving threats and confirm the continued validity of the exemption."
  },
  {
    id: "5.3.1",
    title: "The anti-malware solution(s) is kept current via automatic updates",
    description: "Anti-malware solutions must be configured to receive automatic updates to detection signatures, heuristic definitions, and the scanning engine itself. Updates must be applied promptly to ensure protection against the latest threats. Outdated anti-malware solutions may fail to detect recently identified malware variants.",
    testingProcedure: "Examine anti-malware configurations to verify automatic updates are enabled. Examine update logs to verify that updates are being received and applied promptly."
  },
  {
    id: "5.3.2",
    title: "The anti-malware solution(s) performs periodic scans and active or real-time scans, or performs continuous behavioral analysis of systems or processes",
    description: "Anti-malware solutions must be configured to perform both periodic scheduled scans and active real-time scanning, or employ continuous behavioral analysis to detect malicious activity. Periodic scans catch malware that may have been introduced when real-time scanning was temporarily disabled. Behavioral analysis can detect previously unknown malware based on suspicious behavior patterns.",
    testingProcedure: "Examine anti-malware configurations to verify that periodic scans and real-time scanning or behavioral analysis are enabled. Verify scan schedules and review scan logs to confirm scans are being performed as configured."
  },
  {
    id: "5.3.2.1",
    title: "If periodic malware scans are performed to meet Requirement 5.3.2, the frequency of scans is defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1",
    description: "The frequency of periodic malware scans must be determined through a documented targeted risk analysis. The risk analysis must consider the likelihood and impact of malware threats specific to the organization's environment. More frequent scanning may be needed for high-risk systems or during periods of elevated threat.",
    testingProcedure: "Examine the targeted risk analysis and verify it addresses the frequency of periodic malware scans. Verify that the scan frequency configured in the anti-malware solution matches the risk analysis findings."
  },
  {
    id: "5.3.3",
    title: "For removable electronic media, the anti-malware solution(s) performs automatic scans of when the media is inserted, connected, or logically mounted, or performs continuous behavioral analysis of systems or processes when the media is inserted, connected, or logically mounted",
    description: "Anti-malware solutions must be configured to automatically scan removable electronic media when it is inserted, connected, or mounted. This includes USB drives, external hard drives, and optical media. Removable media is a common vector for malware introduction and must be scanned before allowing access to its contents.",
    testingProcedure: "Examine anti-malware configurations to verify automatic scanning of removable media upon insertion or connection. Test the control by connecting removable media and verifying that a scan is initiated."
  },
  {
    id: "5.3.4",
    title: "Audit logs for the anti-malware solution(s) are enabled and retained in accordance with Requirement 10.5.1",
    description: "Audit logging must be enabled for all anti-malware solutions to record scanning activities, detection events, update activities, and configuration changes. Logs must be retained according to the organization's log retention policy as defined in Requirement 10.5.1. Anti-malware logs are essential for incident investigation and compliance verification.",
    testingProcedure: "Examine anti-malware configurations to verify that audit logging is enabled. Examine log retention settings to verify logs are retained in accordance with Requirement 10.5.1."
  },
  {
    id: "5.3.5",
    title: "Anti-malware mechanisms cannot be disabled or altered by users, unless specifically documented and authorized by management on a case-by-case basis for a limited time period",
    description: "End users must not be able to disable, alter, or interfere with the operation of anti-malware solutions on their systems. Any exception allowing temporary disabling must be documented with management authorization and limited to a specific time period. When an exception expires, the anti-malware solution must be automatically re-enabled.",
    testingProcedure: "Examine anti-malware configurations to verify that users cannot disable or alter the solution. Examine records of any authorized exceptions and verify they include management authorization, time limits, and re-enablement."
  },
  {
    id: "5.4.1",
    title: "Processes and automated mechanisms are in place to detect and protect personnel against phishing attacks",
    description: "The organization must implement technical controls to detect and block phishing attacks targeting personnel. These controls may include email filtering, URL filtering, anti-spoofing technologies such as DMARC, DKIM, and SPF, and security awareness training. Phishing is one of the primary attack vectors used to gain initial access to cardholder data environments.",
    testingProcedure: "Examine anti-phishing controls and verify that technical mechanisms are in place to detect and block phishing attacks. Verify that email authentication protocols and filtering technologies are properly configured and operational."
  },

  // ============================================================
  // REQUIREMENT 6: Develop and Maintain Secure Systems and Software
  // ============================================================
  {
    id: "6.1.1",
    title: "All security policies and operational procedures identified in Requirement 6 are documented, kept up to date, in use, and known to all affected parties",
    description: "All policies and procedures for developing and maintaining secure systems and software must be documented, current, and communicated to all relevant development and operations personnel. Documentation must cover secure coding practices, vulnerability management, and change control. Regular reviews ensure the policies address evolving threats and technologies.",
    testingProcedure: "Examine documentation to verify that all Requirement 6 policies and procedures exist and are current. Interview development and operations personnel to confirm awareness and adherence."
  },
  {
    id: "6.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 6 are documented, assigned, and understood",
    description: "Specific roles and responsibilities for secure development, vulnerability management, and change control must be formally assigned. Personnel must understand their responsibilities and have the skills and resources needed to fulfill them. Clear assignment ensures accountability for maintaining secure systems and software.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for Requirement 6 are assigned. Interview responsible personnel to confirm they understand their duties."
  },
  {
    id: "6.2.1",
    title: "Bespoke and custom software are developed securely, including: based on industry standards and/or best practices for secure development, in accordance with PCI DSS, and incorporating information security throughout the software development life cycle",
    description: "All custom and bespoke software must be developed following secure development practices based on industry standards such as OWASP, SANS, or equivalent frameworks. Security must be integrated throughout the entire software development lifecycle, from requirements gathering through deployment and maintenance. This proactive approach prevents the introduction of security vulnerabilities during development.",
    testingProcedure: "Examine the software development lifecycle documentation and verify that security is integrated at each phase. Verify that development standards reference industry-accepted secure development practices."
  },
  {
    id: "6.2.2",
    title: "Software development personnel working on bespoke and custom software are trained at least once every 12 months in software security relevant to their job function and development languages",
    description: "Developers who work on custom or bespoke software must receive annual training on software security topics relevant to their specific job functions and the programming languages they use. Training must cover common vulnerability types, secure coding practices, and security testing techniques. Well-trained developers are the first line of defense against introducing vulnerabilities into code.",
    testingProcedure: "Examine training records and verify that all development personnel receive security training at least annually. Verify that training content is relevant to the developer's job function and programming languages."
  },
  {
    id: "6.2.3",
    title: "Bespoke and custom software is reviewed prior to being released into production or to customers, to identify and correct potential coding vulnerabilities",
    description: "All custom and bespoke software must undergo security review before deployment to production or delivery to customers. Reviews may include manual code review, automated static analysis, or a combination of both. The review must be performed by individuals other than the original developer and must address common coding vulnerabilities.",
    testingProcedure: "Examine code review processes and records to verify that security reviews are performed prior to production release. Verify that reviews are conducted by qualified reviewers who are not the original code author."
  },
  {
    id: "6.2.3.1",
    title: "If manual code reviews are performed for bespoke and custom software prior to release to production, code changes are reviewed by individuals other than the originating code author, and by individuals knowledgeable about code-review techniques and secure coding practices",
    description: "Manual code reviews must be performed by individuals who did not author the code being reviewed and who have training in code review techniques and secure coding practices. Reviewers must understand common vulnerability patterns in the programming languages used. Independent review provides an objective assessment of code security that authors may miss due to familiarity bias.",
    testingProcedure: "Examine code review records and verify that reviewers are different from the code authors. Verify that reviewers have documented training in code review techniques and secure coding practices."
  },
  {
    id: "6.2.4",
    title: "Software engineering techniques or other methods are defined and in use by software development personnel to prevent or mitigate common software attacks and related vulnerabilities in bespoke and custom software",
    description: "Software development teams must employ specific techniques to prevent common software attacks including injection attacks, buffer overflows, insecure cryptographic storage, insecure communications, and improper error handling. These techniques must be integrated into the development process through coding standards, libraries, and frameworks. Preventing vulnerabilities during development is more effective and less costly than finding and fixing them after deployment.",
    testingProcedure: "Examine software development processes and coding standards to verify that techniques for preventing common vulnerabilities are defined. Review sample code to verify that these techniques are applied in practice."
  },
  {
    id: "6.3.1",
    title: "Security vulnerabilities are identified and managed through a process that includes using reputable outside sources for security vulnerability information and ranking vulnerabilities using a risk ranking methodology",
    description: "The organization must have a formal process for identifying and managing security vulnerabilities that includes monitoring reputable sources such as CVE databases, vendor advisories, and security mailing lists. Identified vulnerabilities must be ranked using a risk methodology that considers severity, exploitability, and the sensitivity of affected systems. This risk-based approach ensures that the most critical vulnerabilities receive priority attention.",
    testingProcedure: "Examine the vulnerability management process and verify that reputable outside sources are monitored for vulnerability information. Verify that a risk ranking methodology is applied to all identified vulnerabilities."
  },
  {
    id: "6.3.2",
    title: "An inventory of bespoke and custom software, and third-party software components incorporated into bespoke and custom software, is maintained to facilitate vulnerability and patch management",
    description: "A comprehensive inventory must be maintained of all custom software and third-party components used within custom software, including open-source libraries and frameworks. The inventory must include version information and be kept current as changes are made. This software bill of materials enables rapid identification of affected systems when vulnerabilities are discovered in third-party components.",
    testingProcedure: "Examine the software inventory and verify it includes all custom software and third-party components with version information. Verify the inventory is updated when software changes are made."
  },
  {
    id: "6.3.3",
    title: "All system components are protected from known vulnerabilities by installing applicable security patches/updates within a defined timeframe",
    description: "Security patches and updates must be applied to all system components within a defined timeframe based on the risk ranking of the vulnerability. Critical and high-risk vulnerabilities must be patched within one month of release, with shorter timeframes for actively exploited vulnerabilities. A formal process must track the patching status of all system components.",
    testingProcedure: "Examine patch management records and verify that patches are applied within the defined timeframes based on risk ranking. Compare installed patch levels against available patches to identify any gaps."
  },
  {
    id: "6.4.1",
    title: "For public-facing web applications, new threats and vulnerabilities are addressed on an ongoing basis and these applications are protected against known attacks",
    description: "Public-facing web applications must be continuously protected against known attacks through methods such as web application firewalls, automated vulnerability scanning, or manual application security assessments. New threats must be evaluated as they emerge and protection measures updated accordingly. Public-facing web applications are common targets for attacks seeking to access cardholder data.",
    testingProcedure: "Examine the protection mechanisms for public-facing web applications and verify they address known threats. Verify that the protection is updated to address newly discovered vulnerabilities and attack techniques."
  },
  {
    id: "6.4.2",
    title: "For public-facing web applications, an automated technical solution is deployed that continually detects and prevents web-based attacks",
    description: "An automated technical solution, such as a web application firewall, must be deployed in front of public-facing web applications to detect and prevent web-based attacks in real time. The solution must be actively running and up to date, and must generate audit logs. This provides a defense layer that protects against exploitation of both known and unknown vulnerabilities in web applications.",
    testingProcedure: "Examine the configuration of the automated web attack detection and prevention solution and verify it is deployed for all public-facing web applications. Verify the solution is actively protecting applications and generating audit logs."
  },
  {
    id: "6.4.3",
    title: "All payment page scripts that are loaded and executed in the consumer's browser are managed as follows: a method is implemented to confirm that each script is authorized, a method is implemented to assure the integrity of each script, an inventory of all scripts is maintained with written justification as to why each is necessary",
    description: "All scripts loaded on payment pages must be inventoried, authorized, and monitored for integrity. Each script must have documented business justification for its presence on the payment page. Integrity monitoring must detect unauthorized modifications to scripts that could indicate a web skimming attack, which is one of the most prevalent attack vectors against online payment forms.",
    testingProcedure: "Examine the inventory of payment page scripts and verify each has documented authorization and business justification. Verify that integrity monitoring is in place and functioning to detect unauthorized script modifications."
  },
  {
    id: "6.5.1",
    title: "Changes to all system components in the production environment are made according to established procedures that include documented change requests with description of the change, documented approval by authorized parties, testing to verify that the change does not adversely impact system security, and back-out procedures",
    description: "All changes to production system components must follow a formal change control process that includes documenting the nature of the change, obtaining authorization, testing the change, and defining rollback procedures. The change control process must apply to all changes including patches, configuration changes, and software updates. Uncontrolled changes are a leading cause of security incidents and system outages.",
    testingProcedure: "Examine change control records for a sample of recent changes and verify that all required elements are documented. Verify that changes were tested, authorized, and include documented back-out procedures."
  },
  {
    id: "6.5.2",
    title: "Upon completion of a significant change, all applicable PCI DSS requirements are confirmed to be in place on all new or changed systems and networks, and documentation is updated as applicable",
    description: "After significant changes to the environment, the organization must verify that all applicable PCI DSS requirements remain in place and effective. This includes verifying that security controls on new or changed systems are properly configured and that documentation such as network diagrams and asset inventories is updated. Significant changes can inadvertently weaken security controls if not properly verified.",
    testingProcedure: "Examine records of significant changes and verify that PCI DSS compliance was confirmed after each change. Verify that documentation was updated to reflect the changes made."
  },
  {
    id: "6.5.3",
    title: "Pre-production environments are separated from production environments and the separation is enforced with access controls",
    description: "Development, testing, and staging environments must be logically or physically separated from production environments. Access controls must enforce this separation to prevent unauthorized access from pre-production to production systems. Pre-production environments often have weaker security controls and may contain test data or vulnerabilities that could be exploited if accessible from production.",
    testingProcedure: "Examine network configurations and access controls to verify that pre-production environments are separated from production. Verify that access controls enforce the separation and prevent unauthorized cross-environment access."
  },
  {
    id: "6.5.4",
    title: "Roles and functions are separated between production and pre-production environments to provide accountability such that only reviewed and approved changes are deployed",
    description: "Different roles must manage production versus pre-production environments to maintain separation of duties. Developers should not have uncontrolled access to deploy code directly to production. This separation ensures that code changes go through proper review and approval before being deployed to the production environment.",
    testingProcedure: "Examine access controls and personnel assignments to verify separation of roles between production and pre-production environments. Verify that production deployment access is restricted to authorized personnel."
  },
  {
    id: "6.5.5",
    title: "Live PANs are not used in pre-production environments, except where those environments are included in the CDE and protected in accordance with all applicable PCI DSS requirements",
    description: "Live primary account numbers must not be used in development, testing, or staging environments unless those environments are included within the CDE boundary and fully protected. If live PANs are needed for testing, the pre-production environment must meet all PCI DSS requirements. Using live PANs in unprotected environments significantly increases the risk of data compromise.",
    testingProcedure: "Examine pre-production environments and verify that live PANs are not present. If live PANs are used, verify that the pre-production environment is included in the CDE and meets all applicable PCI DSS requirements."
  },
  {
    id: "6.5.6",
    title: "Test data and test accounts are removed from system components before the system goes into production",
    description: "All test data, test accounts, and custom application accounts used during development and testing must be removed before a system is deployed to production. Test accounts often have known or weak credentials that could be exploited by attackers. Test data may also contain patterns that could be used to bypass security controls.",
    testingProcedure: "Examine production systems and verify that test data and test accounts have been removed prior to deployment. Interview development and operations personnel to confirm the process for removing test artifacts before production deployment."
  },

  // ============================================================
  // REQUIREMENT 7: Restrict Access to System Components and Cardholder Data by Business Need to Know
  // ============================================================
  {
    id: "7.1.1",
    title: "All security policies and operational procedures identified in Requirement 7 are documented, kept up to date, in use, and known to all affected parties",
    description: "All policies and procedures for restricting access based on business need to know must be documented, current, and communicated to relevant personnel. These documents must define access control models, role definitions, and procedures for granting and revoking access. Comprehensive documentation ensures consistent application of the principle of least privilege.",
    testingProcedure: "Examine documentation to verify that all Requirement 7 policies and procedures exist and are current. Interview personnel to confirm they are aware of and follow the access control policies."
  },
  {
    id: "7.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 7 are documented, assigned, and understood",
    description: "Specific roles and responsibilities for managing access controls based on business need to know must be formally assigned and documented. Personnel responsible for access management must understand the principle of least privilege and the procedures for managing access. Clear role assignment ensures accountability for access control decisions.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for Requirement 7 activities are assigned. Interview responsible personnel to confirm they understand their duties related to access management."
  },
  {
    id: "7.2.1",
    title: "An access control model is defined and includes granting access to system components and data resources based on users' job classification and function, and the least privileges necessary to perform job responsibilities",
    description: "A formal access control model must be defined that grants access based on job classification and function, implementing the principle of least privilege. The model must specify what access each role requires and ensure that access is limited to the minimum necessary for job performance. Role-based access control is the preferred approach for managing access at scale.",
    testingProcedure: "Examine the access control model and verify it defines access based on job classification and function. Verify that the model implements least privilege by limiting access to the minimum necessary for each role."
  },
  {
    id: "7.2.2",
    title: "Access is assigned to users, including privileged users, based on job classification and function",
    description: "Access to system components and data must be assigned based on documented job classifications and functions. Privileged access must be especially tightly controlled and justified. Each user's access must align with their defined role and not exceed what is necessary for their specific job responsibilities.",
    testingProcedure: "Examine user access lists and compare assigned access against documented job classifications and functions. Verify that privileged access is limited to those with a documented business need."
  },
  {
    id: "7.2.3",
    title: "Required privileges are approved by authorized personnel",
    description: "Access privileges must be formally approved by authorized personnel before being granted to users. The approval process must include verification that the requested access aligns with the user's job function and the principle of least privilege. Documented approvals provide an audit trail and ensure that access decisions are made by personnel with appropriate authority.",
    testingProcedure: "Examine access approval records and verify that all access grants have documented authorization from appropriate personnel. Interview approving personnel to confirm they verify business need before authorizing access."
  },
  {
    id: "7.2.4",
    title: "All user accounts and related access privileges, including third-party/vendor accounts, are reviewed at least once every six months",
    description: "All user accounts and their associated access privileges must be reviewed at least every six months to verify that access remains appropriate. The review must include third-party and vendor accounts and must result in the removal or modification of access that is no longer needed. Regular reviews detect and correct access creep and ensure that departed or transferred personnel no longer have inappropriate access.",
    testingProcedure: "Examine access review records and verify that reviews are conducted at least every six months. Verify that the reviews result in the identification and remediation of inappropriate access."
  },
  {
    id: "7.2.5",
    title: "All application and system accounts and related access privileges are assigned and managed as follows: based on the least privileges necessary for the operability of the system or application, access is limited to the systems, applications, or processes that specifically require their use",
    description: "Application and system accounts must be assigned the minimum privileges needed for the application or system to function properly. These accounts must be restricted to only the specific systems, applications, or processes that require them. Over-privileged system accounts are a significant risk because they can be exploited for lateral movement if compromised.",
    testingProcedure: "Examine application and system account configurations and verify they have the minimum necessary privileges. Verify that account access is limited to the specific systems and processes that require it."
  },
  {
    id: "7.2.5.1",
    title: "All access by application and system accounts and related access privileges are reviewed in accordance with Requirement 7.2.4 to determine if the access is still appropriate",
    description: "Application and system accounts must be included in the periodic access review process defined in Requirement 7.2.4. The review must confirm that each account's privileges remain appropriate for its intended function and that unnecessary access has been removed. System accounts often accumulate privileges over time and must be regularly reviewed to maintain least privilege.",
    testingProcedure: "Examine access review records and verify that application and system accounts are included in the review process. Verify that the reviews result in the identification and remediation of excessive privileges."
  },
  {
    id: "7.2.6",
    title: "All user access to query repositories of stored cardholder data is restricted as follows: via applications or other programmatic methods, with access and allowed actions based on user roles and least privileges, and only the minimum amount of data needed is returned",
    description: "User access to query repositories containing stored cardholder data must be controlled through applications or programmatic methods that enforce role-based access controls. Query results must be limited to return only the minimum amount of data needed for the user's job function. Direct database access for querying cardholder data must be restricted to database administrators with a documented business need.",
    testingProcedure: "Examine application configurations and database access controls to verify that query access to cardholder data repositories is restricted. Verify that queries return only the minimum necessary data based on the user's role."
  },
  {
    id: "7.3.1",
    title: "An access control system(s) is in place that restricts access based on a user's need to know and covers all system components",
    description: "An access control system must be implemented that restricts access to system components and cardholder data based on the user's documented need to know. The system must cover all system components in the cardholder data environment and enforce the defined access control model. The access control system provides the technical enforcement mechanism for the organization's access policies.",
    testingProcedure: "Examine the access control system and verify it covers all system components in the CDE. Verify that the system enforces restrictions based on documented need to know for all users."
  },
  {
    id: "7.3.2",
    title: "The access control system(s) is configured to enforce permissions assigned to individuals, applications, and systems based on job classification and function",
    description: "Access control systems must be configured to enforce the permissions defined in the access control model based on job classifications and functions. The system must not allow users to exceed their assigned permissions. Technical enforcement of access controls prevents both intentional and accidental access to data or systems beyond what is authorized.",
    testingProcedure: "Examine access control system configurations and verify that permissions are enforced based on job classification and function. Test the access controls by attempting to access resources outside of assigned permissions."
  },
  {
    id: "7.3.3",
    title: "The access control system(s) is set to deny all by default",
    description: "Access control systems must be configured to deny all access by default, granting access only when explicitly authorized. This default-deny approach ensures that new users or system components have no access until access is specifically granted through the approval process. Default-deny is a fundamental principle of least privilege that prevents unauthorized access through oversight.",
    testingProcedure: "Examine access control system configurations and verify that the default setting denies all access. Test by creating a new user or system account and verifying that no access is granted without explicit authorization."
  },

  // ============================================================
  // REQUIREMENT 8: Identify Users and Authenticate Access to System Components
  // ============================================================
  {
    id: "8.1.1",
    title: "All security policies and operational procedures identified in Requirement 8 are documented, kept up to date, in use, and known to all affected parties",
    description: "All policies and procedures for user identification and authentication must be documented, current, and communicated to all relevant personnel. These documents must define account management procedures, authentication requirements, and password policies. Regular review and updates ensure the policies address evolving authentication threats and best practices.",
    testingProcedure: "Examine documentation to verify that all Requirement 8 policies and procedures exist and are current. Interview personnel to confirm awareness and adherence to the documented policies."
  },
  {
    id: "8.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 8 are documented, assigned, and understood",
    description: "Specific roles and responsibilities for user identification and authentication management must be formally assigned and documented. Personnel must understand their responsibilities for managing user accounts, authentication mechanisms, and access credentials. Clear assignment ensures accountability for identity and authentication management.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for Requirement 8 activities are assigned. Interview responsible personnel to confirm understanding of their duties."
  },
  {
    id: "8.2.1",
    title: "All users are assigned a unique ID before access to system components or cardholder data is allowed",
    description: "Every user must be assigned a unique identification that enables individual accountability for actions taken in the system. Shared, group, or generic user IDs must not be used except where specifically permitted by PCI DSS. Unique identification ensures that actions can be traced to specific individuals for security monitoring and forensic investigation.",
    testingProcedure: "Examine user account lists and verify that each user has a unique ID. Verify that no shared, group, or generic IDs are in use except where specifically allowed by PCI DSS."
  },
  {
    id: "8.2.2",
    title: "Group, shared, or generic accounts, or other shared authentication credentials are only used when necessary on an exception basis, and are managed as follows: account use is prevented unless needed for an exceptional circumstance, use is limited to the time needed for the exceptional circumstance, business justification for use is documented, use is explicitly approved by management, individual user identity is confirmed before access to account is granted, and every action taken is attributable to an individual user",
    description: "Shared accounts must only be used when there is a documented business need and no other alternative exists. When shared accounts are used, each use must have management approval, individual user identity must be verified, and all actions must be attributable to individual users. These strict controls on shared accounts maintain accountability while accommodating legitimate business needs.",
    testingProcedure: "Examine records of shared account usage and verify that all required controls are in place. Verify that business justification, management approval, and individual attribution mechanisms are documented for each shared account."
  },
  {
    id: "8.2.3",
    title: "Additional requirement for service providers only: Service providers with remote access to customer premises use unique authentication factors for each customer premises",
    description: "Service providers must use unique authentication credentials for each customer environment they access remotely. Shared credentials across multiple customer environments create a risk that compromise of one customer's credentials could lead to unauthorized access to other customers. This requirement ensures that a security breach at one customer does not propagate to others through shared service provider credentials.",
    testingProcedure: "Examine service provider authentication configurations and verify that unique authentication factors are used for each customer premises. Verify that no shared credentials are used across multiple customer environments."
  },
  {
    id: "8.2.4",
    title: "Addition, deletion, and modification of user IDs, authentication factors, and other identifier objects are managed as follows: authorized with appropriate approval, implemented with only the privileges specified on the documented approval, and action is performed by a user account with appropriate privilege",
    description: "All user account lifecycle operations including creation, modification, and deletion must follow a formal process with proper authorization. Changes must be limited to what was specifically approved in the request. Only personnel with appropriate administrative privileges may perform account management operations. This ensures that account changes are controlled and auditable.",
    testingProcedure: "Examine account management records and verify that user ID additions, modifications, and deletions are properly authorized. Verify that implemented changes match the documented approvals."
  },
  {
    id: "8.2.5",
    title: "Access for terminated users is immediately revoked",
    description: "User accounts must be disabled or removed immediately upon the user's termination from the organization. This includes disabling all access to system components, applications, and remote access capabilities. Delayed revocation of terminated user access creates a window during which the former employee could access systems and data without authorization.",
    testingProcedure: "Examine termination procedures and verify that user access is revoked immediately upon termination. Compare recently terminated employee lists against active user accounts to verify timely revocation."
  },
  {
    id: "8.2.6",
    title: "Inactive user accounts are removed or disabled within 90 days of inactivity",
    description: "User accounts that have not been used for 90 days or more must be disabled or removed from the system. Inactive accounts may belong to personnel who no longer need access or who have left the organization without proper offboarding. Dormant accounts are attractive targets for attackers because suspicious activity may go unnoticed.",
    testingProcedure: "Examine user account lists and login records to identify accounts inactive for 90 or more days. Verify that inactive accounts have been disabled or removed in accordance with the policy."
  },
  {
    id: "8.2.7",
    title: "Accounts used by third parties to access, support, or maintain system components via remote access are managed as follows: enabled only during the time period needed and disabled when not in use, use is monitored for unexpected activity",
    description: "Third-party remote access accounts must be enabled only during the specific time periods when access is needed and must be disabled at all other times. Activity on these accounts must be monitored for unexpected or unauthorized actions. Third-party accounts represent elevated risk because they extend the trust boundary beyond the organization's direct control.",
    testingProcedure: "Examine third-party account configurations and verify they are disabled when not in active use. Examine monitoring records to verify that third-party account activity is logged and reviewed for unexpected behavior."
  },
  {
    id: "8.2.8",
    title: "If a user session has been idle for more than 15 minutes, the user is required to re-authenticate to re-activate the terminal or session",
    description: "System sessions must be configured to require re-authentication after 15 minutes of inactivity. This prevents unauthorized access through unattended terminals or sessions. The timeout must apply to all interactive sessions including console, remote desktop, and application sessions within the cardholder data environment.",
    testingProcedure: "Examine session timeout configurations for system components and verify the idle timeout is set to 15 minutes or less. Test by leaving a session idle for 15 minutes and verifying that re-authentication is required."
  },
  {
    id: "8.3.1",
    title: "All user access to system components for users and administrators is authenticated via at least one of the following authentication factors: something you know, something you have, or something you are",
    description: "All user and administrator access to system components must require authentication using at least one valid authentication factor. Authentication factors include knowledge factors such as passwords, possession factors such as tokens or smart cards, and inherence factors such as biometrics. Authentication must be enforced before any access to system components or data is granted.",
    testingProcedure: "Examine authentication configurations for all system components and verify that at least one authentication factor is required. Test authentication mechanisms to confirm they function correctly and cannot be bypassed."
  },
  {
    id: "8.3.2",
    title: "Strong cryptography is used to render all authentication factors unreadable during storage and transmission on all system components",
    description: "All authentication factors, including passwords, tokens, and biometric data, must be protected with strong cryptography both when stored and when transmitted. Passwords must be stored using one-way hashing with a strong cryptographic hash function and a unique salt. Unprotected authentication factors can be intercepted or stolen, enabling unauthorized access.",
    testingProcedure: "Examine storage configurations and verify that all authentication factors are rendered unreadable using strong cryptography. Examine transmission configurations to verify encryption is used during authentication."
  },
  {
    id: "8.3.3",
    title: "User identity is verified before modifying any authentication factor",
    description: "Before any authentication factor is modified, including password resets and token replacements, the user's identity must be verified through a secure process. The verification process must be documented and must not rely solely on the authentication factor being changed. This prevents social engineering attacks that could be used to compromise user accounts through fraudulent password resets.",
    testingProcedure: "Examine procedures for modifying authentication factors and verify that user identity verification is required. Test the process by requesting an authentication factor modification and verifying that identity verification is performed."
  },
  {
    id: "8.3.4",
    title: "Invalid authentication attempts are limited by locking out the user ID after not more than 10 attempts, setting the lockout duration to a minimum of 30 minutes or until the user's identity is confirmed",
    description: "System components must be configured to lock out a user account after no more than 10 consecutive invalid authentication attempts. The locked account must remain locked for a minimum of 30 minutes or until the user's identity is verified by an administrator. Account lockout prevents brute-force attacks that systematically try different passwords to gain access.",
    testingProcedure: "Examine system configurations and verify that account lockout is set to trigger after no more than 10 invalid attempts. Verify that the lockout duration is at least 30 minutes and test by exceeding the attempt limit."
  },
  {
    id: "8.3.5",
    title: "If passwords/passphrases are used as authentication factors to meet Requirement 8.3.1, they are set and reset for each user as follows: set to a unique value for first-time use and upon reset, and forced to be changed immediately after the first use",
    description: "Initial and reset passwords must be set to a unique value for each user and must expire immediately, requiring the user to set a new password upon first use. This prevents shared initial passwords from being used to gain unauthorized access. The process for generating and distributing initial passwords must be secure to prevent interception.",
    testingProcedure: "Examine password management procedures and system configurations to verify that initial and reset passwords are unique per user. Verify that first-use passwords are required to be changed immediately upon first login."
  },
  {
    id: "8.3.6",
    title: "If passwords/passphrases are used as authentication factors to meet Requirement 8.3.1, they meet the following minimum level of complexity: a minimum length of 12 characters, or if the system does not support 12 characters, a minimum length of eight characters, and contain both numeric and alphabetic characters",
    description: "Passwords must be a minimum of 12 characters in length and contain both numeric and alphabetic characters. If a system does not support 12-character passwords, the minimum is eight characters. Strong password complexity requirements significantly increase the difficulty of brute-force and dictionary-based password attacks.",
    testingProcedure: "Examine password configuration settings on system components and verify that minimum length and complexity requirements are enforced. Test by attempting to set passwords that do not meet the requirements and verifying they are rejected."
  },
  {
    id: "8.3.7",
    title: "Individuals are not allowed to submit a new password/passphrase that is the same as any of the last four passwords/passphrases used",
    description: "Password history must be enforced to prevent users from reusing any of their last four passwords. This prevents users from alternating between a small set of passwords, which reduces the effectiveness of mandatory password changes. Password history must be enforced by the system and must store historical passwords in a secure, non-recoverable form.",
    testingProcedure: "Examine password configuration settings and verify that password history is set to remember at least the last four passwords. Test by attempting to reuse a recent password and verifying it is rejected."
  },
  {
    id: "8.3.8",
    title: "Authentication policies and procedures are documented and communicated to all users including guidance on selecting strong authentication factors, guidance on how users should protect their authentication factors, and instructions not to reuse previously used passwords/passphrases",
    description: "Authentication policies must be documented and communicated to all users, providing guidance on creating strong passwords, protecting authentication credentials, and the prohibition against reusing previous passwords. Users must understand their responsibilities for protecting their credentials and the risks of weak or compromised authentication. Regular communication reinforces good authentication practices.",
    testingProcedure: "Examine authentication policy documentation and verify it includes guidance on strong credential selection and protection. Interview users to confirm they have received and understand the authentication policies."
  },
  {
    id: "8.3.9",
    title: "If passwords/passphrases are used as the only authentication factor for user access, then either passwords/passphrases are changed at least once every 90 days, or the security posture of accounts is dynamically analyzed",
    description: "When passwords are the sole authentication factor, they must be changed at least every 90 days, or the organization must implement a system that dynamically analyzes the security posture of each account to determine if access should be allowed. Dynamic analysis may consider factors such as login patterns, account compromise indicators, and password strength. This requirement encourages the adoption of multi-factor authentication or risk-based authentication approaches.",
    testingProcedure: "Examine system configurations and verify that password expiration is set to 90 days or less, or that a dynamic security analysis system is in place. If dynamic analysis is used, verify that it effectively evaluates account security posture."
  },
  {
    id: "8.3.10",
    title: "Additional requirement for service providers only: If passwords/passphrases are used as the only authentication factor for customer user access to cardholder data, then guidance is provided to customer users including guidance to change their passwords/passphrases periodically and guidance as to when and under what circumstances passwords/passphrases are to be changed",
    description: "Service providers that use password-only authentication for customer user access must provide customers with guidance on periodic password changes. The guidance must include recommended change frequencies and circumstances that should trigger an immediate password change, such as a suspected breach. This helps service provider customers maintain the security of their accounts even when multi-factor authentication is not implemented.",
    testingProcedure: "Examine documentation provided to customer users and verify it includes guidance on periodic password changes and circumstances requiring immediate changes. Interview customer-facing personnel to confirm the guidance is communicated."
  },
  {
    id: "8.3.10.1",
    title: "Additional requirement for service providers only: If passwords/passphrases are used as the only authentication factor for customer user access, then either passwords/passphrases are changed at least once every 90 days, or the security posture of accounts is dynamically analyzed",
    description: "Service providers using password-only authentication for customer access must enforce password changes every 90 days or implement dynamic security analysis. The dynamic analysis must evaluate the security posture of customer accounts in real time and respond to indicators of compromise. This provides ongoing protection against credential-based attacks targeting service provider customer accounts.",
    testingProcedure: "Examine system configurations for customer user authentication and verify that 90-day password expiration or dynamic analysis is implemented. Verify the control is functioning as designed."
  },
  {
    id: "8.4.1",
    title: "MFA is implemented for all non-console access into the CDE for personnel with administrative access",
    description: "Multi-factor authentication must be required for all non-console administrative access to the cardholder data environment. MFA requires at least two of the three authentication factor types: something you know, something you have, and something you are. Administrative accounts have elevated privileges that could cause significant damage if compromised, making MFA essential for protecting these high-value accounts.",
    testingProcedure: "Examine MFA configurations for administrative access to the CDE and verify that MFA is required for all non-console administrative connections. Test administrative access to verify that MFA is enforced and cannot be bypassed."
  },
  {
    id: "8.4.2",
    title: "MFA is implemented for all access into the CDE",
    description: "Multi-factor authentication must be required for all access to the cardholder data environment, not just administrative access. This applies to all users who access the CDE regardless of their role or the method of access. Implementing MFA for all CDE access significantly reduces the risk of unauthorized access through compromised credentials.",
    testingProcedure: "Examine MFA configurations for the CDE and verify that MFA is required for all user access. Test various access methods to verify that MFA is consistently enforced."
  },
  {
    id: "8.4.3",
    title: "MFA is implemented for all remote network access originating from outside the entity's network that could access or impact the CDE",
    description: "Multi-factor authentication must be required for all remote network access from outside the entity's network that could reach or affect the cardholder data environment. This applies to all remote users, including employees, administrators, and third parties. Remote access from external networks represents an elevated risk because the entity has limited control over the security of the remote endpoint.",
    testingProcedure: "Examine MFA configurations for remote access and verify that MFA is required for all external remote connections that could access or impact the CDE. Test remote access to verify MFA enforcement."
  },
  {
    id: "8.5.1",
    title: "MFA systems are implemented as follows: the MFA system is not susceptible to replay attacks, MFA systems cannot be bypassed by any users including administrative users unless specifically documented and authorized by management on an exception basis for a limited time period, and at least two different types of authentication factors are used",
    description: "MFA implementations must be resistant to replay attacks, must not allow any user including administrators to bypass the MFA requirement except with documented management authorization, and must use at least two different types of authentication factors. The MFA system must be robust against attacks that attempt to reuse previously captured authentication data. Any bypass exceptions must be time-limited and regularly reviewed.",
    testingProcedure: "Examine MFA system configurations and verify resistance to replay attacks and that bypass is not possible without documented authorization. Verify that the system requires at least two different types of authentication factors."
  },
  {
    id: "8.6.1",
    title: "If accounts used by systems or applications can be used for interactive login, they are managed as follows: interactive use is prevented unless needed for an exceptional circumstance, interactive use is limited to the time needed for the exceptional circumstance, business justification for interactive use is documented, interactive use is explicitly approved by management, individual user identity is confirmed before access to account is granted, and every action taken is attributable to an individual user",
    description: "System and application accounts capable of interactive login must have interactive access disabled by default. When interactive use is needed for exceptional circumstances such as troubleshooting, it must be explicitly approved by management with documented business justification and time limits. All actions during interactive sessions must be attributable to the specific individual using the account.",
    testingProcedure: "Examine system and application account configurations and verify that interactive login is disabled by default. Examine records of any interactive use and verify that all required controls including management approval and individual attribution are in place."
  },
  {
    id: "8.6.2",
    title: "Passwords/passphrases for any application and system accounts that can be used for interactive login are not hard coded in scripts, configuration/property files, or bespoke and custom source code",
    description: "Passwords for system and application accounts must not be embedded or hard coded in scripts, configuration files, or source code. Hard-coded credentials cannot be easily changed when compromised and are frequently discovered by attackers through source code analysis. Credentials must be stored securely using credential vaults, environment variables, or other secure credential management mechanisms.",
    testingProcedure: "Examine scripts, configuration files, and source code to verify that no hard-coded passwords exist. Verify that secure credential management mechanisms are used to store and retrieve application and system account passwords."
  },
  {
    id: "8.6.3",
    title: "Passwords/passphrases for any application and system accounts are protected against misuse by changing the passwords/passphrases periodically and with a frequency defined in the entity's targeted risk analysis, and with the complexity commensurate with the entity's targeted risk analysis",
    description: "Application and system account passwords must be changed periodically based on the organization's targeted risk analysis. The complexity of these passwords must also be determined by the risk analysis, considering factors such as the sensitivity of the data accessed and the security of the environment. Regular rotation of system account passwords limits the window of exposure if a credential is compromised.",
    testingProcedure: "Examine the targeted risk analysis and verify it defines password rotation frequency and complexity for application and system accounts. Examine system configurations to verify that password policies match the risk analysis findings."
  },

  // ============================================================
  // REQUIREMENT 9: Restrict Physical Access to Cardholder Data
  // ============================================================
  {
    id: "9.1.1",
    title: "All security policies and operational procedures identified in Requirement 9 are documented, kept up to date, in use, and known to all affected parties",
    description: "All policies and procedures for restricting physical access to cardholder data must be documented, current, and communicated to all relevant personnel. Documentation must cover physical access controls, visitor management, and media handling procedures. Regular review ensures the policies address changes to the physical environment and evolving threats.",
    testingProcedure: "Examine documentation to verify that all Requirement 9 policies and procedures exist and are current. Interview personnel to confirm awareness and adherence to physical access control policies."
  },
  {
    id: "9.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 9 are documented, assigned, and understood",
    description: "Specific roles and responsibilities for physical security management must be formally assigned and documented. Personnel responsible for physical access controls must understand their duties and be trained on the procedures. Clear role assignment ensures accountability for maintaining physical security.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for Requirement 9 activities are assigned. Interview responsible personnel to confirm understanding of their physical security duties."
  },
  {
    id: "9.2.1",
    title: "Appropriate facility entry controls are in place to restrict physical access to systems in the CDE",
    description: "Physical access to areas containing system components in the cardholder data environment must be controlled through appropriate entry mechanisms. Entry controls may include badge readers, locks, biometric devices, or security personnel. The controls must prevent unauthorized individuals from accessing areas where cardholder data is processed, stored, or transmitted.",
    testingProcedure: "Observe facility entry controls and verify they restrict physical access to the CDE. Test the controls to confirm that only authorized personnel can gain entry."
  },
  {
    id: "9.2.1.1",
    title: "Individual physical access to sensitive areas within the CDE is monitored with either video cameras or physical access control mechanisms (or both) that are protected from tampering or disabling and collected data is reviewed and correlated with other entries",
    description: "Physical access to sensitive areas within the CDE must be monitored using video cameras, physical access control mechanisms, or both. Monitoring equipment must be protected from tampering and disabling. Collected monitoring data must be stored for a minimum of three months, reviewed regularly, and correlated with other access records to detect unauthorized access attempts.",
    testingProcedure: "Examine monitoring mechanisms for sensitive areas and verify they are operational and protected from tampering. Verify that monitoring data is retained for at least three months and is reviewed regularly."
  },
  {
    id: "9.2.2",
    title: "Physical and/or logical controls are implemented to restrict use of publicly accessible network jacks within the facility",
    description: "Network jacks in publicly accessible areas must be controlled to prevent unauthorized devices from connecting to the network. Controls may include disabling unused network jacks, implementing 802.1X port-based authentication, or placing network jacks in locked enclosures. Uncontrolled network jacks in public areas could allow an attacker to connect directly to the internal network.",
    testingProcedure: "Examine network jack locations in publicly accessible areas and verify that controls are implemented to restrict their use. Test controls by attempting to connect an unauthorized device to a publicly accessible network jack."
  },
  {
    id: "9.2.3",
    title: "Physical access to wireless access points, gateways, networking/communications hardware, and telecommunication lines within the facility is restricted",
    description: "Physical access to network infrastructure components including wireless access points, gateways, routers, switches, and telecommunication lines must be restricted to authorized personnel. These components must be located in secured areas or enclosures that prevent unauthorized physical access. Physical access to network infrastructure could enable an attacker to intercept data, introduce malicious devices, or disrupt communications.",
    testingProcedure: "Observe the physical locations of network infrastructure components and verify they are secured from unauthorized access. Verify that access controls prevent unauthorized personnel from reaching wireless access points, gateways, and telecommunication lines."
  },
  {
    id: "9.2.4",
    title: "Access to consoles in sensitive areas is restricted via locking when not in use",
    description: "Console access points in sensitive areas must be locked when not actively in use by authorized personnel. This includes server console ports, network device console connections, and KVM switches. Unlocked consoles in sensitive areas could allow an unauthorized individual who gains physical access to interact directly with system components.",
    testingProcedure: "Observe consoles in sensitive areas and verify they are locked when not in active use. Verify that locking mechanisms are functioning and that keys or access codes are restricted to authorized personnel."
  },
  {
    id: "9.3.1",
    title: "Procedures are implemented for authorizing and managing physical access of personnel to the CDE based on job function",
    description: "Formal procedures must be implemented for authorizing physical access to the CDE based on job function and need. Access must be granted only to personnel whose job requires physical presence in the CDE. The authorization process must include management approval and documentation of the specific areas to which access is granted.",
    testingProcedure: "Examine physical access authorization procedures and records to verify that access is granted based on job function. Verify that management approval is documented for all personnel with physical access to the CDE."
  },
  {
    id: "9.3.1.1",
    title: "Physical access to sensitive areas within the CDE for personnel is controlled as follows: access is authorized and based on individual job function, access is revoked immediately upon termination, and all physical access mechanisms are returned or disabled upon termination",
    description: "Physical access to sensitive areas must be individually authorized based on job function and revoked immediately upon employment termination. All physical access mechanisms such as keys, badges, and access codes must be returned or disabled when a person's access is terminated. This prevents former personnel from using retained physical access mechanisms to enter sensitive areas.",
    testingProcedure: "Examine physical access records and verify that access is individually authorized based on job function. Compare terminated employee lists against physical access lists to verify timely revocation."
  },
  {
    id: "9.3.2",
    title: "Procedures are implemented for authorizing and managing visitor access to the CDE",
    description: "Formal visitor management procedures must be implemented for controlling visitor access to areas containing CDE system components. Visitors must be authorized before entry, escorted by authorized personnel at all times, and logged in and out with identification recorded. Visitor procedures prevent unauthorized physical access by individuals who do not have a regular need to access the CDE.",
    testingProcedure: "Examine visitor management procedures and records to verify that visitors are authorized, escorted, and logged. Observe the visitor process to confirm it is followed in practice."
  },
  {
    id: "9.3.3",
    title: "Visitor badges or identification are surrendered or deactivated before visitors leave the facility or at the date of expiration",
    description: "Visitor badges or identification must be collected or deactivated when visitors leave the facility or when the badge expires. The badge return process must be enforced to prevent visitors from retaining badges that could be used for unauthorized re-entry. Expired or unreturned badges must be tracked and deactivated promptly.",
    testingProcedure: "Examine visitor badge management processes and verify that badges are collected upon departure. Examine records to verify that expired badges are deactivated and that unreturned badges are tracked."
  },
  {
    id: "9.3.4",
    title: "A visitor log is used to maintain a physical audit trail of visitor activity to the facility and to sensitive areas, including the visitor's name, the firm represented, and the onsite personnel authorizing physical access",
    description: "A visitor log must record all visitor activity including the visitor's name, organization, purpose of visit, date and time, and the name of the authorizing personnel. The log must be maintained for a minimum of three months and be available for review. Visitor logs provide an audit trail that supports investigation of physical security incidents.",
    testingProcedure: "Examine the visitor log and verify it captures all required information. Verify that the log is retained for at least three months and is available for review."
  },
  {
    id: "9.4.1",
    title: "All media with cardholder data is physically secured",
    description: "All physical media containing cardholder data must be stored in a physically secure location with restricted access. This includes backup tapes, removable drives, paper records, and any other media that contains cardholder data. Physical security controls must prevent unauthorized access to, theft of, or damage to media containing sensitive data.",
    testingProcedure: "Examine media storage locations and verify they are physically secured with appropriate access controls. Verify that access to media storage areas is restricted to authorized personnel."
  },
  {
    id: "9.4.1.1",
    title: "Offline media backups with cardholder data are stored in a secure location",
    description: "Offline backup media containing cardholder data must be stored in a secure location, preferably offsite, with physical access controls. The storage location must be protected against environmental threats such as fire and flood. Secure offsite storage ensures that backup media is available for recovery while being protected from the same threats that might affect the primary location.",
    testingProcedure: "Examine the storage locations for offline media backups and verify they are physically secure. Verify that access controls are in place and that the location is protected against environmental threats."
  },
  {
    id: "9.4.1.2",
    title: "The security of the offline media backup location(s) is reviewed at least once every 12 months",
    description: "The physical security of offline backup media storage locations must be reviewed at least annually to ensure that security controls remain effective. The review must assess the adequacy of physical access controls, environmental protections, and any changes to the storage location. Annual reviews detect and address deterioration of physical security measures over time.",
    testingProcedure: "Examine records of annual security reviews for offline backup storage locations. Verify that reviews assess physical access controls and environmental protections and that identified issues are remediated."
  },
  {
    id: "9.4.2",
    title: "All media with cardholder data is classified in accordance with the sensitivity of the data",
    description: "All media containing cardholder data must be classified according to the data sensitivity level to ensure appropriate handling and protection. Classification must be clearly marked on the media to indicate the required level of protection. Proper classification ensures that media handlers understand the sensitivity of the data they are working with and apply appropriate safeguards.",
    testingProcedure: "Examine media classification procedures and verify that media containing cardholder data is classified and labeled. Verify that classification levels correspond to appropriate handling requirements."
  },
  {
    id: "9.4.3",
    title: "Media with cardholder data sent outside the facility is secured as follows: media sent outside the facility is logged, media is sent by secured courier or other delivery method that can be accurately tracked, and management approves media before it is moved outside the facility",
    description: "When media containing cardholder data must be sent outside the facility, it must be logged, sent via a trackable delivery method, and approved by management prior to the transfer. The delivery method must provide tracking throughout transit to enable verification of receipt. These controls provide accountability and traceability for media containing sensitive data when it leaves the secure perimeter.",
    testingProcedure: "Examine media transfer logs and verify that all outbound media transfers are documented with management approval. Verify that media is sent via trackable delivery methods and that delivery receipts are obtained."
  },
  {
    id: "9.4.4",
    title: "Management approves all media with cardholder data that is moved outside the facility (including when media is distributed to individuals)",
    description: "Any movement of media containing cardholder data outside the secure facility must receive explicit management approval prior to the transfer. The approval must document the purpose of the transfer, the destination, and the expected return date if applicable. Management approval ensures that transfers are legitimate and that proper security measures are in place for the media while outside the facility.",
    testingProcedure: "Examine records of media transfers and verify that management approval is documented for each instance. Interview management to confirm they review and approve media movements before they occur."
  },
  {
    id: "9.4.5",
    title: "Inventory logs of all electronic media with cardholder data are maintained",
    description: "An inventory of all electronic media containing cardholder data must be maintained and updated when media is created, moved, or destroyed. The inventory must track the location and custodian of each piece of media. Regular inventory reconciliation helps detect lost or stolen media promptly, enabling timely response to potential data exposure.",
    testingProcedure: "Examine the media inventory log and verify it includes all electronic media containing cardholder data. Verify that the inventory is current and includes location and custodian information."
  },
  {
    id: "9.4.5.1",
    title: "Inventories of electronic media with cardholder data are conducted at least once every 12 months",
    description: "A formal inventory of all electronic media containing cardholder data must be conducted at least annually. The inventory must reconcile the physical media present against the documented inventory to identify any discrepancies such as missing or unaccounted media. Annual inventories are essential for detecting loss or theft of media that may have gone unnoticed.",
    testingProcedure: "Examine inventory records and verify that electronic media inventories are conducted at least annually. Verify that inventory results are reconciled against documented records and that discrepancies are investigated."
  },
  {
    id: "9.4.6",
    title: "Hard-copy materials with cardholder data are destroyed when no longer needed for business or legal reasons",
    description: "Hard-copy materials containing cardholder data must be securely destroyed when they are no longer needed for business or legal purposes. Destruction methods must include cross-cut shredding, incineration, or pulping that renders the data unrecoverable. Improperly discarded hard-copy materials are a common source of data compromise through dumpster diving.",
    testingProcedure: "Examine destruction procedures and records to verify that hard-copy materials with cardholder data are securely destroyed. Observe the destruction process to confirm it renders data unrecoverable."
  },
  {
    id: "9.4.7",
    title: "Electronic media with cardholder data is destroyed when no longer needed for business or legal reasons using secure methods that render cardholder data unrecoverable",
    description: "Electronic media containing cardholder data must be securely destroyed when no longer needed using methods that make the data unrecoverable. Acceptable methods include degaussing, physical destruction, or cryptographic erasure using approved tools. Simply deleting files or reformatting media does not securely destroy data and leaves it recoverable with readily available tools.",
    testingProcedure: "Examine destruction procedures and records for electronic media containing cardholder data. Verify that approved secure destruction methods are used that render data unrecoverable."
  },
  {
    id: "9.5.1",
    title: "POI devices are protected from tampering and unauthorized substitution, including maintaining a list of POI devices, periodically inspecting devices, and training personnel to be aware of suspicious behavior",
    description: "Point-of-interaction devices such as card readers and POS terminals must be protected from tampering and unauthorized substitution. A list of all POI devices must be maintained with details including make, model, serial number, and location. Regular inspections must be conducted to detect tampering signs such as broken seals, unexpected attachments, or serial number changes.",
    testingProcedure: "Examine the POI device inventory and verify it includes all required details. Examine inspection records and verify that periodic inspections are conducted to detect tampering or substitution."
  },
  {
    id: "9.5.1.1",
    title: "An up-to-date list of POI devices is maintained, including make, model, location, and serial number or other method of unique identification",
    description: "A current and accurate inventory of all POI devices must be maintained, including the make, model, location, and serial number or other unique identifier for each device. The inventory must be updated whenever devices are added, removed, or relocated. An accurate POI device inventory enables the detection of unauthorized device substitution or addition.",
    testingProcedure: "Examine the POI device list and verify it includes make, model, location, and serial number for each device. Compare the list against physical devices to verify accuracy."
  },
  {
    id: "9.5.1.2",
    title: "POI device surfaces are periodically inspected to detect tampering and unauthorized substitution",
    description: "The physical surfaces of POI devices must be inspected periodically to detect signs of tampering such as card skimmers, overlays, or unauthorized modifications. Inspections must also verify that serial numbers match the device inventory to detect unauthorized device substitution. The inspection frequency must be determined through a targeted risk analysis based on factors such as device location and accessibility.",
    testingProcedure: "Examine inspection procedures and records to verify that POI devices are periodically inspected for tampering. Observe an inspection to verify that inspectors check for tampering indicators and verify serial numbers."
  },
  {
    id: "9.5.1.2.1",
    title: "The frequency of periodic POI device inspections and the type of inspections performed is defined in the entity's targeted risk analysis",
    description: "The frequency and scope of POI device inspections must be determined through a documented targeted risk analysis. The risk analysis must consider factors such as the type and location of devices, the level of supervision, and the risk of tampering. Higher-risk devices and locations should receive more frequent and thorough inspections.",
    testingProcedure: "Examine the targeted risk analysis and verify it defines inspection frequencies and types based on assessed risk. Verify that actual inspection practices align with the risk analysis findings."
  },
  {
    id: "9.5.1.3",
    title: "Training is provided for personnel in POI environments to be aware of attempted tampering or replacement of POI devices",
    description: "Personnel who work in environments with POI devices must be trained to recognize signs of device tampering or unauthorized substitution. Training must cover indicators of tampering such as unexpected attachments, broken seals, and changes in device appearance or behavior. Personnel must know how to report suspected tampering and the importance of verifying device integrity.",
    testingProcedure: "Examine training materials and records to verify that personnel are trained on POI device tampering awareness. Interview personnel to confirm they understand how to recognize and report suspected tampering."
  },

  // ============================================================
  // REQUIREMENT 10: Log and Monitor All Access to System Components and Cardholder Data
  // ============================================================
  {
    id: "10.1.1",
    title: "All security policies and operational procedures identified in Requirement 10 are documented, kept up to date, in use, and known to all affected parties",
    description: "All policies and procedures for logging and monitoring access to system components and cardholder data must be documented, current, and communicated. Documentation must cover log generation, protection, review, and retention requirements. Comprehensive logging and monitoring policies are essential for detecting and responding to security incidents.",
    testingProcedure: "Examine documentation to verify that all Requirement 10 policies and procedures exist and are current. Interview personnel to confirm awareness and adherence to the logging and monitoring policies."
  },
  {
    id: "10.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 10 are documented, assigned, and understood",
    description: "Specific roles and responsibilities for logging and monitoring activities must be formally assigned and documented. Personnel must understand their responsibilities for configuring, maintaining, and reviewing logs. Clear assignment ensures accountability for the critical function of security monitoring.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for Requirement 10 activities are assigned. Interview responsible personnel to confirm understanding of their monitoring duties."
  },
  {
    id: "10.2.1",
    title: "Audit logs are enabled and active for all system components and cardholder data",
    description: "Audit logging must be enabled on all system components within the cardholder data environment and on systems that store, process, or transmit cardholder data. Logs must be actively recording events and must capture sufficient detail to support security monitoring and forensic investigation. Disabled or incomplete logging prevents the detection of unauthorized activity.",
    testingProcedure: "Examine audit log configurations for all system components and verify that logging is enabled and active. Verify that logs are being generated and contain the required event information."
  },
  {
    id: "10.2.1.1",
    title: "Audit logs capture all individual user access to cardholder data",
    description: "Audit logs must record every instance of individual user access to cardholder data, including who accessed the data, when, and what data was accessed. This provides a detailed trail of all data access that supports both routine monitoring and forensic investigation. Without logging data access, unauthorized access to cardholder data may go undetected.",
    testingProcedure: "Examine audit log configurations and sample log entries to verify that all individual user access to cardholder data is recorded. Verify that log entries include user identity, date, time, and the data accessed."
  },
  {
    id: "10.2.1.2",
    title: "Audit logs capture all actions taken by any individual with administrative access, including any interactive use of application or system accounts",
    description: "All actions performed by users with administrative or root access must be logged, including any interactive use of application or system accounts. This provides accountability for privileged operations and enables detection of misuse of elevated privileges. Administrative actions have the greatest potential impact and require the most thorough logging.",
    testingProcedure: "Examine audit log configurations and verify that all administrative actions are logged. Verify that interactive use of application and system accounts is also captured in the audit logs."
  },
  {
    id: "10.2.1.3",
    title: "Audit logs capture all access to audit logs",
    description: "All access to audit logs must itself be logged to prevent unauthorized viewing, modification, or deletion of log data. This creates a meta-audit trail that protects the integrity of the logging system. If attackers can access or modify logs without detection, they can cover their tracks and prevent incident detection.",
    testingProcedure: "Examine audit log configurations and verify that access to log files and logging systems is recorded. Verify that log access events include the identity of the user, date, time, and type of access."
  },
  {
    id: "10.2.1.4",
    title: "Audit logs capture all invalid logical access attempts",
    description: "All invalid or failed logical access attempts must be recorded in audit logs, including failed login attempts, failed attempts to access restricted resources, and authorization failures. Patterns of failed access attempts may indicate a brute-force attack, credential stuffing, or reconnaissance activity. Logging these events is essential for detecting attack attempts in progress.",
    testingProcedure: "Examine audit log configurations and verify that invalid logical access attempts are logged. Examine sample log entries to confirm that failed authentication and authorization attempts are recorded."
  },
  {
    id: "10.2.1.5",
    title: "Audit logs capture all changes to identification and authentication credentials including but not limited to creation of new accounts, elevation of privileges, and all changes, additions, or deletions to accounts with administrative access",
    description: "All changes to identification and authentication credentials must be logged, including new account creation, privilege modifications, and changes to administrative accounts. This provides visibility into identity management activities that could indicate unauthorized account manipulation. Account and privilege changes are commonly performed by attackers to establish persistence.",
    testingProcedure: "Examine audit log configurations and verify that credential and account changes are logged. Examine sample logs to confirm that new account creation, privilege changes, and administrative account modifications are recorded."
  },
  {
    id: "10.2.1.6",
    title: "Audit logs capture the following: all initialization of new audit logs, and all starting, stopping, or pausing of the existing audit logs",
    description: "The initialization of new audit logs and any starting, stopping, or pausing of existing logs must be captured. This ensures that any interruption in logging, whether accidental or malicious, is detectable. Attackers may attempt to stop logging before performing unauthorized actions, and this requirement ensures such attempts are recorded.",
    testingProcedure: "Examine audit log configurations and verify that log initialization, start, stop, and pause events are logged. Test by stopping and restarting logging to verify that these events are captured."
  },
  {
    id: "10.2.1.7",
    title: "Audit logs capture all creation and deletion of system-level objects",
    description: "The creation and deletion of system-level objects such as files, databases, users, and system services must be recorded in audit logs. Changes to system-level objects may indicate unauthorized system modification or the installation of malicious software. Logging these events enables detection of unauthorized system changes.",
    testingProcedure: "Examine audit log configurations and verify that creation and deletion of system-level objects is logged. Examine sample log entries to confirm these events are captured with sufficient detail."
  },
  {
    id: "10.2.2",
    title: "Audit logs record the following details for each auditable event: user identification, type of event, date and time, success and failure indication, origination of event, and identity or name of affected data, system component, resource, or service",
    description: "Each audit log entry must include sufficient detail to identify who performed the action, what was done, when it occurred, whether it was successful, where the event originated, and what was affected. These details are essential for effective security monitoring and forensic investigation. Incomplete log entries reduce the value of logging for detecting and investigating security incidents.",
    testingProcedure: "Examine sample audit log entries for various event types and verify that all required details are present. Verify that the log format consistently captures user identification, event type, timestamp, success or failure, source, and affected resource."
  },
  {
    id: "10.3.1",
    title: "Read access to time-sensitive audit logs files is limited to those with a job-related need",
    description: "Read access to audit log files must be restricted to personnel with a documented job-related need to review logs. This prevents unauthorized individuals from viewing log data that could contain sensitive information or reveal security monitoring capabilities. Access restrictions must be enforced through file system permissions and access control mechanisms.",
    testingProcedure: "Examine access controls on audit log files and verify that read access is restricted to authorized personnel. Verify that access is based on documented job-related need."
  },
  {
    id: "10.3.2",
    title: "Audit log files are protected to prevent modifications by individuals",
    description: "Audit log files must be protected from modification by individual users, including system administrators. Write-once media, integrity monitoring, or centralized log management systems should be used to prevent log tampering. If an attacker can modify logs, they can erase evidence of their activities and prevent incident detection.",
    testingProcedure: "Examine log protection mechanisms and verify that audit log files cannot be modified by individuals. Verify that integrity monitoring or write-once storage is used to detect or prevent unauthorized modifications."
  },
  {
    id: "10.3.3",
    title: "Audit log files, including those for external-facing technologies, are promptly backed up to a secure, central, internal log server(s) or other media that is difficult to alter",
    description: "Audit logs must be promptly transmitted to a centralized log management system or backed up to media that is difficult to alter. This ensures that log data is preserved even if the originating system is compromised. Centralized log management also enables correlation of events across multiple systems for more effective security monitoring.",
    testingProcedure: "Examine log backup and centralization configurations and verify that logs are promptly transmitted to a secure central location. Verify that the central log storage is protected from unauthorized modification."
  },
  {
    id: "10.3.4",
    title: "File integrity monitoring or change-detection mechanisms is used on audit logs to ensure that existing log data cannot be changed without generating alerts",
    description: "File integrity monitoring or change-detection mechanisms must be deployed on audit logs to detect any unauthorized modifications to existing log data. Alerts must be generated when changes are detected so that incident response procedures can be initiated. Integrity monitoring provides assurance that log data has not been tampered with and can be relied upon for investigation.",
    testingProcedure: "Examine file integrity monitoring configurations for audit logs and verify that monitoring is active. Verify that alerts are generated when log modifications are detected."
  },
  {
    id: "10.4.1",
    title: "The following audit logs are reviewed at least once daily: all security events, logs of all system components that store, process, or transmit CHD and/or SAD, logs of all critical system components, and logs of all servers and system components that perform security functions",
    description: "Specified audit logs must be reviewed at least daily to detect suspicious or anomalous activity. Reviews must cover security events, CDE components, critical systems, and security function components. Daily review is necessary because attackers can accomplish significant damage within hours of initial access if their activity goes undetected.",
    testingProcedure: "Examine log review procedures and records to verify that specified logs are reviewed at least daily. Verify that reviews are documented and that identified anomalies are investigated."
  },
  {
    id: "10.4.1.1",
    title: "Automated mechanisms are used to perform audit log reviews",
    description: "Automated tools and mechanisms must be used to support the review of audit logs, given the volume of log data generated in most environments. Security information and event management systems, log analysis tools, and automated alerting help identify significant events that require human review. Purely manual log review is insufficient for the volume and velocity of log data in modern environments.",
    testingProcedure: "Examine the automated log review tools and configurations and verify they are actively analyzing logs. Verify that automated mechanisms generate alerts for events requiring human investigation."
  },
  {
    id: "10.4.2",
    title: "Logs of all other system components (those not specified in Requirement 10.4.1) are reviewed periodically",
    description: "Logs from system components not covered by the daily review requirement must be reviewed periodically based on the organization's risk assessment. The review frequency must be defined in the organization's targeted risk analysis and must be appropriate for the risk level of the systems. Periodic review of all logs ensures that no system component escapes security monitoring entirely.",
    testingProcedure: "Examine the targeted risk analysis and verify it defines review frequencies for all system component logs. Verify that periodic reviews are conducted according to the defined schedule."
  },
  {
    id: "10.4.2.1",
    title: "The frequency of periodic log reviews for all other system components is defined in the entity's targeted risk analysis",
    description: "The frequency at which logs from systems not subject to daily review are reviewed must be determined through a documented targeted risk analysis. The risk analysis must consider the function and criticality of each system, the type of data it processes, and its exposure to threats. Higher-risk systems should have more frequent log reviews.",
    testingProcedure: "Examine the targeted risk analysis and verify it specifically addresses log review frequency for each system type. Verify that actual log review frequencies match the risk analysis findings."
  },
  {
    id: "10.4.3",
    title: "Exceptions and anomalies identified during the review process are addressed",
    description: "Exceptions and anomalies identified during log reviews must be investigated and addressed through a formal process. The investigation must determine whether the anomaly represents a security incident or a false positive, and appropriate actions must be taken. Failure to follow up on identified anomalies defeats the purpose of conducting log reviews.",
    testingProcedure: "Examine records of exceptions and anomalies identified during log reviews and verify that each was investigated. Verify that appropriate actions were taken and documented for each identified issue."
  },
  {
    id: "10.5.1",
    title: "Retain audit log history for at least 12 months, with at least the most recent three months immediately available for analysis",
    description: "Audit logs must be retained for a minimum of 12 months to support forensic investigation of security incidents that may not be discovered immediately. The most recent three months of logs must be immediately accessible for analysis without requiring restoration from archives. Longer retention periods may be required by specific legal or regulatory requirements.",
    testingProcedure: "Examine log retention configurations and archived logs to verify that 12 months of log history is maintained. Verify that the most recent three months of logs are immediately accessible for analysis."
  },
  {
    id: "10.6.1",
    title: "System clocks and time are synchronized using time-synchronization technology",
    description: "All system clocks within the cardholder data environment must be synchronized using a common time-synchronization technology such as NTP or PTP. Accurate and consistent time across all systems is essential for correlating events during security investigations and for maintaining the integrity of audit log timestamps. Time discrepancies between systems can make forensic analysis extremely difficult.",
    testingProcedure: "Examine time synchronization configurations for system components and verify they are synchronized to a common time source. Verify that the time synchronization service is running and operational."
  },
  {
    id: "10.6.2",
    title: "Systems are configured to the correct and consistent time as follows: one or more designated time servers are in use, only the designated central time server(s) receive time from external sources, time received from external sources is based on International Atomic Time or UTC, and the designated time server(s) accept time updates only from specific, industry-accepted external sources",
    description: "Time synchronization must be configured with designated internal time servers that receive time from approved external sources based on International Atomic Time or UTC. Only designated time servers may communicate with external time sources, and all other systems must synchronize from the internal time servers. This hierarchical approach ensures consistent time throughout the environment while limiting external communication.",
    testingProcedure: "Examine time synchronization configurations and verify the hierarchical time server architecture. Verify that external time sources are industry-accepted and that only designated servers receive external time."
  },
  {
    id: "10.6.3",
    title: "Time synchronization settings and data are protected as follows: access to time data is restricted to only personnel with a business need, and any changes to time settings on critical systems are logged, monitored, and reviewed",
    description: "Access to time synchronization settings and data must be restricted to authorized personnel to prevent unauthorized modification. Changes to time settings on critical systems must be logged and monitored because unauthorized time changes could be used to manipulate audit log timestamps and obscure evidence of security incidents. Time integrity is fundamental to the reliability of the entire audit logging system.",
    testingProcedure: "Examine access controls on time synchronization configurations and verify they are restricted to authorized personnel. Verify that changes to time settings are logged, monitored, and reviewed."
  },
  {
    id: "10.7.1",
    title: "Additional requirement for service providers only: Failures of critical security control systems are detected, alerted, and addressed promptly, including but not limited to failure of network security controls, IDS/IPS, FIM, anti-malware, physical access controls, logical access controls, audit logging mechanisms, and segmentation controls",
    description: "Service providers must implement mechanisms to promptly detect, alert on, and respond to failures of critical security control systems. This includes monitoring for failures of firewalls, intrusion detection systems, file integrity monitoring, anti-malware, access controls, logging systems, and segmentation controls. Prompt detection of security control failures enables rapid response to prevent exploitation of the gap in protection.",
    testingProcedure: "Examine monitoring configurations and verify that failures of all critical security controls are detected and generate alerts. Examine incident records to verify that detected failures are addressed promptly."
  },
  {
    id: "10.7.2",
    title: "Failures of critical security control systems are detected, alerted, and addressed promptly",
    description: "All entities must detect, alert on, and promptly address failures of critical security control systems. This includes monitoring the health and operational status of security controls and implementing automated alerting for failures. The time between a security control failure and its resolution represents a window of increased vulnerability that must be minimized.",
    testingProcedure: "Examine monitoring configurations for critical security controls and verify that failure detection and alerting are implemented. Verify that failures are addressed within defined response timeframes."
  },
  {
    id: "10.7.3",
    title: "Failures of any critical security controls are responded to promptly, including but not limited to restoring security functions, identifying and documenting the duration of the security failure, identifying and documenting the cause(s) of failure, identifying and addressing any security issues that arose during the failure, determining whether further actions are required as a result of the security failure, implementing controls to prevent the cause of failure from recurring, and resuming monitoring of security controls",
    description: "When critical security control failures occur, a formal response process must be followed that includes restoring security functions, documenting the failure duration and cause, assessing the security impact, and implementing corrective actions. The response must also include measures to prevent recurrence and verification that monitoring has resumed. Thorough incident response for security control failures ensures that the root cause is addressed and future failures are prevented.",
    testingProcedure: "Examine records of security control failures and verify that the formal response process was followed. Verify that all required response actions including root cause analysis, corrective actions, and resumed monitoring are documented."
  },

  // ============================================================
  // REQUIREMENT 11: Test Security of Systems and Networks Regularly
  // ============================================================
  {
    id: "11.1.1",
    title: "All security policies and operational procedures identified in Requirement 11 are documented, kept up to date, in use, and known to all affected parties",
    description: "All policies and procedures for regular security testing must be documented, current, and communicated to all relevant personnel. Documentation must cover vulnerability scanning, penetration testing, wireless detection, and change detection requirements. Regular review ensures the testing program addresses evolving threats and technologies.",
    testingProcedure: "Examine documentation to verify that all Requirement 11 policies and procedures exist and are current. Interview personnel to confirm awareness and adherence to the security testing policies."
  },
  {
    id: "11.1.2",
    title: "Roles and responsibilities for performing activities in Requirement 11 are documented, assigned, and understood",
    description: "Specific roles and responsibilities for security testing activities must be formally assigned and documented. Personnel must understand their responsibilities for conducting, overseeing, and remediating the results of security tests. Clear role assignment ensures accountability for the regular security testing program.",
    testingProcedure: "Examine documentation to verify that roles and responsibilities for Requirement 11 activities are assigned. Interview responsible personnel to confirm understanding of their security testing duties."
  },
  {
    id: "11.2.1",
    title: "Authorized and unauthorized wireless access points are managed as follows: the presence of wireless (Wi-Fi) access points is tested for, all authorized and unauthorized wireless access points are detected and identified, and testing, detection, and identification occurs at least once every three months",
    description: "A wireless access point detection process must be implemented that identifies both authorized and unauthorized wireless access points within the environment. Testing must occur at least quarterly using wireless scanning, network access control monitoring, or wireless IDS/IPS. Rogue wireless access points can provide an unauthorized entry point into the network that bypasses wired network security controls.",
    testingProcedure: "Examine wireless detection records and verify that testing occurs at least quarterly. Verify that the process identifies both authorized and unauthorized wireless access points and that unauthorized access points are addressed."
  },
  {
    id: "11.2.2",
    title: "An inventory of authorized wireless access points is maintained, including a documented business justification",
    description: "A current inventory of all authorized wireless access points must be maintained, with documented business justification for each access point. The inventory must include details such as location, SSID, security configuration, and the business purpose of each access point. This inventory enables rapid identification of unauthorized access points by comparison during wireless scanning activities.",
    testingProcedure: "Examine the authorized wireless access point inventory and verify it is current and complete. Verify that each access point has documented business justification."
  },
  {
    id: "11.3.1",
    title: "Internal vulnerability scans are performed at least once every three months",
    description: "Internal vulnerability scanning must be performed at least quarterly to identify known security vulnerabilities in system components within the cardholder data environment. Scans must cover all system components and must be performed using qualified personnel or tools. Quarterly internal scanning provides regular assessment of the internal security posture and identification of newly discovered vulnerabilities.",
    testingProcedure: "Examine internal vulnerability scan reports and verify that scans are performed at least quarterly. Verify that scans cover all in-scope system components."
  },
  {
    id: "11.3.1.1",
    title: "All other applicable vulnerabilities (those not ranked as high-risk or critical) found during internal vulnerability scans are managed as follows: addressed based on the risk defined in the entity's targeted risk analysis, and rescans are conducted as needed",
    description: "Vulnerabilities that are not rated as high-risk or critical must still be addressed based on the risk level determined through the organization's targeted risk analysis. The risk analysis must define remediation timeframes based on vulnerability severity and the risk to the environment. Rescans must be conducted to verify that vulnerabilities have been successfully remediated.",
    testingProcedure: "Examine the targeted risk analysis for non-critical vulnerabilities and verify that remediation timeframes are defined. Examine vulnerability management records to verify that vulnerabilities are remediated and rescanned according to the defined schedule."
  },
  {
    id: "11.3.1.2",
    title: "Internal vulnerability scans are performed via authenticated scanning",
    description: "Internal vulnerability scans must use authenticated scanning techniques that provide the scanner with credentials to log into system components. Authenticated scanning provides significantly more thorough results by enabling the scanner to examine system configurations, installed software, and patch levels from within the system. Unauthenticated scans can miss many vulnerabilities that are only visible to authenticated users.",
    testingProcedure: "Examine vulnerability scan configurations and verify that authenticated scanning is used. Compare scan results from authenticated and unauthenticated scans to verify the increased coverage provided by authentication."
  },
  {
    id: "11.3.1.3",
    title: "Internal vulnerability scans are performed after any significant change",
    description: "Internal vulnerability scans must be performed after any significant change to the environment, such as new system installations, network topology changes, or firewall rule modifications. Post-change scanning verifies that the changes have not introduced new vulnerabilities or weakened existing security controls. The definition of significant change must be documented and understood by relevant personnel.",
    testingProcedure: "Examine records of significant changes and corresponding vulnerability scan results. Verify that internal scans are performed after significant changes and that identified vulnerabilities are remediated."
  },
  {
    id: "11.3.2",
    title: "External vulnerability scans are performed at least once every three months",
    description: "External vulnerability scanning must be performed at least quarterly by a PCI SSC Approved Scanning Vendor (ASV) to identify vulnerabilities visible from outside the network perimeter. External scans assess the security posture of internet-facing systems and services. ASV scans must result in a passing score, with all vulnerabilities rated 4.0 or higher on the CVSS scale remediated.",
    testingProcedure: "Examine external vulnerability scan reports from the ASV and verify that scans are performed at least quarterly. Verify that passing scan results are achieved with appropriate remediation of identified vulnerabilities."
  },
  {
    id: "11.3.2.1",
    title: "External vulnerability scans are performed after any significant change",
    description: "External vulnerability scans must be performed after any significant change to internet-facing systems or services. Post-change scanning verifies that changes have not introduced new external vulnerabilities. The scans must be performed by a PCI SSC Approved Scanning Vendor and must result in a passing score.",
    testingProcedure: "Examine records of significant changes to external-facing systems and corresponding ASV scan results. Verify that external scans are performed after significant changes and produce passing results."
  },
  {
    id: "11.4.1",
    title: "A penetration testing methodology is defined, documented, and implemented by the entity that includes industry-accepted penetration testing approaches, coverage for the entire CDE perimeter and critical systems, testing from both inside and outside the network, testing to validate any segmentation and scope-reduction controls, application-layer penetration testing, and network-layer penetration testing",
    description: "The organization must define and document a penetration testing methodology based on industry-accepted approaches such as NIST SP 800-115, OWASP, or PTES. The methodology must address testing from both inside and outside the network, cover both network-layer and application-layer testing, and include validation of segmentation controls. A well-defined methodology ensures consistent and thorough penetration testing across the environment.",
    testingProcedure: "Examine the penetration testing methodology and verify it includes all required elements. Verify that the methodology references industry-accepted approaches and covers both internal and external testing perspectives."
  },
  {
    id: "11.4.2",
    title: "Internal penetration testing is performed at least once every 12 months and after any significant infrastructure or application upgrade or change",
    description: "Internal penetration testing must be performed at least annually and after significant changes to the infrastructure or applications. Internal testing simulates an attacker who has already gained access to the internal network to evaluate the effectiveness of internal security controls. Testing must be performed by qualified personnel who are independent of the systems being tested.",
    testingProcedure: "Examine internal penetration test reports and verify that testing is performed at least annually and after significant changes. Verify that the testing was conducted by qualified, independent personnel."
  },
  {
    id: "11.4.3",
    title: "External penetration testing is performed at least once every 12 months and after any significant infrastructure or application upgrade or change",
    description: "External penetration testing must be performed at least annually and after significant changes to external-facing infrastructure or applications. External testing evaluates the effectiveness of perimeter security controls from an attacker's perspective outside the network. Testing must be performed by qualified personnel or organizations with appropriate penetration testing experience.",
    testingProcedure: "Examine external penetration test reports and verify that testing is performed at least annually and after significant changes. Verify that the testing was conducted by qualified professionals."
  },
  {
    id: "11.4.4",
    title: "Exploitable vulnerabilities and security weaknesses found during penetration testing are corrected and testing is repeated to verify the corrections",
    description: "All exploitable vulnerabilities and security weaknesses identified during penetration testing must be remediated and retested to verify that the remediation was effective. The retesting must be performed using the same testing techniques that originally identified the vulnerability. Failure to remediate and verify corrections means that known vulnerabilities remain in the environment.",
    testingProcedure: "Examine penetration test reports and remediation records to verify that all identified vulnerabilities were corrected. Examine retest results to verify that corrections were effective."
  },
  {
    id: "11.4.5",
    title: "If segmentation is used to isolate the CDE from other networks, penetration tests are performed on segmentation controls at least once every 12 months and after any changes to segmentation controls/methods",
    description: "When network segmentation is used to reduce the scope of PCI DSS compliance, penetration testing must be performed specifically on the segmentation controls at least annually and after any changes to segmentation. The testing must verify that segmentation is effective at isolating the CDE from out-of-scope networks. Ineffective segmentation could expose cardholder data to systems and users that are not subject to PCI DSS controls.",
    testingProcedure: "Examine segmentation penetration test reports and verify that testing is performed at least annually and after changes to segmentation controls. Verify that tests confirm the effectiveness of segmentation in isolating the CDE."
  },
  {
    id: "11.4.6",
    title: "Additional requirement for service providers only: If segmentation is used, penetration tests on segmentation controls are performed at least once every six months and after any changes to segmentation controls/methods",
    description: "Service providers that use segmentation to reduce PCI DSS scope must test segmentation controls at least every six months and after changes, rather than the 12-month frequency required for other entities. The increased frequency reflects the higher risk associated with service provider environments that may process cardholder data for multiple clients. More frequent testing provides greater assurance that segmentation remains effective.",
    testingProcedure: "Examine segmentation penetration test reports for service providers and verify that testing occurs at least every six months. Verify that additional testing is performed after any changes to segmentation controls."
  },
  {
    id: "11.4.7",
    title: "Additional requirement for multi-tenant service providers only: Multi-tenant service providers support their customers for external penetration testing per Requirement 11.4.3 and 11.4.4",
    description: "Multi-tenant service providers must support their customers in performing external penetration testing of their environment. This includes providing reasonable access and cooperation for customer-initiated testing activities. The service provider must define and communicate the process by which customers can request and conduct external penetration testing.",
    testingProcedure: "Examine the service provider's process for supporting customer external penetration testing. Verify that customers are informed of the process and that testing requests are accommodated."
  },
  {
    id: "11.5.1",
    title: "Intrusion-detection and/or intrusion-prevention techniques are used to detect and/or prevent intrusions into the network as follows: all traffic at the perimeter of the CDE is monitored, all traffic at critical points in the CDE is monitored, and personnel are alerted to suspected compromises",
    description: "Intrusion detection or prevention systems must be deployed to monitor all traffic at the CDE perimeter and at critical points within the CDE. The systems must be configured to alert personnel when suspicious activity is detected that may indicate a compromise. IDS/IPS provides real-time monitoring capability that can detect attacks in progress and enable rapid response.",
    testingProcedure: "Examine IDS/IPS configurations and verify deployment at the CDE perimeter and critical internal points. Verify that alerting is configured and that personnel receive and respond to alerts."
  },
  {
    id: "11.5.1.1",
    title: "Intrusion-detection and/or intrusion-prevention techniques detect, alert on/prevent, and address covert malware communication channels",
    description: "IDS/IPS must be configured to detect and address covert communication channels that malware uses to communicate with command-and-control servers. This includes detecting DNS tunneling, encrypted communications to known malicious hosts, and other covert channels. Blocking covert channels prevents exfiltration of cardholder data and disrupts the attacker's ability to control compromised systems.",
    testingProcedure: "Examine IDS/IPS configurations and verify that covert malware communication detection is enabled. Verify that alerts are generated and that detected covert channels are blocked or investigated."
  },
  {
    id: "11.5.2",
    title: "A change-detection mechanism (for example, file integrity monitoring tools) is deployed to alert personnel to unauthorized modification of critical system files, configuration files, or content files, and the tools are configured to perform critical file comparisons at least once weekly",
    description: "File integrity monitoring or equivalent change-detection mechanisms must be deployed on critical system files, configuration files, and content files within the CDE. The mechanism must compare current file states against known good baselines at least weekly and generate alerts when unauthorized changes are detected. Change detection identifies unauthorized modifications that could indicate system compromise or configuration drift.",
    testingProcedure: "Examine file integrity monitoring configurations and verify deployment on critical system files and configuration files. Verify that comparisons are performed at least weekly and that alerts are generated for unauthorized changes."
  },
  {
    id: "11.6.1",
    title: "A change- and tamper-detection mechanism is deployed on payment pages to alert personnel to unauthorized modification, including to the HTTP headers and the contents of payment pages as received by the consumer browser",
    description: "Payment pages must be monitored for unauthorized modifications using change and tamper detection mechanisms. The monitoring must cover both HTTP headers and page content as received by the consumer's browser to detect web skimming attacks. This control specifically addresses the threat of attackers injecting malicious JavaScript into payment pages to capture cardholder data entered by customers.",
    testingProcedure: "Examine the change and tamper detection mechanism and verify it monitors payment page HTTP headers and content. Verify that alerts are generated when unauthorized modifications are detected."
  },

  // ============================================================
  // REQUIREMENT 12: Support Information Security with Organizational Policies and Programs
  // ============================================================
  {
    id: "12.1.1",
    title: "An overall information security policy is established, published, maintained, and disseminated to all relevant personnel, as well as relevant vendors and business partners",
    description: "The organization must establish and maintain a comprehensive information security policy that defines the organization's approach to protecting information assets. The policy must be published and distributed to all relevant personnel, vendors, and business partners. The information security policy serves as the foundation for all other security policies and procedures within the organization.",
    testingProcedure: "Examine the overall information security policy and verify it is published and current. Interview personnel, vendors, and business partners to verify they have received and are aware of the policy."
  },
  {
    id: "12.1.2",
    title: "The information security policy is reviewed at least once every 12 months and updated as needed to reflect changes to business objectives or the risk environment",
    description: "The information security policy must be reviewed at least annually and updated to reflect changes in business objectives, the risk environment, and the regulatory landscape. The review must be documented and include sign-off by management. Regular review ensures the policy remains relevant and effective as the organization and threat landscape evolve.",
    testingProcedure: "Examine policy review records and verify that the information security policy is reviewed at least annually. Verify that updates reflect current business objectives and risk factors."
  },
  {
    id: "12.1.3",
    title: "The security policy clearly defines information security roles and responsibilities for all personnel, and all personnel are aware of and acknowledge their information security responsibilities",
    description: "The information security policy must clearly define roles and responsibilities for all personnel related to information security. All personnel must acknowledge their security responsibilities, typically through signed acknowledgment forms or during onboarding. Clear definition and acknowledgment of roles ensures that everyone understands their part in maintaining the security of the organization.",
    testingProcedure: "Examine the security policy and verify it defines roles and responsibilities for all personnel. Examine acknowledgment records to verify that all personnel have acknowledged their security responsibilities."
  },
  {
    id: "12.1.4",
    title: "Responsibility for information security is formally assigned to a Chief Information Security Officer or other information security knowledgeable member of management",
    description: "Executive responsibility for information security must be formally assigned to a qualified individual such as a Chief Information Security Officer or equivalent management-level position. This individual must have the authority, resources, and organizational support necessary to effectively manage the information security program. Formal executive accountability ensures that security receives appropriate management attention and resources.",
    testingProcedure: "Examine organizational documentation and verify that information security responsibility is formally assigned to a qualified executive. Interview the designated individual to confirm they have the authority and resources to manage the security program."
  },
  {
    id: "12.2.1",
    title: "An acceptable use policy for end-user technologies is documented and implemented, including explicit approval by authorized parties, acceptable uses of the technology, and a list of products approved by the company for employee use",
    description: "An acceptable use policy must be documented for all end-user technologies that defines acceptable and prohibited uses, lists company-approved products, and requires explicit authorization for the use of technologies. The policy must address technologies such as laptops, mobile devices, removable media, email, and internet access. Clear acceptable use policies help prevent security incidents caused by inappropriate use of technology.",
    testingProcedure: "Examine the acceptable use policy and verify it includes all required elements. Interview personnel to confirm they are aware of and comply with the acceptable use policy."
  },
  {
    id: "12.3.1",
    title: "Each PCI DSS requirement that provides flexibility for how frequently it is performed (for example, requirements to be performed periodically) is supported by a targeted risk analysis that is documented and includes: identification of the assets being protected, identification of the threat(s) that the requirement is protecting against, identification of factors that contribute to the likelihood and/or impact of a threat being realized, resulting analysis that determines and includes justification for how frequently the requirement must be performed to minimize the likelihood of the threat being realized, and review of each targeted risk analysis at least once every 12 months",
    description: "For PCI DSS requirements that specify periodic performance without defining a specific frequency, the organization must conduct a targeted risk analysis to determine the appropriate frequency. The analysis must identify the protected assets, relevant threats, contributing factors, and provide justified reasoning for the chosen frequency. Risk analyses must be reviewed at least annually to ensure they remain valid.",
    testingProcedure: "Examine targeted risk analyses for requirements with flexible performance frequencies. Verify that each analysis includes all required elements and is reviewed at least annually."
  },
  {
    id: "12.3.2",
    title: "A targeted risk analysis is performed for each PCI DSS requirement that the entity meets with the customized approach",
    description: "When an entity uses the PCI DSS customized approach to meet a requirement, a targeted risk analysis must be performed to demonstrate that the customized control provides at least an equivalent level of security. The analysis must identify the risks being addressed, describe the customized control, and demonstrate its effectiveness. This ensures that the customized approach genuinely meets the security objective of the original requirement.",
    testingProcedure: "Examine targeted risk analyses for customized approach implementations. Verify that each analysis demonstrates the customized control provides at least equivalent security to the defined approach."
  },
  {
    id: "12.3.3",
    title: "Cryptographic cipher suites and protocols in use are documented and reviewed at least once every 12 months",
    description: "The organization must maintain documentation of all cryptographic cipher suites and protocols in use and review this documentation at least annually. The review must assess whether the cipher suites and protocols in use remain secure and appropriate. As cryptographic vulnerabilities are discovered over time, regular review ensures that outdated or weakened algorithms are identified and replaced.",
    testingProcedure: "Examine the documentation of cryptographic cipher suites and protocols in use. Verify that the documentation is reviewed at least annually and that insecure or outdated cryptographic implementations are identified for replacement."
  },
  {
    id: "12.3.4",
    title: "Hardware and software technologies in use are reviewed at least once every 12 months to confirm they continue to receive security fixes from vendors, and technologies approaching end of life are identified",
    description: "All hardware and software technologies must be reviewed at least annually to verify they continue to receive security updates from vendors. Technologies approaching or at end of life must be identified and a plan developed for their replacement or migration. Using technologies that no longer receive security fixes exposes the environment to unpatched vulnerabilities.",
    testingProcedure: "Examine the technology review documentation and verify that all hardware and software is reviewed annually for vendor support status. Verify that end-of-life technologies are identified and remediation plans are documented."
  },
  {
    id: "12.4.1",
    title: "Additional requirement for service providers only: Responsibility is established by executive management for the protection of cardholder data and a PCI DSS compliance program, including overall accountability for maintaining PCI DSS compliance, defining a charter for a PCI DSS compliance program, and providing updates to executive management and the board of directors",
    description: "Service provider executive management must take formal responsibility for cardholder data protection and PCI DSS compliance. A formal PCI DSS compliance program charter must be established, and regular updates on compliance status must be provided to executive management and the board of directors. Executive engagement ensures that PCI DSS compliance receives adequate organizational support and resources.",
    testingProcedure: "Examine the PCI DSS compliance program charter and verify executive management accountability is established. Examine records of executive and board updates on PCI DSS compliance status."
  },
  {
    id: "12.4.2",
    title: "Additional requirement for service providers only: Reviews are performed at least once every three months to confirm that personnel are performing their tasks in accordance with all security policies and all operational procedures",
    description: "Service providers must conduct quarterly reviews to confirm that personnel are performing their security-related tasks according to documented policies and procedures. The reviews must cover all critical security activities and result in documented findings and corrective actions where needed. Quarterly reviews help ensure that documented security controls are actually being implemented and followed consistently.",
    testingProcedure: "Examine quarterly review records and verify that personnel task compliance is assessed every three months. Verify that review findings and corrective actions are documented."
  },
  {
    id: "12.4.2.1",
    title: "Additional requirement for service providers only: Reviews performed in accordance with Requirement 12.4.2 are documented to include results of the reviews, documented remediation actions taken for any tasks that were found to not be performed, and review and sign-off of results by personnel assigned responsibility for the PCI DSS compliance program",
    description: "The quarterly compliance reviews required for service providers must be documented with review results, remediation actions for any deficiencies found, and sign-off by the personnel responsible for the PCI DSS compliance program. Documentation provides evidence of ongoing compliance monitoring and accountability for addressing identified gaps. Sign-off ensures that responsible personnel are aware of and accept the review findings.",
    testingProcedure: "Examine quarterly review documentation and verify it includes review results, remediation actions, and sign-off. Verify that sign-off is by personnel assigned responsibility for the PCI DSS compliance program."
  },
  {
    id: "12.5.1",
    title: "An inventory of system components that are in scope for PCI DSS, including a description of function/use for each, is maintained and kept current",
    description: "The organization must maintain a current inventory of all system components that are within the scope of PCI DSS compliance. The inventory must include a description of the function and use of each component. An accurate scope inventory is foundational to PCI DSS compliance because it ensures that all in-scope components are subject to applicable security controls.",
    testingProcedure: "Examine the inventory of in-scope system components and verify it is current and includes descriptions of each component's function. Compare the inventory against the actual environment to verify completeness."
  },
  {
    id: "12.5.2",
    title: "PCI DSS scope is documented and confirmed by the entity at least once every 12 months and upon significant change to the in-scope environment",
    description: "The scope of PCI DSS compliance must be formally documented and confirmed at least annually and whenever significant changes occur to the environment. The scoping exercise must identify all locations and flows of cardholder data, all systems connected to the CDE, and all systems that could impact CDE security. Accurate scoping is essential because under-scoping leads to unprotected systems while over-scoping wastes resources.",
    testingProcedure: "Examine scoping documentation and verify that PCI DSS scope is confirmed at least annually and after significant changes. Verify that the scoping exercise identifies all cardholder data locations, flows, and connected systems."
  },
  {
    id: "12.5.2.1",
    title: "Additional requirement for service providers only: PCI DSS scope is documented and confirmed by the entity at least once every six months and upon significant change to the in-scope environment",
    description: "Service providers must confirm their PCI DSS scope at least every six months and after significant changes, rather than the annual frequency required for other entities. More frequent scope confirmation reflects the dynamic nature of service provider environments and the higher risk associated with processing cardholder data for multiple clients. Regular scope validation ensures that new systems and data flows are promptly identified and brought under PCI DSS controls.",
    testingProcedure: "Examine scoping documentation for the service provider and verify that PCI DSS scope is confirmed at least every six months. Verify that scope confirmation occurs after significant changes."
  },
  {
    id: "12.5.3",
    title: "Additional requirement for service providers only: Significant changes to organizational structure result in a documented (internal) review of the impact to PCI DSS scope and applicability of controls, with results communicated to executive management",
    description: "When significant organizational changes occur, service providers must conduct an internal review to assess the impact on PCI DSS scope and the applicability of existing security controls. The review results must be documented and communicated to executive management. Organizational changes such as mergers, acquisitions, or restructuring can significantly affect the scope and effectiveness of PCI DSS controls.",
    testingProcedure: "Examine records of significant organizational changes and corresponding PCI DSS impact reviews. Verify that review results are documented and communicated to executive management."
  },
  {
    id: "12.6.1",
    title: "A formal security awareness program is implemented to make all personnel aware of the entity's information security policy and procedures, and their role in protecting cardholder data",
    description: "A formal security awareness program must be implemented to educate all personnel about the organization's information security policies and their individual responsibilities for protecting cardholder data. The program must be ongoing and address current threats and security best practices. Security awareness training transforms personnel from potential vulnerabilities into active participants in the organization's security posture.",
    testingProcedure: "Examine the security awareness program and verify it is formally established and covers information security policies and cardholder data protection. Verify that the program is delivered to all personnel."
  },
  {
    id: "12.6.2",
    title: "The security awareness program is reviewed at least once every 12 months and updated as needed to address any new threats and vulnerabilities",
    description: "The security awareness program must be reviewed at least annually and updated to address new threats, vulnerabilities, and changes to the organization's security policies. The review must consider current attack trends, recent security incidents, and employee feedback. Keeping the program current ensures that personnel are prepared to recognize and respond to the latest threats.",
    testingProcedure: "Examine security awareness program review records and verify that reviews occur at least annually. Verify that the program is updated to address current threats and vulnerabilities."
  },
  {
    id: "12.6.3",
    title: "Personnel receive security awareness training as follows: upon hire and at least once every 12 months, and awareness training includes awareness of threats and vulnerabilities that could impact the security of account data, awareness of acceptable use of end-user technologies, and acknowledgment by personnel of their responsibility to protect cardholder data",
    description: "All personnel must receive security awareness training upon hire and at least annually thereafter. Training must cover current threats and vulnerabilities, acceptable use of technology, and individual responsibilities for protecting cardholder data. Personnel must formally acknowledge completion of training and their understanding of security responsibilities.",
    testingProcedure: "Examine training records and verify that all personnel receive security awareness training upon hire and annually. Verify that training covers required topics and that personnel acknowledgments are documented."
  },
  {
    id: "12.6.3.1",
    title: "Security awareness training includes awareness of threats and vulnerabilities that could impact the security of the CDE, including but not limited to phishing and related attacks, and social engineering",
    description: "Security awareness training must specifically address phishing attacks, social engineering techniques, and other threats that could compromise the security of the cardholder data environment. Training must include practical examples and guidance on recognizing and reporting these threats. Phishing and social engineering are among the most common and successful attack vectors, making targeted awareness training essential.",
    testingProcedure: "Examine security awareness training content and verify it specifically addresses phishing, social engineering, and related attack techniques. Interview personnel to confirm they understand how to recognize and report these threats."
  },
  {
    id: "12.6.3.2",
    title: "Security awareness training includes awareness of acceptable use of end-user technologies in accordance with Requirement 12.2.1",
    description: "Security awareness training must reinforce the acceptable use policy for end-user technologies as defined in Requirement 12.2.1. Training must cover proper use of approved technologies, prohibited activities, and the security implications of policy violations. Integrating acceptable use education into security awareness training ensures personnel understand the connection between technology use and security.",
    testingProcedure: "Examine security awareness training content and verify it addresses acceptable use of end-user technologies. Verify alignment between training content and the acceptable use policy defined in Requirement 12.2.1."
  },
  {
    id: "12.7.1",
    title: "Potential personnel who will have access to the CDE are screened prior to hire to minimize the risk of attacks from internal sources",
    description: "Background screening must be conducted for all potential personnel who will have access to the cardholder data environment prior to their hire date. Screening may include criminal background checks, employment verification, and reference checks as permitted by local laws. Pre-employment screening helps identify individuals who may pose an insider threat risk.",
    testingProcedure: "Examine screening procedures and records for personnel with CDE access and verify that screening is conducted prior to hire. Verify that screening includes appropriate checks as permitted by local laws."
  },
  {
    id: "12.8.1",
    title: "A list of all third-party service providers (TPSPs) with which account data is shared or that could affect the security of account data is maintained, including a description of each of the services provided",
    description: "The organization must maintain a current list of all third-party service providers that have access to or could affect the security of account data. The list must include a description of the services each provider performs. This inventory enables effective management of third-party risk and ensures that all service providers are subject to appropriate security oversight.",
    testingProcedure: "Examine the third-party service provider list and verify it is current and includes all service providers with access to account data. Verify that service descriptions are documented for each provider."
  },
  {
    id: "12.8.2",
    title: "Written agreements are maintained with all TPSPs with which account data is shared or that could affect the security of account data",
    description: "Written agreements must be established with all third-party service providers that handle or could affect the security of account data. The agreements must include acknowledgment by the service provider of their responsibility for the security of account data in their possession. Formal agreements ensure that security responsibilities are clearly defined and enforceable between the organization and its service providers.",
    testingProcedure: "Examine written agreements with service providers and verify they include acknowledgment of security responsibility. Verify that agreements exist for all service providers on the maintained list."
  },
  {
    id: "12.8.3",
    title: "An established process is implemented for engaging TPSPs, including proper due diligence prior to engagement",
    description: "A formal process must be implemented for evaluating and engaging third-party service providers, including conducting security due diligence before establishing the relationship. Due diligence must assess the provider's security posture, compliance status, and ability to meet PCI DSS requirements. Thorough vetting before engagement prevents relationships with providers that could compromise the security of account data.",
    testingProcedure: "Examine the TPSP engagement process and verify that due diligence is conducted prior to engagement. Examine due diligence records for recent engagements to verify the process is followed."
  },
  {
    id: "12.8.4",
    title: "A program is implemented to monitor TPSPs' PCI DSS compliance status at least once every 12 months",
    description: "The organization must monitor the PCI DSS compliance status of all third-party service providers at least annually. Monitoring may include reviewing the provider's Attestation of Compliance, self-assessment questionnaire, or other evidence of compliance. Ongoing monitoring ensures that service providers maintain their security posture throughout the relationship, not just at the time of initial engagement.",
    testingProcedure: "Examine TPSP monitoring records and verify that PCI DSS compliance status is assessed at least annually. Verify that monitoring covers all service providers on the maintained list."
  },
  {
    id: "12.8.5",
    title: "Information is maintained about which PCI DSS requirements are managed by each TPSP, which are managed by the entity, and any that are shared between the TPSP and the entity",
    description: "The organization must document and maintain information about the division of PCI DSS responsibilities between itself and each service provider. This responsibility matrix must clearly indicate which requirements are managed by the entity, which by the service provider, and which are shared. A clear understanding of responsibility boundaries prevents gaps where requirements fall through the cracks between parties.",
    testingProcedure: "Examine responsibility matrices for each TPSP and verify they clearly define which PCI DSS requirements are managed by each party. Verify that shared responsibilities are explicitly identified and understood by both parties."
  },
  {
    id: "12.9.1",
    title: "Additional requirement for TPSPs only: TPSPs acknowledge in writing to customers that they are responsible for the security of account data the TPSP possesses or otherwise stores, processes, or transmits on behalf of the customer, or to the extent that they could impact the security of the customer's CDE",
    description: "Third-party service providers must provide written acknowledgment to each customer that they are responsible for the security of account data they possess or handle on the customer's behalf. This acknowledgment must be specific about the scope of responsibility and the data involved. Written acknowledgment creates a clear and enforceable commitment to data security that customers can rely upon.",
    testingProcedure: "Examine written acknowledgments provided to customers and verify they address the TPSP's responsibility for account data security. Verify that acknowledgments are provided to all customers."
  },
  {
    id: "12.9.2",
    title: "Additional requirement for TPSPs only: TPSPs support their customers' requests to provide PCI DSS compliance status and information about the PCI DSS requirements that are the responsibility of the TPSP",
    description: "Service providers must support customer requests for information about the provider's PCI DSS compliance status and which PCI DSS requirements the provider manages. This transparency enables customers to verify the provider's compliance and understand the division of responsibilities. Prompt and transparent communication about compliance status builds trust and enables effective risk management.",
    testingProcedure: "Examine the TPSP's process for responding to customer compliance information requests. Verify that the TPSP provides PCI DSS compliance status and responsibility information to customers upon request."
  },
  {
    id: "12.10.1",
    title: "An incident response plan exists and is ready to be activated in the event of a suspected or confirmed security incident that includes roles, responsibilities, and communication and contact strategies in the event of a suspected or confirmed security incident, including notification of the payment brands and acquirers at a minimum, incident response procedures with specific containment and mitigation activities for different types of incidents, business recovery and continuity procedures, data backup processes, analysis of legal requirements for reporting compromises, coverage for all critical system components, and reference or inclusion of incident response procedures from the payment brands",
    description: "A comprehensive incident response plan must be documented and ready for activation in the event of a suspected or confirmed security incident. The plan must define roles and responsibilities, communication procedures, containment and mitigation activities, business recovery procedures, and legal reporting requirements. Payment brand incident response procedures must be referenced or incorporated. A well-prepared incident response plan minimizes the impact of security incidents through rapid and organized response.",
    testingProcedure: "Examine the incident response plan and verify it includes all required elements. Verify that the plan is current, accessible, and ready for activation."
  },
  {
    id: "12.10.2",
    title: "At least once every 12 months, the security incident response plan is reviewed and the content is updated as needed, including after an incident",
    description: "The incident response plan must be reviewed at least annually and updated to address lessons learned from actual incidents, changes in the environment, and evolving threats. Post-incident reviews must identify areas for improvement in the response process. Regular updates ensure the plan remains effective and reflects current organizational capabilities and contact information.",
    testingProcedure: "Examine incident response plan review records and verify that reviews occur at least annually and after incidents. Verify that the plan is updated based on review findings."
  },
  {
    id: "12.10.3",
    title: "Specific personnel are designated to be available on a 24/7 basis to respond to suspected or confirmed security incidents",
    description: "Specific personnel must be designated and available around the clock to respond to security incidents. Contact information for incident response team members must be current and accessible. Continuous availability ensures that incidents are responded to promptly regardless of when they occur, minimizing the attacker's window of opportunity.",
    testingProcedure: "Examine the incident response plan and contact lists to verify that specific personnel are designated for 24/7 incident response. Verify that contact information is current and that the on-call process functions effectively."
  },
  {
    id: "12.10.4",
    title: "Personnel responsible for responding to suspected and confirmed security incidents are appropriately and periodically trained on their incident response responsibilities",
    description: "Incident response team members must receive periodic training on their specific responsibilities during a security incident. Training must cover the incident response plan, procedures for their assigned role, and current threat scenarios. Well-trained incident responders can execute the plan efficiently during the high-stress environment of an actual security incident.",
    testingProcedure: "Examine training records for incident response personnel and verify they receive periodic training. Verify that training covers the incident response plan and role-specific responsibilities."
  },
  {
    id: "12.10.4.1",
    title: "The frequency of periodic training for incident response personnel is defined in the entity's targeted risk analysis",
    description: "The frequency of training for incident response personnel must be determined through a targeted risk analysis that considers factors such as personnel turnover, changes in the threat landscape, and the complexity of the incident response plan. The risk analysis must justify the chosen training frequency and be reviewed annually. More frequent training may be needed for environments with rapidly evolving threats or high personnel turnover.",
    testingProcedure: "Examine the targeted risk analysis and verify it defines training frequency for incident response personnel. Verify that actual training frequency aligns with the risk analysis findings."
  },
  {
    id: "12.10.5",
    title: "The security incident response plan includes monitoring and responding to alerts from security monitoring systems, including but not limited to intrusion-detection and intrusion-prevention systems, network security controls, change-detection mechanisms for critical files, and the anti-tampering mechanism for payment pages",
    description: "The incident response plan must integrate with and address alerts generated by security monitoring systems including IDS/IPS, firewalls, file integrity monitoring, and payment page tamper detection. Procedures must define how alerts are triaged, escalated, and investigated. Integration between monitoring systems and incident response ensures that detected threats receive timely and appropriate attention.",
    testingProcedure: "Examine the incident response plan and verify it addresses alerts from all specified security monitoring systems. Verify that procedures define how alerts are triaged and escalated."
  },
  {
    id: "12.10.6",
    title: "The security incident response plan is modified and evolved according to lessons learned and to incorporate industry developments",
    description: "The incident response plan must be continuously improved based on lessons learned from actual incidents, tabletop exercises, and industry developments. Each incident should result in a post-incident review that identifies areas for improvement. Incorporating industry developments ensures the plan addresses emerging threat techniques and reflects current best practices in incident response.",
    testingProcedure: "Examine incident response plan revision history and verify that updates incorporate lessons learned from incidents and industry developments. Examine post-incident review records to verify that findings are integrated into the plan."
  },
  {
    id: "12.10.7",
    title: "Incident response procedures are in place, to be initiated upon detection of stored PAN anywhere it is not expected, and include determining what to do if PAN is discovered outside the CDE, including its retrieval, secure deletion, and/or migration into the currently defined CDE, identifying the sensitive authentication data stored with PAN, determining where the account data came from and how it ended up where it was not expected, and remediating data leaks or process gaps that resulted in the account data being where it was not expected",
    description: "Specific incident response procedures must address the discovery of PAN stored in unexpected locations outside the CDE. The procedures must include steps for retrieving or securely deleting the data, investigating how it arrived at the unexpected location, and remediating the process gaps that allowed the data leak. Prompt response to unexpected PAN storage prevents the expansion of the CDE and addresses the root cause of data spillage.",
    testingProcedure: "Examine incident response procedures for unexpected PAN discovery and verify they address all required elements. Examine records of any such incidents to verify the procedures were followed."
  }
];

const OWASP_ASVS_V4 = [
  // ============================================================
  // V1 - Architecture, Design and Threat Modeling
  // ============================================================

  // V1.1 Secure Software Development Lifecycle
  { id: "V1.1.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Secure SDLC", description: "Verify that a secure software development lifecycle is in use that addresses security in all stages of development. The SDLC should include threat modeling, secure design patterns, secure coding guidelines, and security testing.", level: "L2" },
  { id: "V1.1.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Threat Modeling for Design Changes", description: "Verify that threat modeling is performed for every design change or sprint planning to identify threats, plan for countermeasures, facilitate appropriate risk responses, and guide security testing. Threat models should be updated when the application changes.", level: "L2" },
  { id: "V1.1.3", category: "V1 - Architecture, Design and Threat Modeling", title: "Up-to-Date Threat Model", description: "Verify that all user stories and features contain functional security constraints such as 'As a user, I should be able to view and edit my profile. I should not be able to view or edit any other profile.' Security requirements should be documented and tested.", level: "L2" },
  { id: "V1.1.4", category: "V1 - Architecture, Design and Threat Modeling", title: "Documentation of Trust Boundaries", description: "Verify documentation and justification of all the application's trust boundaries, components, and significant data flows. The architecture should clearly delineate the boundaries between trusted and untrusted zones.", level: "L2" },
  { id: "V1.1.5", category: "V1 - Architecture, Design and Threat Modeling", title: "High-Level Architecture Definition", description: "Verify definition and security analysis of the application's high-level architecture and all connected remote services. The analysis should identify potential attack surfaces and determine appropriate mitigations.", level: "L2" },
  { id: "V1.1.6", category: "V1 - Architecture, Design and Threat Modeling", title: "Centralized Security Controls", description: "Verify implementation of centralized, simple, vetted, secure, and reusable security controls to avoid duplicate, missing, ineffective, or insecure controls. Centralized controls reduce the risk of inconsistent security enforcement.", level: "L2" },
  { id: "V1.1.7", category: "V1 - Architecture, Design and Threat Modeling", title: "Secure Coding Checklist or Guide", description: "Verify availability of a secure coding checklist, security requirements, guideline, or policy to all developers and testers. These resources should be kept current and reviewed regularly to incorporate new threat intelligence.", level: "L2" },

  // V1.2 Authentication Architecture
  { id: "V1.2.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Unique Low-Privilege Service Accounts", description: "Verify the use of unique or special low-privilege operating system accounts for all application components, services, and servers. Shared or high-privilege accounts should not be used for application runtime operations.", level: "L2" },
  { id: "V1.2.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Authenticated Communications Between Components", description: "Verify that communications between application components, including APIs, middleware and data layers, are authenticated. Components should know which other components they need to communicate with and authenticate those connections.", level: "L2" },
  { id: "V1.2.3", category: "V1 - Architecture, Design and Threat Modeling", title: "Single Vetted Authentication Mechanism", description: "Verify that the application uses a single vetted authentication mechanism that is known to be secure, can be extended to include strong authentication, and has sufficient logging and monitoring to detect account abuse or breaches.", level: "L2" },
  { id: "V1.2.4", category: "V1 - Architecture, Design and Threat Modeling", title: "All Authentication Pathways and Identity Management", description: "Verify that all authentication pathways and identity management APIs implement consistent authentication security control strength, such that there are no weaker alternatives per the risk of the application.", level: "L2" },

  // V1.3 Session Management Architecture
  { id: "V1.3.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Session Management Not Based on Insecure Tokens", description: "Verify that the application never reveals session tokens in URL parameters or error messages. Session tokens should be stored securely and transmitted only through protected channels.", level: "L1" },
  { id: "V1.3.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Centralized Session Management", description: "Verify that the application uses a centralized, vetted session management implementation. All session creation, validation, and termination should go through a single, well-tested module rather than ad hoc per-component solutions.", level: "L1" },

  // V1.4 Access Control Architecture
  { id: "V1.4.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Trusted Enforcement Points", description: "Verify that trusted enforcement points such as access control gateways, servers, and serverless functions enforce access controls. Access controls should never be enforced solely on the client side where they can be bypassed.", level: "L1" },
  { id: "V1.4.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Documented Access Control Mechanism", description: "Verify that the chosen access control solution is flexible enough to meet the application's needs. The access control architecture should be documented and consistently applied across all application components.", level: "L1" },
  { id: "V1.4.3", category: "V1 - Architecture, Design and Threat Modeling", title: "Enforcement of Access Control at Function Level", description: "Verify enforcement of the principle of least privilege in functions, data files, URLs, controllers, services, and other resources. Access to sensitive operations and data should require explicit authorization checks.", level: "L1" },
  { id: "V1.4.4", category: "V1 - Architecture, Design and Threat Modeling", title: "Single Well-Vetted Access Control Mechanism", description: "Verify the application uses a single and well-vetted access control mechanism for accessing protected data and resources. All requests must pass through this mechanism to prevent direct object reference vulnerabilities.", level: "L1" },
  { id: "V1.4.5", category: "V1 - Architecture, Design and Threat Modeling", title: "Attribute or Feature-Based Access Control", description: "Verify that attribute or feature-based access control is used whereby the code checks the user's authorization for a feature or data item rather than just their role. Permissions should be allocated using roles to group related permissions.", level: "L2" },

  // V1.5 Input and Output Architecture
  { id: "V1.5.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Defined Input and Output Requirements", description: "Verify that input and output requirements clearly define how to handle and process data based on type, content, and applicable laws, regulations, and other policy compliance. Data classification should drive validation rules.", level: "L2" },
  { id: "V1.5.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Serialization Not Used for Untrusted Data", description: "Verify that serialization is not used when communicating with untrusted clients. If serialization is unavoidable, use safe serialization formats and libraries that do not allow arbitrary object instantiation to prevent deserialization attacks.", level: "L2" },
  { id: "V1.5.3", category: "V1 - Architecture, Design and Threat Modeling", title: "Input Validation at Trusted Service Layer", description: "Verify that input validation is enforced on a trusted service layer. While client-side validation improves usability, it must not be relied upon as a security control since it can be easily bypassed.", level: "L1" },
  { id: "V1.5.4", category: "V1 - Architecture, Design and Threat Modeling", title: "Output Encoding Near or By Interpreter", description: "Verify that output encoding occurs close to or by the interpreter for which it is intended. Output encoding should be context-appropriate for the target interpreter such as HTML, URL, JavaScript, CSS, or SQL.", level: "L1" },

  // V1.6 Cryptographic Architecture
  { id: "V1.6.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Cryptographic Key Management Policy", description: "Verify that there is an explicit policy for management of cryptographic keys and that a cryptographic key lifecycle follows a key management standard. The policy should cover generation, distribution, storage, rotation, and destruction.", level: "L2" },
  { id: "V1.6.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Consumers of Cryptographic Services Protect Key Material", description: "Verify that consumers of cryptographic services protect key material and other secrets by using key vaults or API-based alternatives. Keys should never be hardcoded, stored in plaintext, or committed to source code.", level: "L2" },
  { id: "V1.6.3", category: "V1 - Architecture, Design and Threat Modeling", title: "All Keys and Passwords Replaceable", description: "Verify that all keys and passwords are replaceable and are part of a well-defined process to re-encrypt sensitive data. The application should support key rotation without requiring downtime or data loss.", level: "L2" },
  { id: "V1.6.4", category: "V1 - Architecture, Design and Threat Modeling", title: "Client-Side Secrets Architecture", description: "Verify that the architecture treats client-side secrets such as symmetric keys, passwords, or API tokens as insecure and never uses them to protect or access sensitive data on the server side.", level: "L2" },

  // V1.7 Errors, Logging and Auditing Architecture
  { id: "V1.7.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Common Logging Format and Approach", description: "Verify that a common logging format and approach is used across the system. Log formats should be consistent to facilitate analysis, correlation, and integration with centralized logging and monitoring systems.", level: "L2" },
  { id: "V1.7.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Logs Sent to Remote Monitoring and Alerting", description: "Verify that logs are securely sent to a preferably remote system for analysis, detection, alerting, and escalation. Logs should be protected against tampering and unauthorized access to maintain their integrity.", level: "L2" },

  // V1.8 Data Protection and Privacy Architecture
  { id: "V1.8.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Sensitive Data Identified and Classified", description: "Verify that all sensitive data is identified and classified into protection levels. Each protection level should have a documented set of protection requirements including encryption, integrity verification, retention, and privacy controls.", level: "L2" },
  { id: "V1.8.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Protection Levels Have Associated Controls", description: "Verify that all protection levels have an associated set of protection requirements, such as encryption requirements, integrity requirements, retention, privacy, and other confidentiality requirements. These controls should be consistently applied.", level: "L2" },

  // V1.9 Communications Architecture
  { id: "V1.9.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Encryption Between Components", description: "Verify that the application encrypts communications between components, particularly when these components are in different containers, systems, sites, or cloud providers. Transport layer encryption using TLS or equivalent should be mandatory.", level: "L2" },
  { id: "V1.9.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Encrypted Communications for Sensitive Data", description: "Verify that application components verify the authenticity of each side in a communication link to prevent person-in-the-middle attacks. For example, application components should validate TLS certificates and certificate chains.", level: "L2" },

  // V1.10 Malicious Software Architecture
  { id: "V1.10.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Source Code Control System in Use", description: "Verify that a source code control system is in use, with procedures to ensure that check-ins are accompanied by issues or change tickets. The source code control system should have access control and identifiable users.", level: "L2" },

  // V1.11 Business Logic Architecture
  { id: "V1.11.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Synchronization and Ordering of Business Logic Flows", description: "Verify the definition and documentation of all application components in terms of the business or security functions they provide. Ensure that all high-value business logic flows cannot be circumvented via misuse or abuse.", level: "L2" },
  { id: "V1.11.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Business Logic Flows Handle Out-of-Order Steps", description: "Verify that all high-value business logic flows, including authentication, session management, and access control, do not share unsynchronized state. Business logic should enforce ordering and detect out-of-sequence operations.", level: "L2" },
  { id: "V1.11.3", category: "V1 - Architecture, Design and Threat Modeling", title: "All High-Value Business Logic Flows Considered", description: "Verify that all high-value business logic flows, including authentication, session management, and access control, are thread safe and resistant to time-of-check and time-of-use race conditions.", level: "L3" },

  // V1.12 Secure File Upload Architecture
  { id: "V1.12.1", category: "V1 - Architecture, Design and Threat Modeling", title: "User-Uploaded Files Served from Separate Domain", description: "Verify that user-uploaded files are served by either octet stream downloads, or from an unrelated domain such as a cloud file storage bucket. This prevents cross-site scripting attacks through uploaded files containing malicious content.", level: "L2" },
  { id: "V1.12.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Direct File Execution Prevention", description: "Verify that user-uploaded files, if required to be displayed or downloaded from the application, are served by either octet stream downloads, or from an unrelated domain. Implement a suitable Content Security Policy to reduce XSS risk.", level: "L2" },

  // V1.13 API Architecture
  { id: "V1.13.1", category: "V1 - Architecture, Design and Threat Modeling", title: "API URL Definition and Documentation", description: "Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit differing URI or file parsing behavior. Components should share common parsing libraries.", level: "L2" },
  { id: "V1.13.2", category: "V1 - Architecture, Design and Threat Modeling", title: "API Access Control Verification", description: "Verify that access to administration and management functions is limited to authorized administrators. API endpoints for administrative functions should enforce strict role-based access control.", level: "L2" },

  // V1.14 Configuration Architecture
  { id: "V1.14.1", category: "V1 - Architecture, Design and Threat Modeling", title: "Segregation of Components", description: "Verify the segregation of components of differing trust levels through well-defined security controls, firewall rules, API gateways, reverse proxies, cloud-based security groups, or similar mechanisms.", level: "L2" },
  { id: "V1.14.2", category: "V1 - Architecture, Design and Threat Modeling", title: "Binary Signatures and Trusted Connections", description: "Verify that binary signatures, trusted connections, and verified endpoints are used to deploy binaries to remote devices. Deployment pipelines should validate the integrity and authenticity of build artifacts.", level: "L2" },
  { id: "V1.14.3", category: "V1 - Architecture, Design and Threat Modeling", title: "Build Pipeline Security", description: "Verify that the build pipeline warns of out-of-date or insecure components and takes appropriate action. The build pipeline should incorporate software composition analysis to identify known vulnerabilities.", level: "L2" },
  { id: "V1.14.4", category: "V1 - Architecture, Design and Threat Modeling", title: "Build Pipeline Integrity Controls", description: "Verify that the build pipeline contains a build step to automatically build and verify the secure deployment of the application, particularly if the application infrastructure is software-defined.", level: "L2" },
  { id: "V1.14.5", category: "V1 - Architecture, Design and Threat Modeling", title: "Application Deployments Adequately Sandboxed", description: "Verify that application deployments adequately sandbox, containerize, or isolate at the network level to delay and deter attackers from attacking other applications. Least privilege networking should be enforced.", level: "L2" },
  { id: "V1.14.6", category: "V1 - Architecture, Design and Threat Modeling", title: "No Unsupported or Insecure Technologies", description: "Verify the application does not use unsupported, insecure, or deprecated client-side technologies such as NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets.", level: "L2" },

  // ============================================================
  // V2 - Authentication
  // ============================================================

  // V2.1 Password Security
  { id: "V2.1.1", category: "V2 - Authentication", title: "Password Minimum Length", description: "Verify that user set passwords are at least 12 characters in length after combining spaces. Longer passwords should be encouraged by the application. Short passwords are significantly easier to brute force.", level: "L1" },
  { id: "V2.1.2", category: "V2 - Authentication", title: "Password Maximum Length", description: "Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied. Overly long passwords can cause denial of service through excessive hashing computation.", level: "L1" },
  { id: "V2.1.3", category: "V2 - Authentication", title: "No Password Truncation", description: "Verify that password truncation is not performed. Consecutive multiple spaces should be allowed but may be replaced by a single space. The full length of the user-supplied password should be validated.", level: "L1" },
  { id: "V2.1.4", category: "V2 - Authentication", title: "Unicode Characters in Passwords", description: "Verify that any printable Unicode character, including language-neutral characters such as spaces and emojis, are permitted in passwords. Users should not be restricted from using characters from their native language.", level: "L1" },
  { id: "V2.1.5", category: "V2 - Authentication", title: "Password Change Functionality", description: "Verify users can change their password. The password change function should require the user's current and new password. This prevents unauthorized password changes by attackers who have compromised a session.", level: "L1" },
  { id: "V2.1.6", category: "V2 - Authentication", title: "Password Change Requires Current Password", description: "Verify that password change functionality requires the user's current and new password. This ensures that even if a session is compromised, the attacker cannot change the password without knowing the current one.", level: "L1" },
  { id: "V2.1.7", category: "V2 - Authentication", title: "Breached Password Check", description: "Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords either locally or using an external API. If breached, the application should require the user to set a new password.", level: "L1" },
  { id: "V2.1.8", category: "V2 - Authentication", title: "Password Strength Meter", description: "Verify that a password strength meter is provided to help users set a stronger password. The meter should provide real-time feedback on password complexity and guide users toward selecting resistant credentials.", level: "L1" },
  { id: "V2.1.9", category: "V2 - Authentication", title: "No Password Composition Rules", description: "Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters. Modern guidance favors length over complexity.", level: "L1" },
  { id: "V2.1.10", category: "V2 - Authentication", title: "No Periodic Credential Rotation", description: "Verify that there are no periodic credential rotation or password history requirements. Password rotation is no longer considered best practice and can lead users to use predictable incremental password patterns.", level: "L1" },
  { id: "V2.1.11", category: "V2 - Authentication", title: "Paste Functionality Allowed", description: "Verify that 'paste' functionality, browser password helpers, and external password managers are permitted. These tools generally increase security by enabling the use of longer, more complex, and unique passwords.", level: "L1" },
  { id: "V2.1.12", category: "V2 - Authentication", title: "Password Show/Masked Toggle", description: "Verify that the user can choose to either temporarily view the entire masked password, or temporarily view the last typed character of the password on platforms that do not have this as built-in functionality.", level: "L1" },

  // V2.2 General Authenticator Security
  { id: "V2.2.1", category: "V2 - Authentication", title: "Anti-Automation Controls", description: "Verify that anti-automation controls are effective at mitigating breached credential testing, brute force, and account lockout attacks. Such controls include blocking the most common breached passwords, soft lockouts, rate limiting, and CAPTCHA.", level: "L1" },
  { id: "V2.2.2", category: "V2 - Authentication", title: "Weak Authenticator Resistance", description: "Verify that the use of weak authenticators such as SMS and email as sole authentication factors is not offered. Stronger alternatives such as OTP, hardware tokens, or biometrics should be available as primary or secondary factors.", level: "L1" },
  { id: "V2.2.3", category: "V2 - Authentication", title: "Secure Notification After Authentication Updates", description: "Verify that secure notifications are sent to users after updates to authentication details, such as credential resets, email or address changes, logging in from unknown or risky locations. Push notifications are preferred over SMS.", level: "L1" },
  { id: "V2.2.4", category: "V2 - Authentication", title: "Impersonation Resistance", description: "Verify impersonation resistance against phishing, such as the use of multi-factor authentication, cryptographic devices with intent (such as connected push), or at higher AAL levels, client-side certificates.", level: "L3" },
  { id: "V2.2.5", category: "V2 - Authentication", title: "Credential Service Provider Independence", description: "Verify that where a Credential Service Provider (CSP) and the application verifying authentication are separated, mutually authenticated TLS is in place between the two endpoints. This ensures secure communication between authentication components.", level: "L2" },
  { id: "V2.2.6", category: "V2 - Authentication", title: "Replay Resistance", description: "Verify replay resistance through the mandated use of One-Time Passwords (OTP) devices, cryptographic authenticators, or lookup codes. Replay attacks should be mitigated by ensuring each authentication attempt uses unique values.", level: "L2" },
  { id: "V2.2.7", category: "V2 - Authentication", title: "Intent to Authenticate", description: "Verify intent to authenticate by requiring the entry of an OTP token or user-initiated action such as a button press on a FIDO hardware key. This prevents unintended authentication through shoulder surfing or other passive attacks.", level: "L2" },

  // V2.3 Authenticator Lifecycle
  { id: "V2.3.1", category: "V2 - Authentication", title: "System Generated Initial Passwords", description: "Verify system generated initial passwords or activation codes shall be securely randomly generated, at least 6 characters long, may contain letters and numbers, and expire after a short period of time. These initial secrets must not be permitted to become long-term passwords.", level: "L1" },
  { id: "V2.3.2", category: "V2 - Authentication", title: "Enrollment and Use of Subscriber-Provided Authenticators", description: "Verify that enrollment and use of subscriber-provided authentication devices are supported, such as U2F or FIDO tokens. Users should be able to register multiple authentication devices for account recovery purposes.", level: "L2" },
  { id: "V2.3.3", category: "V2 - Authentication", title: "Renewal Instructions Sent with Sufficient Time", description: "Verify that renewal instructions are sent with sufficient time to renew time-bound authenticators. Users should receive clear notifications before expiration with straightforward steps to complete the renewal process.", level: "L2" },

  // V2.4 Credential Storage
  { id: "V2.4.1", category: "V2 - Authentication", title: "Passwords Stored in Resistant Form", description: "Verify that passwords are stored in a form that is resistant to offline attacks. Passwords shall be salted and hashed using an approved one-way key derivation or password hashing function such as bcrypt, scrypt, or Argon2.", level: "L1" },
  { id: "V2.4.2", category: "V2 - Authentication", title: "Salt at Least 32 Bits", description: "Verify that the salt is at least 32 bits in length and be chosen arbitrarily to minimize salt value collisions among stored hashes. For each credential, a unique salt value and the resulting hash shall be stored.", level: "L1" },
  { id: "V2.4.3", category: "V2 - Authentication", title: "Sufficient Work Factor for PBKDF2", description: "Verify that if PBKDF2 is used, the iteration count should be as large as verification server performance will allow, typically at least 100,000 iterations. Higher iteration counts provide better resistance against brute force attacks.", level: "L1" },
  { id: "V2.4.4", category: "V2 - Authentication", title: "Sufficient Work Factor for bcrypt", description: "Verify that if bcrypt is used, the work factor should be as large as verification server performance will allow, with a minimum of 10. Higher work factors exponentially increase the computational cost of brute force attacks.", level: "L1" },
  { id: "V2.4.5", category: "V2 - Authentication", title: "Additional Iteration of Key Derivation", description: "Verify that an additional iteration of a key derivation function is performed, using a salt value that is secret and known only to the verifier. This provides an additional layer of protection known as pepper.", level: "L2" },

  // V2.5 Credential Recovery
  { id: "V2.5.1", category: "V2 - Authentication", title: "System-Generated Recovery Secret", description: "Verify that a system-generated initial activation or recovery secret is not sent in clear text to the user. A time-limited, single-use secure link or token should be used instead of transmitting the secret directly.", level: "L1" },
  { id: "V2.5.2", category: "V2 - Authentication", title: "No Knowledge-Based Hints or Questions", description: "Verify that password hints or knowledge-based authentication (so-called secret questions) are not present. These mechanisms are inherently weak as the answers can often be discovered through social media or social engineering.", level: "L1" },
  { id: "V2.5.3", category: "V2 - Authentication", title: "Password Recovery Does Not Reveal Current Password", description: "Verify that password credential recovery does not reveal the current password in any way. The user should be guided to set a new password rather than receiving their existing one, which could be intercepted.", level: "L1" },
  { id: "V2.5.4", category: "V2 - Authentication", title: "Shared or Default Accounts Not Present", description: "Verify shared or default accounts are not present, such as 'root', 'admin', or 'sa'. Each user should have a unique account to enable individual accountability and audit trail integrity.", level: "L1" },
  { id: "V2.5.5", category: "V2 - Authentication", title: "Authentication Factor Change Notification", description: "Verify that if an authentication factor is changed or replaced, the user is notified of this event. Notifications should be sent through a different channel than the one being changed to prevent interception.", level: "L1" },
  { id: "V2.5.6", category: "V2 - Authentication", title: "Forgotten Password Secure Path", description: "Verify forgotten password and other recovery paths use a secure recovery mechanism, such as time-based OTP (TOTP) or other soft token, mobile push, or another offline recovery mechanism. Recovery should not rely solely on email or SMS.", level: "L1" },
  { id: "V2.5.7", category: "V2 - Authentication", title: "OTP or Multi-Factor Recovery", description: "Verify that if OTP or multi-factor authentication factors are lost, evidence of identity proofing is performed at the same level as during enrollment. The identity verification process should be rigorous enough to prevent account takeover.", level: "L2" },

  // V2.6 Look-up Secret Verifier
  { id: "V2.6.1", category: "V2 - Authentication", title: "Look-up Secrets Single Use", description: "Verify that look-up secrets can be used only once. Look-up secrets are pre-generated codes (such as recovery codes) that should be invalidated after a single use to prevent replay attacks.", level: "L2" },
  { id: "V2.6.2", category: "V2 - Authentication", title: "Look-up Secrets Sufficient Randomness", description: "Verify that look-up secrets have sufficient randomness (112 bits of entropy), or if less than 112 bits of entropy, salted with a unique and random 32-bit salt and hashed with an approved one-way hash.", level: "L2" },
  { id: "V2.6.3", category: "V2 - Authentication", title: "Look-up Secrets Resistant to Offline Attacks", description: "Verify that look-up secrets are resistant to offline attacks, such as predictable values. Stored look-up secrets should be hashed using an appropriate algorithm to prevent recovery if the storage is compromised.", level: "L2" },

  // V2.7 Out of Band Verifier
  { id: "V2.7.1", category: "V2 - Authentication", title: "Clear Text OOB Authenticators Not Used", description: "Verify that clear text out-of-band (PSTN) authenticators such as SMS or PSTN are not offered by default, and stronger alternatives such as push notifications are offered first. If PSTN is used, verify that it is not the sole factor.", level: "L1" },
  { id: "V2.7.2", category: "V2 - Authentication", title: "OOB Verifier Expires", description: "Verify that the out-of-band verifier expires out-of-band authentication requests, codes, or tokens after 10 minutes. Short expiration times limit the window of opportunity for interception and replay of authentication codes.", level: "L1" },
  { id: "V2.7.3", category: "V2 - Authentication", title: "OOB Verifier Requests Sent to Authenticated Channel", description: "Verify that the out-of-band verifier authentication requests, codes, or tokens are only usable once, and only for the original authentication request. Codes should be bound to the specific session that requested them.", level: "L1" },
  { id: "V2.7.4", category: "V2 - Authentication", title: "OOB Authenticator and Verifier Communicate Securely", description: "Verify that the out-of-band authenticator and verifier communicate over a secure independent channel. The channel should be resistant to interception, and communications should be encrypted.", level: "L1" },
  { id: "V2.7.5", category: "V2 - Authentication", title: "OOB Code Generator Resistance", description: "Verify that the out-of-band verifier retains only a hashed version of the authentication code. Plaintext codes should not be stored, and the verification should use constant-time comparison to prevent timing attacks.", level: "L2" },
  { id: "V2.7.6", category: "V2 - Authentication", title: "Physical OOB Code Resistance", description: "Verify that the initial authentication code is generated by a secure random number generator, containing at least 20 bits of entropy (typically a six-digit random number is sufficient). This ensures resistance to brute force guessing.", level: "L2" },

  // V2.8 One Time Verifier
  { id: "V2.8.1", category: "V2 - Authentication", title: "Time-Based OTP Single Use", description: "Verify that time-based OTPs have a defined lifetime before expiring. OTP values should be usable only once within their time window to prevent replay attacks and ensure freshness of authentication.", level: "L1" },
  { id: "V2.8.2", category: "V2 - Authentication", title: "Symmetric Keys for OTP Verifier Protected", description: "Verify that symmetric keys used to verify submitted OTPs are highly protected, such as by using a hardware security module or secure operating system-based key storage. The keys should not be stored in plaintext.", level: "L2" },
  { id: "V2.8.3", category: "V2 - Authentication", title: "Approved Cryptographic Algorithms for OTP", description: "Verify that approved cryptographic algorithms are used in the generation, seeding, and verification. OTP generation should use HMAC-SHA-1, HMAC-SHA-256, or HMAC-SHA-512 as specified in RFC 4226 and RFC 6238.", level: "L2" },
  { id: "V2.8.4", category: "V2 - Authentication", title: "Time-Based OTP Drift Prevention", description: "Verify that time-based OTP can be used only once within the validity period. The verifier should reject replayed OTP values and implement clock drift tolerance no greater than one time step in either direction.", level: "L2" },
  { id: "V2.8.5", category: "V2 - Authentication", title: "Event-Based OTP Not Reusable", description: "Verify that if a time-based multi-factor OTP token is re-used during the validity period, it is logged and rejected with secure notifications being sent to the holder of the device. This detects potential compromise.", level: "L2" },
  { id: "V2.8.6", category: "V2 - Authentication", title: "Physical Single-Factor OTP Generator", description: "Verify that the physical single-factor OTP generator can be revoked in case of theft or other loss. Ensure that revocation is immediately effective across all logged-in sessions, regardless of location.", level: "L2" },
  { id: "V2.8.7", category: "V2 - Authentication", title: "Biometric Authenticators Limited Use", description: "Verify that biometric authenticators are limited to use only as secondary factors in conjunction with either something you have and something you know. Biometrics alone should not be used as a sole authentication factor.", level: "L3" },

  // V2.9 Cryptographic Verifier
  { id: "V2.9.1", category: "V2 - Authentication", title: "Cryptographic Keys Stored Securely", description: "Verify that cryptographic keys used in verification are stored securely and protected against disclosure, such as using a Trusted Platform Module (TPM) or a Hardware Security Module (HSM), or an OS service that can use this secure storage.", level: "L2" },
  { id: "V2.9.2", category: "V2 - Authentication", title: "Challenge Nonce Length", description: "Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device. This ensures sufficient entropy to prevent replay and collision attacks.", level: "L2" },
  { id: "V2.9.3", category: "V2 - Authentication", title: "Approved Cryptographic Algorithms", description: "Verify that approved cryptographic algorithms are used in the generation, seeding, and verification of cryptographic keys. Algorithms should conform to current NIST, FIPS, or equivalent standards for the required security level.", level: "L2" },

  // V2.10 Service Authentication
  { id: "V2.10.1", category: "V2 - Authentication", title: "No Intra-Service Shared Secrets", description: "Verify that intra-service secrets do not rely on unchanging credentials such as passwords, API keys, or shared accounts with privileged access. Service authentication should use certificates, managed identities, or dynamic credentials.", level: "L2" },
  { id: "V2.10.2", category: "V2 - Authentication", title: "Service Authentication Not Using Static Passwords", description: "Verify that if passwords are required for service authentication, the service account used is not a default credential. Default credentials are well-known and are commonly used by attackers for initial access.", level: "L2" },
  { id: "V2.10.3", category: "V2 - Authentication", title: "Passwords Stored with Sufficient Protection", description: "Verify that passwords are stored with sufficient protection to prevent offline recovery attacks, including local system access. Service account passwords should be stored using strong encryption or a secrets management solution.", level: "L2" },
  { id: "V2.10.4", category: "V2 - Authentication", title: "Passwords, API Keys and Tokens Not in Source Code", description: "Verify that passwords, integrations with databases and third-party systems, seeds and internal secrets, and API keys are managed securely and not included in source code or stored within source code repositories.", level: "L2" },

  // ============================================================
  // V3 - Session Management
  // ============================================================

  // V3.1 Fundamental Session Management
  { id: "V3.1.1", category: "V3 - Session Management", title: "URL Does Not Expose Session Token", description: "Verify the application never reveals session tokens in URL parameters. Session identifiers must be transmitted via secure mechanisms such as HTTP cookies with appropriate security attributes set.", level: "L1" },

  // V3.2 Session Binding
  { id: "V3.2.1", category: "V3 - Session Management", title: "Session Token Generation on Login", description: "Verify the application generates a new session token on user authentication. Old session tokens should be invalidated to prevent session fixation attacks where an attacker sets a known session identifier.", level: "L1" },
  { id: "V3.2.2", category: "V3 - Session Management", title: "Session Token Sufficient Entropy", description: "Verify that session tokens possess at least 64 bits of entropy. Tokens with insufficient randomness can be predicted or brute-forced, allowing attackers to hijack user sessions.", level: "L1" },
  { id: "V3.2.3", category: "V3 - Session Management", title: "Application Stores Tokens Server-Side", description: "Verify the application only stores session tokens in the browser using secure methods such as appropriately secured cookies. Session data should be stored server-side with only the session identifier sent to the client.", level: "L1" },

  // V3.3 Session Termination
  { id: "V3.3.1", category: "V3 - Session Management", title: "Logout Invalidates Session Token", description: "Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session, including across relying parties.", level: "L1" },
  { id: "V3.3.2", category: "V3 - Session Management", title: "Absolute Session Timeout", description: "Verify that if authenticators permit users to remain logged in, both passive reauthentication occurs periodically and active reauthentication at intervals determined by the sensitivity of the application. Maximum absolute timeout should be enforced.", level: "L1" },
  { id: "V3.3.3", category: "V3 - Session Management", title: "Idle Session Timeout", description: "Verify that the application gives the option to terminate all other active sessions after a successful password change, and that this is effective across the application, federated login, and any relying parties.", level: "L2" },
  { id: "V3.3.4", category: "V3 - Session Management", title: "Administrative Session Termination", description: "Verify that users are able to view and (having re-entered login credentials) log out of any or all currently active sessions and devices. Administrative staff should also be able to terminate sessions for support purposes.", level: "L2" },

  // V3.4 Cookie-based Session Management
  { id: "V3.4.1", category: "V3 - Session Management", title: "Secure Cookie Attribute", description: "Verify that cookie-based session tokens have the 'Secure' attribute set. This ensures cookies are only sent over HTTPS connections, preventing interception of session tokens over unencrypted channels.", level: "L1" },
  { id: "V3.4.2", category: "V3 - Session Management", title: "HttpOnly Cookie Attribute", description: "Verify that cookie-based session tokens have the 'HttpOnly' attribute set. This prevents client-side scripts from accessing the session cookie, mitigating cross-site scripting attacks targeting session theft.", level: "L1" },
  { id: "V3.4.3", category: "V3 - Session Management", title: "SameSite Cookie Attribute", description: "Verify that cookie-based session tokens utilize the 'SameSite' attribute to limit exposure to cross-site request forgery attacks. Set to 'Strict' or 'Lax' as appropriate for the application's requirements.", level: "L1" },
  { id: "V3.4.4", category: "V3 - Session Management", title: "Path Cookie Attribute", description: "Verify that cookie-based session tokens use the '__Host-' prefix so cookies are only sent to the host that initially set the cookie. This provides additional protection against cookie tossing attacks.", level: "L1" },
  { id: "V3.4.5", category: "V3 - Session Management", title: "Domain Cookie Attribute", description: "Verify that if the application is published under a domain name with other applications that set or use session cookies that might override or disclose the session cookies, set the path attribute in cookie-based session tokens using the most precise path possible.", level: "L1" },

  // V3.5 Token-based Session Management
  { id: "V3.5.1", category: "V3 - Session Management", title: "OAuth Token Validated Server-Side", description: "Verify the application allows users to revoke OAuth tokens that form trust relationships with linked applications. Users should be able to review and selectively revoke access granted to third-party applications.", level: "L2" },
  { id: "V3.5.2", category: "V3 - Session Management", title: "Stateless Session Tokens with Signatures", description: "Verify the application uses session tokens rather than static API secrets and keys, except with legacy implementations. Stateless session tokens should use digital signatures, encryption, and other countermeasures to protect against tampering.", level: "L2" },
  { id: "V3.5.3", category: "V3 - Session Management", title: "Stateless Session Token Revocation", description: "Verify that stateless session tokens use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks.", level: "L2" },

  // V3.6 Federated Re-authentication
  { id: "V3.6.1", category: "V3 - Session Management", title: "Relying Party Reauthentication", description: "Verify that Relying Parties (RPs) specify the maximum authentication time to Credential Service Providers (CSPs) and that CSPs reauthenticate the subscriber if they have not used authentication within that period.", level: "L3" },
  { id: "V3.6.2", category: "V3 - Session Management", title: "CSP and RP Session Independence", description: "Verify that Credential Service Providers (CSPs) inform Relying Parties (RPs) of the last authentication event, to allow RPs to determine if they need to reauthenticate the user. Session management should be coordinated.", level: "L3" },

  // V3.7 Defenses Against Session Management Exploits
  { id: "V3.7.1", category: "V3 - Session Management", title: "Full Valid Session or Re-Authentication", description: "Verify the application ensures a full, valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications.", level: "L1" },

  // ============================================================
  // V4 - Access Control
  // ============================================================

  // V4.1 General Access Control Design
  { id: "V4.1.1", category: "V4 - Access Control", title: "Trusted Enforcement of Access Controls", description: "Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and could be bypassed. Server-side enforcement is mandatory for security.", level: "L1" },
  { id: "V4.1.2", category: "V4 - Access Control", title: "Access Control Attributes Protected", description: "Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized. Attribute values should be validated on the server side.", level: "L1" },
  { id: "V4.1.3", category: "V4 - Access Control", title: "Principle of Least Privilege", description: "Verify that the principle of least privilege exists and users can only access functions, data files, URLs, controllers, services, and other resources for which they possess specific authorization. Deny by default.", level: "L1" },
  { id: "V4.1.4", category: "V4 - Access Control", title: "Deny by Default Access Control", description: "Verify that the principle of deny by default exists whereby new users or roles start with minimal or no permissions, and users do not receive access to new features until access is explicitly assigned.", level: "L1" },
  { id: "V4.1.5", category: "V4 - Access Control", title: "Access Controls Fail Securely", description: "Verify that access controls fail securely including when an exception occurs. If the access control decision cannot be made, the default should be to deny access rather than permit it.", level: "L1" },

  // V4.2 Operation Level Access Control
  { id: "V4.2.1", category: "V4 - Access Control", title: "Sensitive Data and API Protection", description: "Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating, and deletion of records, such as creating or updating someone else's record.", level: "L1" },
  { id: "V4.2.2", category: "V4 - Access Control", title: "Directory Traversal Prevention", description: "Verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality. Directory traversal attacks should be prevented.", level: "L1" },

  // V4.3 Other Access Control Considerations
  { id: "V4.3.1", category: "V4 - Access Control", title: "Administrative Interface Protections", description: "Verify administrative interfaces use appropriate multi-factor authentication to prevent unauthorized use. Administrative interfaces are high-value targets that require stronger authentication controls than standard user interfaces.", level: "L1" },
  { id: "V4.3.2", category: "V4 - Access Control", title: "Directory Listing Disabled", description: "Verify that directory browsing is disabled unless deliberately desired. Additionally, applications should not allow discovery or disclosure of file or directory metadata, such as Thumbs.db, .DS_Store, or .git folders.", level: "L1" },
  { id: "V4.3.3", category: "V4 - Access Control", title: "Principle of Complete Mediation", description: "Verify the application has additional authorization such as step-up or adaptive authentication for lower-value systems, and segregation of duties for high-value applications to enforce anti-fraud controls per risk.", level: "L2" },

  // ============================================================
  // V5 - Validation, Sanitization and Encoding
  // ============================================================

  // V5.1 Input Validation
  { id: "V5.1.1", category: "V5 - Validation, Sanitization and Encoding", title: "HTTP Parameter Pollution Defense", description: "Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (GET, POST, cookies, headers, or environment).", level: "L1" },
  { id: "V5.1.2", category: "V5 - Validation, Sanitization and Encoding", title: "Framework Source Data Protections", description: "Verify that frameworks protect against mass parameter assignment attacks, or that the application has countermeasures to protect against unsafe parameter assignment, such as marking fields private or similar.", level: "L1" },
  { id: "V5.1.3", category: "V5 - Validation, Sanitization and Encoding", title: "Positive Validation", description: "Verify that all input is validated using positive validation (allow lists). Validation should define the expected data type, length, range, and acceptable characters. Reject all input that does not meet the defined criteria.", level: "L1" },
  { id: "V5.1.4", category: "V5 - Validation, Sanitization and Encoding", title: "Structured Data Validation", description: "Verify that structured data is strongly typed and validated against a defined schema including allowed characters, length, and pattern. For example, credit card numbers, email addresses, and telephone numbers should use format-specific validation.", level: "L1" },
  { id: "V5.1.5", category: "V5 - Validation, Sanitization and Encoding", title: "URL Redirects and Forwards Validation", description: "Verify that URL redirects and forwards only allow destinations which appear on an allow list, or show a warning when redirecting to potentially untrusted content. Open redirects can be used for phishing attacks.", level: "L1" },

  // V5.2 Sanitization and Sandboxing
  { id: "V5.2.1", category: "V5 - Validation, Sanitization and Encoding", title: "WYSIWYG Editor Sanitization", description: "Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized with an HTML sanitizer library or framework feature. Rich text input should be cleaned to remove potentially dangerous elements and attributes.", level: "L1" },
  { id: "V5.2.2", category: "V5 - Validation, Sanitization and Encoding", title: "Unstructured Data Sanitization", description: "Verify that unstructured data is sanitized to enforce safety measures such as allowed characters and length. Input that does not conform to expected patterns should be rejected or sanitized before processing.", level: "L1" },
  { id: "V5.2.3", category: "V5 - Validation, Sanitization and Encoding", title: "SMTP Injection Sanitization", description: "Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. Email headers and content should be properly escaped to prevent injection of additional commands.", level: "L1" },
  { id: "V5.2.4", category: "V5 - Validation, Sanitization and Encoding", title: "eval() or Dynamic Code Execution Avoidance", description: "Verify that the application avoids the use of eval() or other dynamic code execution features. Where there is no alternative, any user input being included must be sanitized or sandboxed before being executed.", level: "L1" },
  { id: "V5.2.5", category: "V5 - Validation, Sanitization and Encoding", title: "Template Injection Protection", description: "Verify that the application protects against template injection attacks by ensuring that any user input being included in templates is sanitized or sandboxed. Server-side template injection can lead to remote code execution.", level: "L1" },
  { id: "V5.2.6", category: "V5 - Validation, Sanitization and Encoding", title: "SSRF Sanitization", description: "Verify that the application protects against SSRF attacks by validating or sanitizing untrusted data or HTTP file metadata, such as filenames and URL input fields. Apply allow-listing of protocols, domains, paths, and ports.", level: "L1" },
  { id: "V5.2.7", category: "V5 - Validation, Sanitization and Encoding", title: "SVG Sanitization", description: "Verify that the application sanitizes, disables, or sandboxes user-supplied Scalable Vector Graphics (SVG) scriptable content, especially as they relate to XSS resulting from inline scripts and foreignObject elements.", level: "L1" },
  { id: "V5.2.8", category: "V5 - Validation, Sanitization and Encoding", title: "Expression Language Injection", description: "Verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar constructs.", level: "L1" },

  // V5.3 Output Encoding and Injection Prevention
  { id: "V5.3.1", category: "V5 - Validation, Sanitization and Encoding", title: "Context-Aware Output Encoding", description: "Verify that output encoding is relevant for the interpreter and context required. For example, use encoders specifically for HTML values, HTML attributes, JavaScript, URL parameters, HTTP headers, SMTP, and others.", level: "L1" },
  { id: "V5.3.2", category: "V5 - Validation, Sanitization and Encoding", title: "HTML Encoding for Output", description: "Verify that output encoding preserves the user's chosen character set and locale, such that any Unicode character point is valid and safely handled. Proper character encoding prevents character set-based injection attacks.", level: "L1" },
  { id: "V5.3.3", category: "V5 - Validation, Sanitization and Encoding", title: "Context-Aware Escaping for XSS", description: "Verify that context-aware, preferably automated, output escaping protects against reflected, stored, and DOM-based XSS. Output encoding should be applied at the point of output, not at the point of input.", level: "L1" },
  { id: "V5.3.4", category: "V5 - Validation, Sanitization and Encoding", title: "Parameterized Queries or Safe ORM", description: "Verify that data selection or database queries use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks. SQL injection remains one of the most critical web vulnerabilities.", level: "L1" },
  { id: "V5.3.5", category: "V5 - Validation, Sanitization and Encoding", title: "OS Command Injection Prevention", description: "Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection.", level: "L1" },
  { id: "V5.3.6", category: "V5 - Validation, Sanitization and Encoding", title: "JSON Injection Prevention", description: "Verify that the application protects against JSON injection attacks, JSON eval attacks, and JavaScript expression evaluation. User input incorporated into JSON responses should be properly encoded to prevent injection.", level: "L1" },
  { id: "V5.3.7", category: "V5 - Validation, Sanitization and Encoding", title: "LDAP Injection Prevention", description: "Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. User input used in LDAP queries must be properly escaped.", level: "L1" },
  { id: "V5.3.8", category: "V5 - Validation, Sanitization and Encoding", title: "OS Command Injection Defense", description: "Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. Applications should avoid calling the OS shell directly.", level: "L1" },
  { id: "V5.3.9", category: "V5 - Validation, Sanitization and Encoding", title: "Local File Inclusion Prevention", description: "Verify that the application protects against Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks. User input should not be used to construct file paths without strict validation and sandboxing.", level: "L1" },
  { id: "V5.3.10", category: "V5 - Validation, Sanitization and Encoding", title: "XPath or XML Injection Prevention", description: "Verify that the application protects against XPath injection or XML injection attacks. User input used in XPath expressions or XML documents must be properly encoded and parameterized where possible.", level: "L1" },

  // V5.4 Memory, String, and Unmanaged Code
  { id: "V5.4.1", category: "V5 - Validation, Sanitization and Encoding", title: "Memory-Safe String Operations", description: "Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. Applications written in memory-unsafe languages should use safe alternatives.", level: "L2" },
  { id: "V5.4.2", category: "V5 - Validation, Sanitization and Encoding", title: "Format String Protections", description: "Verify that format strings do not take potentially hostile input, and are constant. Format string vulnerabilities can lead to information disclosure or arbitrary code execution in languages like C and C++.", level: "L2" },
  { id: "V5.4.3", category: "V5 - Validation, Sanitization and Encoding", title: "Integer Overflow Protections", description: "Verify that sign, range, and input validation techniques are used to prevent integer overflows. Integer overflow vulnerabilities can lead to buffer overflows, infinite loops, or incorrect security-critical calculations.", level: "L2" },

  // V5.5 Deserialization Prevention
  { id: "V5.5.1", category: "V5 - Validation, Sanitization and Encoding", title: "Serialized Objects Use Integrity Checks", description: "Verify that serialized objects use integrity checks or are encrypted to prevent hostile object creation or data tampering. Signed or encrypted serialization prevents attackers from modifying serialized data in transit.", level: "L1" },
  { id: "V5.5.2", category: "V5 - Validation, Sanitization and Encoding", title: "XML Parser Configuration", description: "Verify that the application correctly restricts XML parsers to only use the most restrictive configuration possible and to ensure that unsafe features such as resolving external entities are disabled to prevent XXE attacks.", level: "L1" },
  { id: "V5.5.3", category: "V5 - Validation, Sanitization and Encoding", title: "Deserialization of Untrusted Data Prevention", description: "Verify that deserialization of untrusted data is avoided or is protected in both custom code and third-party libraries such as JSON, XML, and YAML parsers. Unsafe deserialization can lead to remote code execution.", level: "L1" },
  { id: "V5.5.4", category: "V5 - Validation, Sanitization and Encoding", title: "JSON Schema Validation", description: "Verify that when parsing JSON in browsers or JavaScript-based backends, JSON.parse is used to parse the JSON document. Do not use eval() to parse JSON as it introduces code execution vulnerabilities from malicious JSON payloads.", level: "L1" },

  // ============================================================
  // V6 - Stored Cryptography
  // ============================================================

  // V6.1 Data Classification
  { id: "V6.1.1", category: "V6 - Stored Cryptography", title: "Regulated Private Data Encrypted at Rest", description: "Verify that regulated private data is stored encrypted while at rest, such as Personally Identifiable Information (PII), sensitive personal information, or data assessed likely to be subject to GDPR or relevant data protection regulations.", level: "L2" },
  { id: "V6.1.2", category: "V6 - Stored Cryptography", title: "Health Data Encrypted at Rest", description: "Verify that regulated health data is stored encrypted while at rest, such as medical records, medical device details, or de-anonymized research records. Health data requires special handling under regulations such as HIPAA.", level: "L2" },
  { id: "V6.1.3", category: "V6 - Stored Cryptography", title: "Financial Data Encrypted at Rest", description: "Verify that regulated financial data is stored encrypted while at rest, such as financial accounts, defaults or credit history, tax records, pay history, beneficiaries, or de-anonymized market or research records.", level: "L2" },

  // V6.2 Algorithms
  { id: "V6.2.1", category: "V6 - Stored Cryptography", title: "Approved Cryptographic Modules", description: "Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable padding oracle attacks. Cryptographic operations should use approved algorithms and fail closed on error.", level: "L1" },
  { id: "V6.2.2", category: "V6 - Stored Cryptography", title: "Industry-Proven Cryptographic Algorithms", description: "Verify that industry proven or government approved cryptographic algorithms, modes, and libraries are used, instead of custom coded cryptography. Custom cryptographic implementations are almost always flawed.", level: "L1" },
  { id: "V6.2.3", category: "V6 - Stored Cryptography", title: "Proper Encryption Modes and Initialization Vectors", description: "Verify that encryption initialization vectors, cipher configuration, and block modes are configured securely using the latest advice. AES-GCM or ChaCha20-Poly1305 are recommended authenticated encryption modes.", level: "L1" },
  { id: "V6.2.4", category: "V6 - Stored Cryptography", title: "Appropriate Random Number Generation", description: "Verify that random number, encryption or hashing algorithms, key lengths, rounds, ciphers, or modes, can be reconfigured, upgraded, or swapped at any time to protect against cryptographic breaks. Algorithm agility is essential.", level: "L1" },
  { id: "V6.2.5", category: "V6 - Stored Cryptography", title: "No Known Insecure Block Modes", description: "Verify that known insecure block modes such as ECB, insecure padding modes such as PKCS#1 v1.5, or insecure ciphers, modes, or algorithms are not used unless required for backward compatibility.", level: "L1" },
  { id: "V6.2.6", category: "V6 - Stored Cryptography", title: "Nonce and IV Not Reused", description: "Verify that nonces, initialization vectors, and other single-use numbers must not be used more than once with a given encryption key. The method of generation must be appropriate for the algorithm being used.", level: "L2" },
  { id: "V6.2.7", category: "V6 - Stored Cryptography", title: "Encrypted Data Authenticated", description: "Verify that encrypted data is authenticated via signatures, authenticated cipher modes, or HMAC to ensure that ciphertext is not altered by an unauthorized party. Authenticated encryption prevents tampering.", level: "L2" },
  { id: "V6.2.8", category: "V6 - Stored Cryptography", title: "All Cryptographic Operations Constant-Time", description: "Verify that all cryptographic operations are constant-time, with no short-circuit operations in comparisons, calculations, or returns, to avoid leaking information. Timing side channels can reveal secret key material.", level: "L3" },

  // V6.3 Random Values
  { id: "V6.3.1", category: "V6 - Stored Cryptography", title: "CSPRNG for Random Values", description: "Verify that all random numbers, random file names, random GUIDs, and random strings are generated using the cryptographic module's approved cryptographically secure pseudo-random number generator (CSPRNG).", level: "L2" },
  { id: "V6.3.2", category: "V6 - Stored Cryptography", title: "Random GUIDs with 122 Bits of Entropy", description: "Verify that random GUIDs are created using the GUID v4 algorithm, and a CSPRNG. GUIDs created using other pseudo-random number generators may be predictable and should not be used for security-sensitive purposes.", level: "L2" },
  { id: "V6.3.3", category: "V6 - Stored Cryptography", title: "Random Numbers with Proper Entropy", description: "Verify that random numbers are created with proper entropy even when the application is under heavy load, or that the application degrades gracefully in such circumstances. Insufficient entropy leads to predictable values.", level: "L2" },

  // V6.4 Secret Management
  { id: "V6.4.1", category: "V6 - Stored Cryptography", title: "Key Management Solution in Use", description: "Verify that a secrets management solution such as a key vault is used to securely create, store, control access to, and destroy secrets. Hardcoded secrets in source code or configuration files are a critical vulnerability.", level: "L2" },
  { id: "V6.4.2", category: "V6 - Stored Cryptography", title: "Key Material Not Exposed to Application", description: "Verify that key material is not exposed to the application but instead uses an isolated security module like a vault for cryptographic operations. Keys should be accessed through APIs that do not reveal the underlying material.", level: "L2" },

  // ============================================================
  // V7 - Error Handling and Logging
  // ============================================================

  // V7.1 Log Content
  { id: "V7.1.1", category: "V7 - Error Handling and Logging", title: "No Sensitive Information in Logs", description: "Verify that the application does not log credentials or payment details. Session tokens should only be stored in logs in an irreversible, hashed form. Sensitive data in logs creates a secondary breach vector.", level: "L1" },
  { id: "V7.1.2", category: "V7 - Error Handling and Logging", title: "No Sensitive Data in Log Files", description: "Verify that the application does not log other sensitive data as defined under local privacy laws or relevant security policy. This includes personal data, health information, and other regulated categories of information.", level: "L1" },
  { id: "V7.1.3", category: "V7 - Error Handling and Logging", title: "Security-Relevant Events Logged", description: "Verify that the application logs security-relevant events including successful and failed authentication events, access control failures, deserialization failures, and input validation failures. These events are essential for incident detection.", level: "L2" },
  { id: "V7.1.4", category: "V7 - Error Handling and Logging", title: "Sufficient Information for Forensics", description: "Verify that each log event includes necessary information that would allow for a detailed investigation of the timeline when an event happens. Log entries should include timestamp, source, event type, and outcome at minimum.", level: "L2" },

  // V7.2 Log Processing
  { id: "V7.2.1", category: "V7 - Error Handling and Logging", title: "Log Sanitization for Injection", description: "Verify that all authentication decisions are logged, without storing sensitive session tokens or passwords. This should include requests with relevant metadata needed for security investigations.", level: "L2" },
  { id: "V7.2.2", category: "V7 - Error Handling and Logging", title: "Log Integrity Protection", description: "Verify that all authentication decisions can be audited through logging and that the log entries cannot be spoofed or tampered with. Log injection attacks should be prevented through proper sanitization of log inputs.", level: "L2" },

  // V7.3 Log Protection
  { id: "V7.3.1", category: "V7 - Error Handling and Logging", title: "Appropriate Log Encoding", description: "Verify that all logging components appropriately encode data to prevent log injection. Log entries should be encoded to prevent interpretation of user-supplied data as log commands or formatting directives.", level: "L2" },
  { id: "V7.3.2", category: "V7 - Error Handling and Logging", title: "All Events Protected from Injection", description: "Verify that all events are protected from injection when viewed in log viewing software. This prevents attackers from injecting malicious content into logs that could compromise log analysis tools or administrators.", level: "L2" },
  { id: "V7.3.3", category: "V7 - Error Handling and Logging", title: "Security Logs Protected from Tampering", description: "Verify that security logs are protected from unauthorized access and modification. Access to logs should be restricted to authorized personnel, and integrity mechanisms should detect unauthorized changes.", level: "L2" },
  { id: "V7.3.4", category: "V7 - Error Handling and Logging", title: "Time Synchronization for Logging", description: "Verify that time sources are synchronized to the correct time and time zone. Strongly consider logging only in UTC if systems are global to assist with post-incident forensic analysis and correlation of events.", level: "L2" },

  // V7.4 Error Handling
  { id: "V7.4.1", category: "V7 - Error Handling and Logging", title: "Generic Error Message on Unexpected Error", description: "Verify that a generic message is shown when an unexpected or security-sensitive error occurs, potentially with a unique ID which support personnel can use to investigate. Detailed error information should not be exposed.", level: "L1" },
  { id: "V7.4.2", category: "V7 - Error Handling and Logging", title: "Consistent Exception Handling", description: "Verify that exception handling is used across the codebase to account for expected and unexpected error conditions. Error handling should be consistent and follow the principle of failing securely.", level: "L2" },
  { id: "V7.4.3", category: "V7 - Error Handling and Logging", title: "Last Resort Error Handler", description: "Verify that a 'last resort' error handler is defined which will catch all unhandled exceptions. The handler should log the error, return a safe generic response, and prevent information leakage from stack traces.", level: "L2" },

  // ============================================================
  // V8 - Data Protection
  // ============================================================

  // V8.1 General Data Protection
  { id: "V8.1.1", category: "V8 - Data Protection", title: "Sensitive Data Identified", description: "Verify the application protects sensitive data from being cached in server components such as load balancers and application caches. Sensitive responses should include appropriate cache-control headers to prevent caching.", level: "L1" },
  { id: "V8.1.2", category: "V8 - Data Protection", title: "Sensitive Data Not in Server Caches", description: "Verify that all cached or temporary copies of sensitive data stored on the server are protected from unauthorized access or purged or invalidated after the authorized user accesses the sensitive data.", level: "L2" },
  { id: "V8.1.3", category: "V8 - Data Protection", title: "Minimized Parameters in Requests", description: "Verify the application minimizes the number of parameters in a request, such as hidden fields, Ajax variables, cookies, and header values. Reducing the attack surface limits opportunities for parameter tampering.", level: "L2" },
  { id: "V8.1.4", category: "V8 - Data Protection", title: "Rate Limiting for Data Access", description: "Verify the application can detect and alert on abnormal numbers of requests, such as by IP, user, total per hour or day, or whatever makes sense for the application. Rate limiting protects against data scraping and abuse.", level: "L2" },
  { id: "V8.1.5", category: "V8 - Data Protection", title: "Regular Backups Performed", description: "Verify that regular backups of important data are performed and that test restoration of data is performed. Backup integrity should be verified regularly, and backups should be stored securely with appropriate access controls.", level: "L3" },
  { id: "V8.1.6", category: "V8 - Data Protection", title: "Encrypted Data Backups", description: "Verify that backups are stored securely to prevent data from being stolen or corrupted. Backups should be encrypted with strong encryption and stored in a location with restricted physical and logical access.", level: "L3" },

  // V8.2 Client-side Data Protection
  { id: "V8.2.1", category: "V8 - Data Protection", title: "Sensitive Data Not Stored in Browser", description: "Verify the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers. Appropriate Cache-Control, Pragma, and Expires headers should be set for pages containing sensitive data.", level: "L1" },
  { id: "V8.2.2", category: "V8 - Data Protection", title: "Browser Storage Does Not Contain Sensitive Data", description: "Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data. Applications should avoid storing authentication tokens or PII in client-side storage.", level: "L1" },
  { id: "V8.2.3", category: "V8 - Data Protection", title: "Data Cleared on Session Termination", description: "Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. Session-related data should be purged to prevent unauthorized access to residual information.", level: "L1" },

  // V8.3 Sensitive Private Data
  { id: "V8.3.1", category: "V8 - Data Protection", title: "Sensitive Data Sent in HTTP Body", description: "Verify that sensitive data is sent to the server in the HTTP message body or headers, and that query string parameters from any HTTP verb do not contain sensitive data. GET request parameters are logged in server logs.", level: "L1" },
  { id: "V8.3.2", category: "V8 - Data Protection", title: "Autocomplete Disabled for Sensitive Fields", description: "Verify that users have a method to remove or export their data on demand. While autocomplete can improve usability, sensitive fields like passwords and credit cards should have autocomplete disabled.", level: "L1" },
  { id: "V8.3.3", category: "V8 - Data Protection", title: "PII Consent and Notification", description: "Verify that users are provided clear language regarding collection and use of supplied personal information and that users have provided opt-in consent for the use of that data before it is used in any way.", level: "L1" },
  { id: "V8.3.4", category: "V8 - Data Protection", title: "Data Created and Processed Identified", description: "Verify that all sensitive data created and processed by the application has been identified, and ensure that a policy is in place on how to deal with sensitive data. Data handling policies should cover the full lifecycle.", level: "L1" },
  { id: "V8.3.5", category: "V8 - Data Protection", title: "Data Collection Justification", description: "Verify accessing sensitive data is audited and that the data is collected under relevant data protection directives or where access logging is required. Each access to sensitive data should be logged with the requesting identity.", level: "L2" },
  { id: "V8.3.6", category: "V8 - Data Protection", title: "Sensitive Information in Memory Cleared", description: "Verify that sensitive information contained in memory is overwritten as soon as it is no longer required to mitigate memory dumping attacks, using zeroes or random data. Sensitive data in memory should have a minimal lifespan.", level: "L2" },
  { id: "V8.3.7", category: "V8 - Data Protection", title: "Sensitive Data Encrypted in Transit", description: "Verify that sensitive or private information that is required to be encrypted, is encrypted using approved algorithms that provide both confidentiality and integrity. Data in transit should use TLS 1.2 or higher.", level: "L2" },
  { id: "V8.3.8", category: "V8 - Data Protection", title: "Sensitive Personal Information Subject to Data Retention", description: "Verify that sensitive personal information is subject to data retention classification, such that old or out-of-date data is deleted automatically, on a schedule, or as the situation requires. Retention policies should be enforced.", level: "L2" },

  // ============================================================
  // V9 - Communication
  // ============================================================

  // V9.1 Client Communication Security
  { id: "V9.1.1", category: "V9 - Communication", title: "TLS for All Connections", description: "Verify that TLS is used for all client connectivity, and does not fall back to insecure or unencrypted communications. All connections between clients and the application must be encrypted using current TLS standards.", level: "L1" },
  { id: "V9.1.2", category: "V9 - Communication", title: "Current TLS Version", description: "Verify using up-to-date TLS testing tools that only strong cipher suites are enabled, with the strongest cipher suites set as preferred. TLS 1.2 or TLS 1.3 should be required, and older versions should be disabled.", level: "L1" },
  { id: "V9.1.3", category: "V9 - Communication", title: "Only Latest Recommended TLS Versions", description: "Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of TLS should be the preferred option for all encrypted communications.", level: "L1" },

  // V9.2 Server Communication Security
  { id: "V9.2.1", category: "V9 - Communication", title: "Trusted TLS Certificates", description: "Verify that connections to and from the server use trusted TLS certificates. Where internally generated or self-signed certificates are used, the server must be configured to only trust specific internal CAs and specific self-signed certificates.", level: "L2" },
  { id: "V9.2.2", category: "V9 - Communication", title: "Encrypted Communications for All Connections", description: "Verify that encrypted communications such as TLS is used for all inbound and outbound connections, including for management ports, monitoring, authentication, API, or web service calls, database, cloud, serverless, mainframe, external, and partner connections.", level: "L2" },
  { id: "V9.2.3", category: "V9 - Communication", title: "Authenticated External Connections", description: "Verify that all encrypted connections to external systems that involve sensitive information or functions are authenticated. Certificate pinning or mutual TLS should be used for connections to critical external services.", level: "L2" },
  { id: "V9.2.4", category: "V9 - Communication", title: "Proper Certificate Revocation", description: "Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured. The application should verify the revocation status of certificates before trusting them.", level: "L2" },
  { id: "V9.2.5", category: "V9 - Communication", title: "Backend TLS Connection Failure Logging", description: "Verify that backend TLS connection failures are logged. Monitoring TLS connection failures helps detect attempted man-in-the-middle attacks and certificate configuration problems before they impact users.", level: "L3" },

  // ============================================================
  // V10 - Malicious Code
  // ============================================================

  // V10.1 Code Integrity
  { id: "V10.1.1", category: "V10 - Malicious Code", title: "Code Analysis Tool in Use", description: "Verify that a code analysis tool is in use that can detect potentially malicious code, such as time functions, unsafe file operations, and network connections. Static analysis should be integrated into the build pipeline.", level: "L3" },
  { id: "V10.1.2", category: "V10 - Malicious Code", title: "No Malicious Features in Code", description: "Verify that the application source code and third-party libraries do not contain unauthorized phone home or data collection capabilities. Where such functionality exists, obtain the user's permission before collecting any data.", level: "L3" },

  // V10.2 Malicious Code Search
  { id: "V10.2.1", category: "V10 - Malicious Code", title: "No Time Bombs", description: "Verify that the application source code and third-party libraries do not contain time bombs by searching for date and time related functions. Time bombs are code that activates or deactivates at a specific date to cause harm.", level: "L3" },
  { id: "V10.2.2", category: "V10 - Malicious Code", title: "No Undocumented Accounts or Backdoors", description: "Verify that the application source code and third-party libraries do not contain unauthorized back doors, such as hard-coded or additional undocumented accounts, obfuscated code blobs, or undocumented binaries.", level: "L3" },
  { id: "V10.2.3", category: "V10 - Malicious Code", title: "No Easter Eggs or Undocumented Functionality", description: "Verify that the application source code and third-party libraries do not contain easter eggs or undocumented functionality that could be exploited. Such hidden features may bypass security controls or introduce vulnerabilities.", level: "L3" },
  { id: "V10.2.4", category: "V10 - Malicious Code", title: "No Internet Connections to Malicious Sites", description: "Verify that the application source code and third-party libraries do not contain code that connects to malicious or unauthorized internet endpoints. All network connections should be documented and authorized.", level: "L3" },
  { id: "V10.2.5", category: "V10 - Malicious Code", title: "No Unapproved Account Sharing", description: "Verify that the application source code and third-party libraries do not send data to unauthorized third parties. All data sharing should be documented, authorized by policy, and consented to by the user.", level: "L3" },
  { id: "V10.2.6", category: "V10 - Malicious Code", title: "Sensitive Data Not Exfiltrated", description: "Verify that the application does not contain code that exfiltrates sensitive data. Data loss prevention controls should be in place to detect and prevent unauthorized transmission of sensitive information.", level: "L3" },

  // V10.3 Application Integrity
  { id: "V10.3.1", category: "V10 - Malicious Code", title: "Auto-Update Over Secure Channel", description: "Verify that if the application has a client or server auto-update feature, updates should be obtained over secure channels and digitally signed. The update code must validate the digital signature of the update before installing or executing.", level: "L1" },
  { id: "V10.3.2", category: "V10 - Malicious Code", title: "Integrity Protections in Place", description: "Verify that the application employs integrity protections, such as code signing or subresource integrity. The application should not load or execute code from untrusted sources that are not signed or integrity-verified.", level: "L1" },
  { id: "V10.3.3", category: "V10 - Malicious Code", title: "Subresource Integrity for External Resources", description: "Verify that the application has protections against subdomain takeovers if the application relies upon DNS entries or DNS subdomains, such as expired domain names, out-of-date DNS pointers, or expired CDN resources.", level: "L1" },

  // ============================================================
  // V11 - Business Logic
  // ============================================================

  // V11.1 Business Logic Security
  { id: "V11.1.1", category: "V11 - Business Logic", title: "Sequential Step Processing", description: "Verify that the application will only process business logic flows for the same user in sequential step order and without skipping steps. Business process flows must enforce proper ordering to prevent bypass of required steps.", level: "L1" },
  { id: "V11.1.2", category: "V11 - Business Logic", title: "Realistic Human Time Processing", description: "Verify that the application will only process business logic flows with all steps being processed in realistic human time, meaning transactions are not submitted too quickly. This detects automated or scripted abuse.", level: "L1" },
  { id: "V11.1.3", category: "V11 - Business Logic", title: "Appropriate Limits for Business Actions", description: "Verify the application has appropriate limits for specific business actions or transactions which are correctly enforced on a per-user basis. Rate limits should prevent abuse while allowing legitimate use.", level: "L1" },
  { id: "V11.1.4", category: "V11 - Business Logic", title: "Anti-Automation Controls", description: "Verify the application has anti-automation controls to protect against excessive calls such as mass data exfiltration, business logic requests, file uploads, or denial of service attacks. Controls should be proportionate to risk.", level: "L1" },
  { id: "V11.1.5", category: "V11 - Business Logic", title: "Business Logic Integrity Checks", description: "Verify the application has business logic limits or validation to protect against likely business risks or threats, identified using threat modeling or similar methodologies. Critical business operations should have integrity checks.", level: "L1" },
  { id: "V11.1.6", category: "V11 - Business Logic", title: "TOCTOU Race Condition Prevention", description: "Verify that the application does not suffer from 'Time of Check to Time of Use' (TOCTOU) issues or other race conditions for sensitive operations. Atomicity should be ensured for operations that check then act on security-relevant state.", level: "L2" },
  { id: "V11.1.7", category: "V11 - Business Logic", title: "Unusual Activity Monitoring", description: "Verify the application monitors for unusual events or activity from a business logic perspective. For example, attempts to perform actions out of order or actions which a normal user would never attempt should be detected and alerted.", level: "L2" },
  { id: "V11.1.8", category: "V11 - Business Logic", title: "Alerting on Automated Attacks", description: "Verify that the application has configurable alerting when automated attacks or unusual activity is detected. Alerts should be sent to security operations for investigation and should include sufficient context for triage.", level: "L2" },

  // ============================================================
  // V12 - Files and Resources
  // ============================================================

  // V12.1 File Upload
  { id: "V12.1.1", category: "V12 - Files and Resources", title: "Large File Upload Prevention", description: "Verify that the application will not accept large files that could fill up storage or cause a denial-of-service attack. File size limits should be enforced server-side and communicated to users before upload.", level: "L1" },
  { id: "V12.1.2", category: "V12 - Files and Resources", title: "File Type Validation", description: "Verify that the application checks compressed files such as zip, gz, and docx against maximum allowed uncompressed size and maximum number of files. This prevents zip bomb attacks that exhaust server resources.", level: "L2" },
  { id: "V12.1.3", category: "V12 - Files and Resources", title: "File Size Quota Enforcement", description: "Verify that a file size quota and maximum number of files per user is enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files.", level: "L2" },

  // V12.2 File Integrity
  { id: "V12.2.1", category: "V12 - Files and Resources", title: "File Content Matches Expected Type", description: "Verify that files obtained from untrusted sources are validated to be of expected type based on the file's content. File type should not be determined solely by file extension, as extensions can be spoofed.", level: "L2" },

  // V12.3 File Execution
  { id: "V12.3.1", category: "V12 - Files and Resources", title: "User-Submitted Filename Metadata Not Used Directly", description: "Verify that user-submitted filename metadata is not used directly by system or framework filesystems, and that a URL API is used to protect against path traversal. Filenames should be sanitized or replaced with generated names.", level: "L1" },
  { id: "V12.3.2", category: "V12 - Files and Resources", title: "User-Submitted Filename Metadata Validated", description: "Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure, creation, updating, or removal of local files. Uploaded files should be stored with generated names rather than user-supplied names.", level: "L1" },
  { id: "V12.3.3", category: "V12 - Files and Resources", title: "User-Submitted Filename Metadata Not Used for Redirection", description: "Verify that user-submitted filename metadata is not used directly with system or library functions to prevent local file disclosure. Validate that file references point only to authorized locations.", level: "L1" },
  { id: "V12.3.4", category: "V12 - Files and Resources", title: "Remote File Inclusion Prevention", description: "Verify that the application protects against Reflective File Download (RFD) by validating or ignoring user-submitted filenames in a JSON, JSONP, or URL parameter. Set the Content-Disposition response header to a fixed filename.", level: "L1" },
  { id: "V12.3.5", category: "V12 - Files and Resources", title: "Untrusted File Metadata Not Used with System API", description: "Verify that untrusted file metadata is not used directly with system API or libraries, to protect against OS command injection. File metadata should be sanitized before being passed to any system call.", level: "L1" },
  { id: "V12.3.6", category: "V12 - Files and Resources", title: "Application Does Not Include Unvalidated Remote Content", description: "Verify that the application does not include and execute functionality from untrusted sources, such as unverified content distribution networks, JavaScript libraries, node npm libraries, or server-side DLLs.", level: "L2" },

  // V12.4 File Storage
  { id: "V12.4.1", category: "V12 - Files and Resources", title: "Files Stored Outside Web Root", description: "Verify that files obtained from untrusted sources are stored outside the web root, with limited permissions. Uploaded files should be stored in a location that prevents direct access through the web server.", level: "L1" },
  { id: "V12.4.2", category: "V12 - Files and Resources", title: "Files Scanned by Antivirus", description: "Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent upload and serving of known malicious content. Virus scanning should be performed before the file is made available.", level: "L1" },

  // V12.5 File Download
  { id: "V12.5.1", category: "V12 - Files and Resources", title: "Serving Specific Files Only", description: "Verify that the web tier is configured to serve only files with specific file extensions to prevent unintentional information and source code leakage. Only expected file types should be served by the web server.", level: "L1" },
  { id: "V12.5.2", category: "V12 - Files and Resources", title: "Direct Requests to Uploaded Files Prevention", description: "Verify that direct requests to uploaded files will never be executed as HTML or JavaScript content. Files should be served with appropriate Content-Type headers and Content-Disposition: attachment to prevent execution.", level: "L1" },

  // V12.6 SSRF Protection
  { id: "V12.6.1", category: "V12 - Files and Resources", title: "SSRF Protection Controls", description: "Verify that the web or application server is configured with an allow list of resources or systems to which the server can send requests or load data from. Server-side request forgery can lead to internal network exploitation.", level: "L1" },

  // ============================================================
  // V13 - API and Web Service
  // ============================================================

  // V13.1 Generic Web Service Security
  { id: "V13.1.1", category: "V13 - API and Web Service", title: "Same Encoding for All Clients", description: "Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit differing URI or file parsing behavior that could be used in SSRF and RFI attacks.", level: "L1" },
  { id: "V13.1.2", category: "V13 - API and Web Service", title: "API Access Control Verification", description: "Verify that access to administration and management functions within the Web Service Application is limited to web service administrators. APIs exposing administrative functionality require additional access control measures.", level: "L1" },
  { id: "V13.1.3", category: "V13 - API and Web Service", title: "Schema and Content Type Validation", description: "Verify that API URLs do not expose sensitive information, such as the API key, session tokens, etc. API endpoint design should follow security best practices for URL structure and parameter handling.", level: "L1" },
  { id: "V13.1.4", category: "V13 - API and Web Service", title: "Authorization Decisions at URI and Resource Level", description: "Verify that authorization decisions are made at both the URI, enforced by programmatic or declarative security at the controller or router, and at the resource level, enforced by model-based permissions.", level: "L1" },
  { id: "V13.1.5", category: "V13 - API and Web Service", title: "Unexpected Content Types Rejected", description: "Verify that requests containing unexpected or missing content types are rejected with appropriate headers (HTTP response status 406 Unacceptable or 415 Unsupported Media Type). Content type validation prevents deserialization attacks.", level: "L1" },

  // V13.2 RESTful Web Service
  { id: "V13.2.1", category: "V13 - API and Web Service", title: "Protected HTTP Methods in RESTful APIs", description: "Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users from using DELETE or PUT on protected API or resources. HTTP method restrictions should align with access control policies.", level: "L1" },
  { id: "V13.2.2", category: "V13 - API and Web Service", title: "JSON Schema Validation for REST", description: "Verify that JSON schema validation is in place and verified before accepting input. JSON schema defines the expected structure, types, and constraints that all input must conform to before processing.", level: "L1" },
  { id: "V13.2.3", category: "V13 - API and Web Service", title: "Cookie-Based REST Services Protection", description: "Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of the following: double submit cookie pattern, CSRF nonces, or Origin request header checks.", level: "L1" },
  { id: "V13.2.4", category: "V13 - API and Web Service", title: "REST Anti-Automation Controls", description: "Verify that REST services have anti-automation controls to protect against excessive calls, especially if the API is unauthenticated. Rate limiting should be implemented to prevent abuse and denial of service.", level: "L1" },
  { id: "V13.2.5", category: "V13 - API and Web Service", title: "REST API JSON Content Type", description: "Verify that REST services explicitly check that the incoming Content-Type is the expected one, such as application/xml or application/json. Incorrect content types should be rejected with appropriate HTTP status codes.", level: "L2" },
  { id: "V13.2.6", category: "V13 - API and Web Service", title: "Message-Level Encryption for Sensitive REST Data", description: "Verify that the message headers and payload are trustworthy and not modified in transit. Requiring strong encryption for transport (TLS only) may be sufficient in many cases, but message-level signing may be needed for high-security applications.", level: "L2" },

  // V13.3 SOAP Web Service
  { id: "V13.3.1", category: "V13 - API and Web Service", title: "XSD Schema Validation for SOAP", description: "Verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field before any processing of that data takes place. Schema validation prevents injection attacks.", level: "L1" },
  { id: "V13.3.2", category: "V13 - API and Web Service", title: "SOAP Message Signing", description: "Verify that the message payload is signed using WS-Security to ensure reliable transport between client and service. Message-level security ensures integrity even when transport security is compromised.", level: "L2" },

  // V13.4 GraphQL
  { id: "V13.4.1", category: "V13 - API and Web Service", title: "GraphQL Query Depth Limiting", description: "Verify that a query allow list or a combination of depth limiting and amount limiting is used to prevent GraphQL or data layer expression denial of service as a result of expensive, nested queries.", level: "L2" },
  { id: "V13.4.2", category: "V13 - API and Web Service", title: "GraphQL Authorization Logic", description: "Verify that GraphQL or other data layer authorization logic should be implemented at the business logic layer instead of the GraphQL layer. Authorization at the resolver level ensures consistent enforcement across all access paths.", level: "L2" },

  // ============================================================
  // V14 - Configuration
  // ============================================================

  // V14.1 Build and Deploy
  { id: "V14.1.1", category: "V14 - Configuration", title: "Separate Build and Deploy Environments", description: "Verify that the application build and deployment processes are performed in a secure fashion, such as CI/CD automation, automated configuration management, and automated deployment scripts. Build servers should be hardened.", level: "L2" },
  { id: "V14.1.2", category: "V14 - Configuration", title: "Compiler Flags Configured", description: "Verify that compiler flags are configured to enable all available buffer overflow protections and warnings, including stack randomization, data execution prevention, and to break the build if an unsafe pointer, memory, format string, integer, or string operation is found.", level: "L2" },
  { id: "V14.1.3", category: "V14 - Configuration", title: "Server Configuration Hardened", description: "Verify that server configuration is hardened as per the recommendations of the application server and frameworks in use. Default configurations are often insecure and should be reviewed and modified for production use.", level: "L2" },
  { id: "V14.1.4", category: "V14 - Configuration", title: "Automated Deployment Verification", description: "Verify that application, configuration, and all dependencies can be re-deployed using automated deployment scripts, built from a documented and tested runbook in a reasonable time, or restored from backups in a timely fashion.", level: "L2" },
  { id: "V14.1.5", category: "V14 - Configuration", title: "Authorized Administrators Verify Integrity", description: "Verify that authorized administrators can verify the integrity of all security-relevant configurations to detect tampering. Integrity verification should use cryptographic hashes or digital signatures.", level: "L3" },

  // V14.2 Dependency
  { id: "V14.2.1", category: "V14 - Configuration", title: "Up-to-Date Dependencies", description: "Verify that all components are up to date, preferably using a dependency checker during build or compile time. Components with known vulnerabilities should be updated or replaced promptly.", level: "L1" },
  { id: "V14.2.2", category: "V14 - Configuration", title: "No Unnecessary Features or Dependencies", description: "Verify that all unneeded features, documentation, sample applications, and configurations are removed. The application should only include components that are required for its operation to minimize the attack surface.", level: "L1" },
  { id: "V14.2.3", category: "V14 - Configuration", title: "Integrity Verification of External Assets", description: "Verify that if application assets, such as JavaScript libraries, CSS or web fonts, are hosted externally on a Content Delivery Network (CDN) or external provider, Subresource Integrity (SRI) is used to validate the integrity of the asset.", level: "L1" },
  { id: "V14.2.4", category: "V14 - Configuration", title: "Third-Party Components from Trusted Sources", description: "Verify that third-party components come from pre-defined, trusted, and continually maintained repositories. Components should be sourced from official package registries and verified against known vulnerability databases.", level: "L2" },
  { id: "V14.2.5", category: "V14 - Configuration", title: "Software Bill of Materials", description: "Verify that a Software Bill of Materials (SBOM) is maintained of all third-party libraries in use. The SBOM should be kept current and include version information, license data, and known vulnerability status.", level: "L2" },
  { id: "V14.2.6", category: "V14 - Configuration", title: "Sandboxed Third-Party Libraries", description: "Verify that the attack surface is reduced by sandboxing or encapsulating third-party libraries to expose only the required behavior into the application. Unnecessary API surface from dependencies should be hidden.", level: "L2" },

  // V14.3 Unintended Security Disclosure
  { id: "V14.3.1", category: "V14 - Configuration", title: "No Web or Application Server Disclosure", description: "Verify that web or application server and framework error messages are configured to deliver user-actionable, customized responses to eliminate any unintended security disclosures. Server version information should be suppressed.", level: "L1" },
  { id: "V14.3.2", category: "V14 - Configuration", title: "Debug Modes Disabled in Production", description: "Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles, and unintended security disclosures. Debug modes expose sensitive internal details.", level: "L1" },
  { id: "V14.3.3", category: "V14 - Configuration", title: "HTTP Headers Do Not Expose Server Details", description: "Verify that the HTTP headers or any part of the HTTP response do not expose detailed version information of system components. Server headers like X-Powered-By and Server should be removed or genericized.", level: "L1" },

  // V14.4 HTTP Security Headers
  { id: "V14.4.1", category: "V14 - Configuration", title: "Content-Type Header with Charset", description: "Verify that every HTTP response contains a Content-Type header. The Content-Type header should specify a safe character set such as UTF-8 or ISO-8859-1. Content must match the provided Content-Type header.", level: "L1" },
  { id: "V14.4.2", category: "V14 - Configuration", title: "X-Content-Type-Options: nosniff", description: "Verify that all API responses contain a Content-Disposition: attachment; filename='api.json' header or other appropriate Content-Disposition header, and X-Content-Type-Options: nosniff to prevent MIME type sniffing.", level: "L1" },
  { id: "V14.4.3", category: "V14 - Configuration", title: "Content Security Policy (CSP)", description: "Verify that a Content Security Policy (CSP) response header is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON, and JavaScript injection vulnerabilities. CSP should be as restrictive as possible.", level: "L1" },
  { id: "V14.4.4", category: "V14 - Configuration", title: "X-Frame-Options or CSP frame-ancestors", description: "Verify that all responses contain an X-Frame-Options header or use the Content-Security-Policy frame-ancestors directive to prevent content from being embedded in third-party sites. This prevents clickjacking attacks.", level: "L1" },
  { id: "V14.4.5", category: "V14 - Configuration", title: "Strict-Transport-Security Header", description: "Verify that a Strict-Transport-Security header is included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=15724800; includeSubdomains. HSTS ensures browsers always use HTTPS.", level: "L1" },
  { id: "V14.4.6", category: "V14 - Configuration", title: "Referrer-Policy Header", description: "Verify that a suitable Referrer-Policy header is included to avoid exposing sensitive information in the URL through the Referer header to untrusted parties. Set to 'no-referrer' or 'same-origin' for sensitive applications.", level: "L1" },
  { id: "V14.4.7", category: "V14 - Configuration", title: "No Unsafe Inline or Eval in CSP", description: "Verify that the Content Security Policy of the web application does not include unsafe-inline or unsafe-eval directives. These directives undermine the effectiveness of CSP and allow execution of injected scripts.", level: "L1" },

  // V14.5 HTTP Request Header Validation
  { id: "V14.5.1", category: "V14 - Configuration", title: "Application Server Accepts Only Configured Methods", description: "Verify that the application server only accepts the HTTP methods in use by the application or API, including pre-flight OPTIONS, and logs or alerts on any requests that are not valid for the application context.", level: "L1" },
  { id: "V14.5.2", category: "V14 - Configuration", title: "Origin Header Validation", description: "Verify that the supplied Origin header is not used for authentication or access control decisions, as the Origin header can easily be changed by an attacker. Origin validation should be a defense-in-depth measure only.", level: "L1" },
  { id: "V14.5.3", category: "V14 - Configuration", title: "CORS Access-Control-Allow-Origin Validation", description: "Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header uses a strict allow list of trusted domains and subdomains to match against and does not support the 'null' origin.", level: "L1" },
  { id: "V14.5.4", category: "V14 - Configuration", title: "HTTP Headers from Trusted Proxies Authenticated", description: "Verify that HTTP headers added by a trusted proxy or SSO devices, such as a bearer token, are authenticated by the application. Forwarded headers like X-Forwarded-For should only be trusted from known proxy sources.", level: "L2" }
];
