// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// The binding Terms of Service, in one place: the sign-in gate (auth.js) shows it for
// acceptance and the public /terms page shows it to visitors. Bump TOS_VERSION in auth.js
// whenever this text changes, so every account is asked to accept the new version.
export const TOS_HTML = `
<h3>Darknode Terms of Service</h3>
<p><strong>Last updated:</strong> October 31, 2026</p>
<p>By using Darknode ("the Platform"), including darknode.ai, the Darknode command center, the Darknode Deck and its Personal and Organization spaces, the code, cloud, dependency and web-exposure analysis engines, the Darknode CLI, the Nexus agent, Darknode OS, the API and MCP server, and all associated tools, you (and, where you act for an organization, that organization) agree to these terms. If you do not agree, do not use the Platform.</p>

<h4>1. Authorized Use Only</h4>
<p>Darknode is a platform for <strong>authorized security operations, vulnerability assessment, compliance review, and legitimate security research</strong> — used by and for organizations on their own code, systems, and data, or on those of clients who have authorized the work in writing. Its tools are designed to help you find and fix problems in environments you are permitted to assess, not to attack systems you are not.</p>
<p><strong>You MUST have explicit written authorization before testing any system, network, or application you do not own.</strong> This includes but is not limited to: penetration tests, vulnerability scans, social engineering assessments, wireless audits, and red team engagements. Unauthorized access to computer systems is a criminal offense under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws worldwide.</p>

<h4>2. No Guarantee of Security, Detection, or Compliance</h4>
<p>Darknode's tools perform <strong>automated analysis</strong> of code, dependencies, cloud configuration, systems and records. They identify <em>some</em> potential issues; they <strong>do not and cannot detect all vulnerabilities, misconfigurations, weaknesses, errors, or weaknesses</strong>, and may produce both false positives and false negatives.</p>
<p><strong>A clean, passing, or "no findings" result is NOT a certification, warranty, or representation that your code, systems, or data are secure, correct, compliant, or free of defects.</strong> Severity scores, risk ratings and compliance or framework mappings are informational aids only and are not a certification of compliance with any law, standard, or framework. The tools are an aid to — never a substitute for — qualified human review, professional penetration testing, and independent audit. <strong>You remain solely responsible for the security, correctness, and compliance of your own code, systems, and data, and for any decision to act or not act on any result.</strong></p>

<h4>3. No Professional Advice</h4>
<p>Nothing Darknode provides — including scan results, findings, scores, compliance mappings, reports, or recommendations — constitutes legal, accounting, tax, financial, audit, regulatory, or other professional advice, or a certification of compliance. You are responsible for obtaining independent professional advice before relying on any output.</p>

<h4>4. Disclaimer of Warranties</h4>
<p>The Platform is provided <strong>"as is" and "as available"</strong> without warranties of any kind, express, implied, or statutory, including but not limited to merchantability, fitness for a particular purpose, title, non-infringement, accuracy, completeness, reliability, security, or availability. Darknode does not warrant that the Platform will be uninterrupted or error-free, that defects will be corrected, or that results will be accurate or complete.</p>

<h4>5. Limitation of Liability</h4>
<p><strong>To the maximum extent permitted by applicable law, Darknode, its owners, creators, contributors, affiliates, and suppliers shall NOT be liable for any indirect, incidental, special, consequential, exemplary, or punitive damages, or for any loss of profits, revenue, data, goodwill, or business, business interruption, security breach, or third-party claim, arising out of or relating to the Platform or any result it produces — even if advised of the possibility of such damages, and regardless of the legal theory (contract, tort, negligence, strict liability, statute, or otherwise).</strong> This includes, without limitation, damages arising from: any undetected vulnerability, misconfiguration, or error; reliance on, or any action or inaction based on, any finding or the absence of a finding; any security incident, breach, or loss affecting your systems or data; any business decision; and the output or behavior of any automated tool or AI feature.</p>
<p><strong>In all cases, Darknode's total aggregate liability for all claims arising out of or relating to the Platform shall not exceed the greater of (a) the total fees you actually paid to Darknode for the Platform in the twelve (12) months immediately before the event giving rise to the claim, or (b) one hundred U.S. dollars (US$100).</strong> Some jurisdictions do not allow certain exclusions or limitations; in those jurisdictions the above applies to the maximum extent permitted, and nothing here limits liability that cannot lawfully be limited.</p>
<p><strong>Indemnification.</strong> You agree to defend, indemnify, and hold harmless Darknode, its owners, creators, contributors, and affiliates from and against any and all claims, liabilities, damages, losses, and expenses (including reasonable legal fees) arising out of or related to: your use of the Platform; your reliance on any result; your code, systems, or data; or your violation of these terms or of any law or third-party right.</p>

<h4>6. Self-Hosted and On-Premises Use</h4>
<p>Where you install or run Darknode in your own browser, infrastructure, or environment (including self-hosted, on-premises, or air-gapped deployments), <strong>you alone control and are responsible for that deployment</strong> — its configuration, access controls, updates, and all data processed within it. Darknode has no access to, and accepts no responsibility or liability for, your self-hosted instance, its security, or the data you process with it. Darknode does not receive, store, or have access to the source code, systems, or data you analyze client-side or in your own environment.</p>

<h4>7. Real Security Data</h4>
<p>Darknode provides real-world security intelligence including CVE databases, exploit references, MITRE ATT&amp;CK mappings, APT group profiles, vulnerability data, and penetration testing methodologies. This information is sourced from publicly available databases and is provided for <strong>defensive security, education, and authorized testing purposes only</strong>. Darknode does not create exploits — it references publicly known vulnerabilities to help defenders understand and mitigate threats.</p>

<h4>8. AI Features</h4>
<p>The built-in web assistant sends your messages through Darknode's edge proxy to a third-party model provider (Google Gemini by default, or Anthropic when a signed-in user picks a Claude model) and returns the answer. Darknode does not log or store those prompts or responses; the provider processes them under its own terms. In Nexus, the CLI, and the desktop app you choose the engine: local models (such as Ollama) keep everything on your machine, and cloud engines use your own account or API key with that provider. When you connect a security integration in the Deck, the assistant can run lookups on it (for example an IP, domain, hash or CVE); it shows each call and asks before sending it, unless you choose Always allow for that lookup. AI output can be wrong; review it before acting on it. You are responsible for your own API usage and costs and for any actions taken by AI agents you run.</p>

<h4>9. Plans and Feature Availability</h4>
<p>Which tools and spaces you can use depends on your plan. Features outside your plan are not shown. We may move features between plans, and features marked as coming soon may change before release.</p>

<h4>10. User Responsibility</h4>
<p><strong>You are solely and entirely responsible for:</strong></p>
<ul>
  <li>Obtaining proper written authorization before any security testing</li>
  <li>Complying with all applicable local, state, national, and international laws</li>
  <li>Any code, payloads, exploits, or tools you generate, modify, or execute</li>
  <li>Securing your own API keys, credentials, and sensitive data</li>
  <li>Understanding the legal implications of your actions in your jurisdiction</li>
  <li>Any damage caused to systems, networks, or data during authorized testing</li>
</ul>

<h4>11. Prohibited Activities</h4>
<p>You agree NOT to use Darknode for:</p>
<ul>
  <li>Attacking, scanning, or probing systems without explicit written authorization, including with the web-security toolkit</li>
  <li>Creating, distributing, or deploying malware for malicious purposes</li>
  <li>Conducting denial-of-service attacks against unauthorized targets</li>
  <li>Stealing, selling, or exposing personal data or credentials</li>
  <li>Reverse-engineering, reselling, or redistributing the Platform or its source code in violation of the license</li>
  <li>Any activity that violates applicable cybercrime laws</li>
</ul>
<p>Violation of these terms may result in immediate account termination and reporting to appropriate authorities.</p>

<h4>12. Intellectual Property</h4>
<p>The Platform, its design, code, branding, documentation, and all related assets are the intellectual property of Darknode and its contributors, protected by copyright and trademark law. You may not copy, modify, distribute, or create derivative works from the Platform except as expressly permitted by the applicable open-source license.</p>
<p><strong>Your content:</strong> You retain all rights to data, reports, scan results, and other outputs you create using the Platform. By using collaborative or cloud features, you grant Darknode a limited, non-exclusive license to process that content solely to provide the service.</p>
<p>The Platform incorporates open-source components distributed under their respective licenses. A list is available in the project repository.</p>

<h4>13. Intended Users</h4>
<p>Darknode is intended for individuals, organizations, and security, engineering, and compliance professionals operating on systems, code, and data they own or are authorized to assess. Training, lab, and simulation features are provided for skills development within that authorized context. We do not endorse, encourage, or condone any unlawful activity.</p>

<h4>14. Data &amp; Privacy</h4>
<p>We store minimal user data in Firebase (Google Cloud):</p>
<ul>
  <li><strong>What we collect:</strong> email address, display name, profile photo URL, login timestamps, and ToS acceptance records.</li>
  <li><strong>Legal basis:</strong> legitimate interest (providing the service) and your consent (accepting these terms).</li>
  <li><strong>Data retention:</strong> your data is retained while your account is active. After deletion, data is purged within 30 days, except where retention is required by law.</li>
  <li><strong>Integration relay:</strong> Deck integrations with providers that do not accept calls from a browser (such as VirusTotal, Shodan or AbuseIPDB) send your API key and the value you look up through Darknode's edge relay to that provider only. The relay uses the key for that one request and does not log or store the key, the value or the result; the provider processes them under its own terms. Keys stay in your browser, under your account.</li>
  <li><strong>Weekly email digest (optional):</strong> only if you turn it on, we store your watched domains and latest certificate-check results to build a weekly email, sent to your account email through our email provider (Resend). You can turn it off at any time in Settings or from the unsubscribe link.</li>
  <li><strong>Product usage:</strong> when you are signed in to the Nexus terminal agent or the Darknode desktop app, it tells us about every 6 hours that your account uses it, with the app version and operating system; the desktop app also reports how many virtual machines its VM manager holds and when one last started (never their names, disks or contents). We use this to know which products and versions to support. Turn it off with <code>/shareusage off</code> in Nexus or Settings &gt; Share app usage in the desktop app.</li>
  <li><strong>No selling or sharing:</strong> we do not sell, rent, or share your personal data with third parties for marketing purposes.</li>
  <li><strong>Cookies:</strong> we use only essential cookies and localStorage for session management and user preferences. We do not use tracking cookies or third-party analytics.</li>
  <li><strong>International transfers:</strong> data is processed and stored in Google Cloud data centers. By using the Platform, you consent to transfer of data to servers that may be outside your country of residence.</li>
</ul>
<p><strong>Your rights (GDPR, CCPA, and similar laws):</strong> depending on your jurisdiction, you may have the right to access, correct, delete, or export your personal data, restrict processing, object to processing, or withdraw consent. To exercise any of these rights, email <strong>contact@darknode.ai</strong>. We will respond within 30 days. You also have the right to lodge a complaint with your local data protection authority.</p>

<h4>15. Account Termination</h4>
<p><strong>By you:</strong> you may stop using the Platform and request account deletion at any time by emailing contact@darknode.ai. Upon deletion, your data will be removed in accordance with Section 14.</p>
<p><strong>By us:</strong> we may suspend or terminate your account immediately, without prior notice, if we reasonably believe you have violated these terms. We may also discontinue the Platform or any feature at any time with reasonable notice.</p>

<h4>16. Paid Plans &amp; Pricing</h4>
<p>The core Platform is free. Paid plans (when available) unlock additional professional features. Prices are listed on the pricing page and may change with at least <strong>30 days' notice</strong> before your next billing cycle. Refunds are handled on a case-by-case basis. Cancellation takes effect at the end of the current billing period. You are responsible for any applicable taxes.</p>

<h4>17. Service Availability</h4>
<p>We aim for high availability but do not guarantee uninterrupted access. We are not liable for downtime caused by events beyond our reasonable control, including but not limited to: natural disasters, internet outages, hosting provider failures, government actions, cyberattacks, or other force majeure events. Scheduled maintenance will be announced when feasible.</p>

<h4>18. Dispute Resolution</h4>
<p>If a dispute arises, you agree to first attempt resolution by emailing contact@darknode.ai. If we cannot resolve it within 60 days, either party may pursue binding arbitration under the rules of a mutually agreed arbitration provider, conducted in English. <strong>You agree to resolve disputes on an individual basis and waive the right to participate in a class action.</strong> Nothing in this section prevents either party from seeking injunctive relief in court for intellectual property violations or imminent harm.</p>

<h4>19. Governing Law</h4>
<p>These terms are governed by and construed in accordance with the laws of the State of California, United States, without regard to conflict-of-law principles. Any legal proceedings not subject to arbitration shall be brought in the state or federal courts located in California.</p>

<h4>20. Changes to These Terms</h4>
<p>We may update these terms from time to time. When we make material changes, we will notify you by email or by posting a notice on the Platform at least <strong>14 days before</strong> the changes take effect. If you continue to use the Platform after the effective date, you accept the updated terms. If you disagree, you may close your account before the changes take effect.</p>

<h4>21. General Provisions</h4>
<ul>
  <li><strong>Entire agreement:</strong> these terms, together with any referenced policies, constitute the entire agreement between you and Darknode regarding the Platform and supersede all prior agreements.</li>
  <li><strong>Severability:</strong> if any provision of these terms is found to be unenforceable or invalid, that provision will be limited or eliminated to the minimum extent necessary, and the remaining provisions will remain in full force.</li>
  <li><strong>No waiver:</strong> failure to enforce any right or provision does not constitute a waiver of that right or provision.</li>
  <li><strong>Assignment:</strong> you may not assign these terms without our written consent. We may assign our rights and obligations without restriction.</li>
</ul>

<h4>Contact</h4>
<p>Questions about these terms? Email <strong>contact@darknode.ai</strong>.</p>

<!-- The pointing-up emoji below is the one emoji the owner explicitly asked to keep here (points up at the terms); no other emojis in the UI. -->
<p class="tos-aside">Our lawyers made us say all of that. <span aria-hidden="true">&#9757;&#65039;</span> They were, regrettably, correct. The short version, which changes none of the legally binding version above: the tools help, they are not magic, nothing here is a guarantee, and you are responsible for your own systems, data, and decisions. Read a real audit before you bet the company on anything.</p>
`;

// Public legal pages for signed-out visitors (/terms, /privacy, /acceptable-use).
export async function renderLegal(mount, id) {
  let html = TOS_HTML;
  // The docs sections carry no heading of their own (the docs sidebar names them).
  if (id !== "terms") html = "<h3>" + ({ privacy: "Privacy Policy", "acceptable-use": "Acceptable Use Policy" }[id] || "") + "</h3>" + (await import("/js/docs.js?v=20261102a")).docSectionHTML(id);
  mount.innerHTML = '<article class="dn-legal">' + html + "</article>";
}
