const esc = (s) => String(s != null ? s : '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const WORDLIST = [
  'www','mail','ftp','admin','api','dev','staging','test','beta','portal','vpn','remote','git','jenkins','jira',
  'confluence','grafana','kibana','elastic','prometheus','vault','consul','traefik','nginx','apache','docker','k8s',
  'registry','cdn','static','assets','img','media','upload','backup','old','new','legacy','internal','intranet',
  'extranet','webmail','owa','exchange','outlook','autodiscover','sso','auth','login','accounts','id','oauth',
  'saml','cas','ldap','radius','dns','ns1','ns2','ns3','ns4','mx','mx1','mx2','smtp','pop','pop3','imap','ntp',
  'snmp','syslog','monitoring','nagios','zabbix','prtg','splunk','siem','waf','proxy','cache','lb','ha','cluster',
  'node','node1','node2','node3','worker','worker1','worker2','master','db','db1','db2','db3','mysql','postgres',
  'postgresql','redis','mongo','mongodb','elastic','elasticsearch','rabbit','rabbitmq','kafka','mq','queue','search',
  'solr','lucene','hadoop','spark','airflow','notebook','jupyter','lab','sandbox','demo','preview','canary','edge',
  'blue','green','prod','production','uat','qa','ci','cd','build','deploy','release','pkg','repo','npm','pip',
  'maven','helm','chart','terraform','ansible','puppet','chef','salt','app','app1','app2','app3','web','web1',
  'web2','web3','server','server1','server2','host','host1','host2','gateway','gw','firewall','fw','router','switch',
  'core','dmz','bastion','jump','jumpbox','relay','bridge','tunnel','openvpn','wireguard','ipsec','ikev2',
  'www2','www3','m','mobile','wap','blog','shop','store','ecommerce','cart','pay','payment','billing','invoice',
  'crm','erp','hr','finance','accounting','legal','compliance','audit','security','sec','infosec','soc','noc',
  'helpdesk','support','ticket','service','services','desk','status','health','monitor','alert','alerts','log',
  'logs','metrics','stats','analytics','data','warehouse','lake','etl','pipeline','stream','event','events','hook',
  'hooks','webhook','webhooks','callback','notify','notification','push','pubsub','ws','websocket','socket','io',
  'realtime','live','chat','messenger','slack','teams','discord','irc','matrix','xmpp','jabber','voip','sip',
  'pbx','asterisk','freeswitch','tel','phone','call','video','meet','zoom','webex','conf','conference','meeting',
  'calendar','cal','schedule','booking','reserve','docs','doc','document','documents','wiki','knowledge','kb',
  'faq','help','guide','manual','handbook','readme','info','about','contact','feedback','survey','form','forms',
  'poll','vote','forum','community','board','discuss','discussion','comment','comments','review','reviews',
  'news','press','blog','article','articles','post','posts','content','cms','wordpress','wp','drupal','joomla',
  'magento','shopify','squarespace','ghost','strapi','directus','contentful','sanity','prismic','netlify','vercel',
  'heroku','aws','azure','gcp','cloud','cloudflare','fastly','akamai','cloudfront','s3','storage','bucket',
  'blob','file','files','share','download','downloads','dist','release','releases','archive','archives','temp',
  'tmp','cache2','staging2','preprod','pre','stg','sit','dev1','dev2','dev3','test1','test2','test3','uat1','uat2',
  'alpha','rc','nightly','snapshot','latest','current','stable','lts','experimental','feature','feat','branch',
  'patch','hotfix','fix','debug','trace','profile','perf','bench','benchmark','load','stress','chaos','monkey',
  'canary2','dark','shadow','mirror','replica','slave','standby','failover','dr','disaster','recovery','cold',
  'warm','hot','primary','secondary','tertiary','active','passive','leader','follower','member','peer','seed',
  'bootstrap','init','setup','install','config','configure','provision','orchestrate','manage','manager','mgmt',
  'control','controller','panel','dashboard','console','cockpit','admin2','administrator','root','superadmin',
  'operator','ops','devops','sre','platform','infra','infrastructure','network','net','lan','wan','dmz2','vlan',
  'subnet','segment','zone','region','dc','datacenter','colo','rack','shelf','blade','hypervisor','vmware','esxi',
  'vcenter','kvm','qemu','proxmox','ovirt','xen','citrix','hyperv','hyper-v','container','containers','pod','pods',
  'namespace','ns','ingress','egress','loadbalancer','nlb','alb','elb','haproxy','nginx2','envoy','istio','linkerd',
  'consul2','nomad','swarm','compose','stack','ecs','eks','aks','gke','openshift','rancher','portainer','watchtower',
  'vault2','secrets','secret','key','keys','cert','certs','certificate','certificates','ca','pki','acme','letsencrypt',
  'ssl','tls','https2','http2','h2','quic','http3','grpc','graphql','rest','restapi','jsonapi','soap','wsdl','xml',
  'rpc','thrift','protobuf','avro','msgpack','binary','tcp','udp','icmp','arp','bgp','ospf','eigrp','rip','isis',
  'mpls','sd-wan','sdwan','sdn','nfv','overlay','underlay','fabric','spine','leaf','tor','distribution','access',
  'aggregation','border','edge2','pop','peering','ix','ixp','exchange2','transit','upstream','downstream','peer2',
  'customer','provider','vendor','partner','supplier','client','tenant','user','users','member2','guest','visitor',
  'anonymous','public','private','internal2','external','open','closed','restricted','confidential','secret2',
  'topsecret','classified','unclassified','sensitive','pii','phi','pci','hipaa','gdpr','sox','fisma','fedramp',
  'nist','iso','cis','owasp','sans','mitre','attack','defend','detect','respond','recover','protect','prevent',
  'identify','assess','remediate','mitigate','accept','transfer','avoid','report','investigate','analyze','triage',
  'contain','eradicate','restore','lesson','postmortem','retrospective','runbook','playbook','procedure','policy',
  'standard','guideline','framework','control','safeguard','countermeasure','defense','offence','red','blue2',
  'purple','white','yellow','orange','green2','black','grey','gray','pentest','vulnerability','exploit','payload',
  'shellcode','backdoor','implant','beacon','c2','command','cnc','rat','trojan','worm','virus','ransomware','crypto2',
  'miner','botnet','zombie','spam','phish','phishing','smishing','vishing','whaling','spear','apt','threat',
  'indicator','ioc','ioa','ttp','tactic','technique','sub-technique','procedure2','campaign','operation','actor',
  'group','gang','syndicate','cartel','nation-state','hacktivist','insider','outsider','adversary','attacker',
  'defender','hunter','analyst','engineer','architect','developer','programmer','coder','hacker','researcher',
  'consultant','auditor','assessor','tester','operator2','responder','handler','investigator','forensic',
  'examiner','specialist','expert','professional','practitioner','officer','director','manager2','lead','senior',
  'junior','intern','associate','staff','principal','fellow','distinguished','chief','ciso','cto','cio','coo',
  'ceo','cfo','cro','cpo','dpo','vp','svp','evp','avp','head','owner2','founder','cofounder','partner2',
  'webdisk','cpanel','whm','plesk','directadmin','cpcalendars','cpcontacts','webdav','dav','caldav','carddav',
  'sync','backup2','snapshot2','clone','fork','merge','rebase','commit','tag','branch2','trunk','head2','tip',
  'base','origin','upstream2','downstream2','remote2','local','localhost','loopback','self','me','my','home',
  'default','example','sample','placeholder','dummy','mock','fake','stub','noop','null','void','empty','blank',
  'unknown','undefined','none','na','n-a','tbd','todo','fixme','hack','workaround','temp2','temporary','interim',
  'scratch','draft','wip','poc','mvp','prototype','proof','concept','idea','experiment','trial','pilot','gamma',
  'delta','epsilon','zeta','eta','theta','iota','kappa','lambda','mu','nu','xi','omicron','pi','rho','sigma',
  'tau','upsilon','phi','chi','psi','omega','one','two','three','four','five','six','seven','eight','nine','ten',
  'smtp2','pop2','imap2','webmail2','roundcube','rainloop','horde','squirrelmail','zimbra','postfix','dovecot',
  'sendmail','exim','qmail','mailman','listserv','announce','newsletter','subscribe','unsubscribe','bounce',
  'abuse','postmaster','hostmaster','webmaster','security2','noc2','admin3','info2','root2','mailer-daemon',
  'no-reply','noreply','do-not-reply','auto','automated','system','robot','bot','crawler','spider','scraper',
  'agent','proxy2','relay2','gateway2','bridge2','hub','spoke','mesh','star','ring','bus','tree','hybrid',
  'flat','hierarchical','distributed','centralized','decentralized','federated','sovereign','autonomous',
  'managed','unmanaged','hosted','dedicated','shared','multi-tenant','single-tenant','bare-metal','virtual',
  'cloud2','edge3','fog','mist','hybrid2','multi-cloud','poly-cloud','cross-cloud','inter-cloud','cloud-native',
  'serverless','lambda2','function','functions','faas','paas','iaas','saas','xaas','baas','maas','daas',
  'caas','kaas','dbaas','seaas','idaas','cpaas','ucaas','ccaas','sase','ztna','casb','cspm','cwpp','cnapp',
  'soar','xdr','edr','ndr','mdr','mssp','msp','isp','asp','bsp','ssp','csp','tsp','asp2',
  'vpn2','ssl-vpn','sslvpn','ras','citrix2','rdp','rds','terminal','ts','vnc','ssh','sftp','scp','rsync',
  'nfs','smb','cifs','afp','iscsi','fc','fcoe','infiniband','rdma','nvme','nvmeof','san','nas','das',
  'raid','lvm','zfs','btrfs','xfs','ext4','ntfs','fat32','exfat','apfs','hfs','swap','page','tmpfs','ramfs',
  'proc','sys','dev2','run','var','log2','lib','bin','sbin','usr','etc','opt','srv','mnt','boot','grub',
  'efi','bios','uefi','firmware','driver','module','kernel','init2','systemd2','upstart','sysvinit','openrc',
  'launchd','service2','daemon','process','thread','task','job','cron2','at','batch','queue2','worker3',
  'pool','scheduler','dispatcher','executor','runtime','engine','interpreter','compiler','assembler','linker',
  'loader','debugger','profiler2','tracer','monitor2','watcher','observer','listener','subscriber','publisher',
  'producer','consumer','reader','writer','sender','receiver','source','sink','input','output','stdin','stdout',
  'stderr','pipe','fifo','socket2','port','bind2','listen2','accept2','connect2','send','recv','read2','write2',
];

const TAKEOVER_FINGERPRINTS = [
  { service: 'GitHub Pages', cname: ['github.io', 'github.com'], fingerprint: "There isn't a GitHub Pages site here.", vulnerable: true },
  { service: 'Heroku', cname: ['herokuapp.com', 'herokussl.com'], fingerprint: 'No such app', vulnerable: true },
  { service: 'AWS S3', cname: ['s3.amazonaws.com', 's3-website'], fingerprint: 'NoSuchBucket', vulnerable: true },
  { service: 'AWS CloudFront', cname: ['cloudfront.net'], fingerprint: 'Bad request', vulnerable: false },
  { service: 'Azure', cname: ['azurewebsites.net', 'cloudapp.azure.com', 'trafficmanager.net', 'blob.core.windows.net', 'azure-api.net', 'azurehdinsight.net', 'azureedge.net'], fingerprint: 'Error 404 - Web app not found', vulnerable: true },
  { service: 'Shopify', cname: ['myshopify.com'], fingerprint: 'Sorry, this shop is currently unavailable', vulnerable: true },
  { service: 'Tumblr', cname: ['tumblr.com'], fingerprint: "There's nothing here.", vulnerable: true },
  { service: 'WordPress.com', cname: ['wordpress.com'], fingerprint: 'Do you want to register', vulnerable: true },
  { service: 'Pantheon', cname: ['pantheonsite.io'], fingerprint: '404 error unknown site', vulnerable: true },
  { service: 'Fastly', cname: ['fastly.net'], fingerprint: 'Fastly error: unknown domain', vulnerable: true },
  { service: 'Zendesk', cname: ['zendesk.com'], fingerprint: 'Help Center Closed', vulnerable: true },
  { service: 'Unbounce', cname: ['unbouncepages.com'], fingerprint: 'The requested URL was not found on this server', vulnerable: true },
  { service: 'HubSpot', cname: ['hs-sites.com'], fingerprint: 'Domain not found', vulnerable: false },
  { service: 'Surge.sh', cname: ['surge.sh'], fingerprint: 'project not found', vulnerable: true },
  { service: 'Bitbucket', cname: ['bitbucket.io'], fingerprint: 'Repository not found', vulnerable: true },
  { service: 'Ghost', cname: ['ghost.io'], fingerprint: 'The thing you were looking for is no longer here', vulnerable: true },
  { service: 'Netlify', cname: ['netlify.app', 'netlify.com'], fingerprint: 'Not Found - Request ID', vulnerable: false },
  { service: 'Vercel', cname: ['vercel.app', 'now.sh'], fingerprint: 'DEPLOYMENT_NOT_FOUND', vulnerable: false },
  { service: 'Firebase', cname: ['firebaseapp.com', 'web.app'], fingerprint: 'Site Not Found', vulnerable: false },
  { service: 'Fly.io', cname: ['fly.dev'], fingerprint: '404 Not Found', vulnerable: false },
  { service: 'Render', cname: ['onrender.com'], fingerprint: 'Not Found', vulnerable: false },
  { service: 'Cargo Collective', cname: ['cargocollective.com'], fingerprint: '404 Not Found', vulnerable: true },
  { service: 'UserVoice', cname: ['uservoice.com'], fingerprint: 'This UserVoice subdomain is currently available', vulnerable: true },
  { service: 'GetResponse', cname: ['gr8.com'], fingerprint: 'With GetResponse', vulnerable: true },
  { service: 'Help Scout', cname: ['helpscoutdocs.com'], fingerprint: 'No settings were found for this company', vulnerable: true },
  { service: 'Campaign Monitor', cname: ['createsend.com'], fingerprint: 'Trying to access your account', vulnerable: true },
  { service: 'Canny', cname: ['canny.io'], fingerprint: 'Company Not Found', vulnerable: true },
  { service: 'Tilda', cname: ['tilda.ws'], fingerprint: 'Domain has been assigned', vulnerable: true },
  { service: 'Webflow', cname: ['webflow.io'], fingerprint: "The page you are looking for doesn't exist", vulnerable: true },
  { service: 'Readme.io', cname: ['readme.io'], fingerprint: 'Project doesnt exist', vulnerable: true },
  { service: 'Strikingly', cname: ['s.strikinglydns.com'], fingerprint: 'page not found', vulnerable: true },
  { service: 'Smartling', cname: ['smartling.com'], fingerprint: 'Domain is not configured', vulnerable: true },
  { service: 'Desk.com', cname: ['desk.com'], fingerprint: 'Sorry, We Couldn\'t Find That Page', vulnerable: true },
  { service: 'Feedpress', cname: ['redirect.feedpress.me'], fingerprint: 'The feed has not been found', vulnerable: true },
  { service: 'Freshdesk', cname: ['freshdesk.com'], fingerprint: 'There is no helpdesk here', vulnerable: false },
  { service: 'LaunchRock', cname: ['launchrock.com'], fingerprint: 'It looks like you may have taken a wrong turn somewhere', vulnerable: true },
  { service: 'Pingdom', cname: ['stats.pingdom.com'], fingerprint: 'This public report page has not been activated', vulnerable: true },
  { service: 'Statuspage', cname: ['statuspage.io'], fingerprint: 'You are being redirected', vulnerable: true },
  { service: 'Teamwork', cname: ['teamwork.com'], fingerprint: 'Oops - We didn\'t find your site', vulnerable: true },
  { service: 'Thinkific', cname: ['thinkific.com'], fingerprint: "You may have mistyped the address", vulnerable: true },
];

const HOMOGLYPHS = { a: ['@','4','q'], b: ['d','6'], c: ['e','('], d: ['b','cl'], e: ['3','c'], f: ['t'], g: ['q','9'], h: ['b','n'], i: ['1','l','!'], j: ['i'], k: ['lk','x'], l: ['1','i','|'], m: ['n','rn','nn'], n: ['m','r'], o: ['0','q'], p: ['q','b'], q: ['g','p'], r: ['n'], s: ['5','z','$'], t: ['f','7'], u: ['v','w'], v: ['u','w'], w: ['vv','uu'], x: ['k','ks'], y: ['v'], z: ['s','2'] };

function generatePermutations(domain) {
  const parts = domain.split('.');
  if (parts.length < 2) return [];
  const name = parts.slice(0, -1).join('.');
  const tld = parts[parts.length - 1];
  const results = [];
  for (let i = 0; i < name.length; i++) {
    const ch = name[i].toLowerCase();
    if (HOMOGLYPHS[ch]) {
      for (const h of HOMOGLYPHS[ch]) {
        results.push({ type: 'Homoglyph', domain: name.slice(0, i) + h + name.slice(i + 1) + '.' + tld });
      }
    }
  }
  for (let i = 0; i < name.length - 1; i++) {
    results.push({ type: 'Transposition', domain: name.slice(0, i) + name[i+1] + name[i] + name.slice(i+2) + '.' + tld });
  }
  for (let i = 0; i < name.length; i++) {
    results.push({ type: 'Omission', domain: name.slice(0, i) + name.slice(i + 1) + '.' + tld });
  }
  for (let i = 0; i <= name.length; i++) {
    for (const c of 'abcdefghijklmnopqrstuvwxyz0123456789-'.split('')) {
      if (i < name.length && name[i] === c) continue;
      const d = name.slice(0, i) + c + name.slice(i) + '.' + tld;
      if (d !== domain && results.length < 200) results.push({ type: 'Insertion', domain: d });
    }
    if (results.length > 200) break;
  }
  const altTlds = ['com','net','org','io','co','info','biz','xyz','app','dev','ai','cc','us','uk','de','fr','ru','cn','in','br','me','tv','pro','tech','site','online','store','shop','cloud','security','hack','cyber'];
  for (const t of altTlds) {
    if (t !== tld) results.push({ type: 'TLD swap', domain: name + '.' + t });
  }
  if (parts.length > 2) {
    results.push({ type: 'Missing dot', domain: parts[0] + parts[1] + '.' + parts.slice(2).join('.') });
  }
  return results.slice(0, 300);
}

function simulateScan(domain, words) {
  const results = [];
  const hash = (s) => { let h = 0; for (let i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0; } return Math.abs(h); };
  const ips = ['192.168.1.', '10.0.0.', '172.16.', '104.21.', '1.2.3.', '34.102.', '151.101.', '185.199.'];
  const servers = ['nginx/1.24', 'Apache/2.4', 'cloudflare', 'AmazonS3', 'gws', 'Microsoft-IIS/10.0', 'LiteSpeed', 'openresty'];
  const titles = ['Login', 'Dashboard', 'Admin Panel', 'Welcome', 'Portal', 'API Documentation', 'Status Page', 'Service'];
  const portSets = [['80','443'], ['80','443','22'], ['443'], ['80','443','8080'], ['22','80','443'], ['80','443','3306'], ['80','443','8443']];
  for (const w of words) {
    const sub = w + '.' + domain;
    const h = hash(sub);
    if (h % 5 < 2) {
      results.push({
        subdomain: sub,
        ip: ips[h % ips.length] + (h % 254 + 1),
        status: (h % 10 === 0) ? 'Timeout' : 'Live',
        title: titles[h % titles.length],
        server: servers[h % servers.length],
        ports: portSets[h % portSets.length],
        records: { A: ips[h % ips.length] + (h % 254 + 1), CNAME: (h % 3 === 0) ? 'cdn.' + domain : '' }
      });
    }
  }
  return results;
}

function renderResultsTable(results) {
  if (!results.length) return '<p style="color:var(--mut);padding:12px">No subdomains found with current wordlist.</p>';
  var html = '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">';
  html += '<thead><tr style="border-bottom:2px solid var(--line);text-align:left">';
  html += '<th style="padding:6px 8px">Subdomain</th><th style="padding:6px 8px">IP</th><th style="padding:6px 8px">Status</th>';
  html += '<th style="padding:6px 8px">Title</th><th style="padding:6px 8px">Server</th><th style="padding:6px 8px">Ports</th></tr></thead><tbody>';
  for (var i = 0; i < results.length; i++) {
    var r = results[i];
    var statusColor = r.status === 'Live' ? 'var(--acc)' : '#f59e0b';
    html += '<tr style="border-bottom:1px solid var(--line)">';
    html += '<td style="padding:6px 8px;font-family:var(--mono,monospace)">' + esc(r.subdomain) + '</td>';
    html += '<td style="padding:6px 8px;font-family:var(--mono,monospace)">' + esc(r.ip) + '</td>';
    html += '<td style="padding:6px 8px;color:' + statusColor + '">' + esc(r.status) + '</td>';
    html += '<td style="padding:6px 8px">' + esc(r.title) + '</td>';
    html += '<td style="padding:6px 8px;color:var(--mut)">' + esc(r.server) + '</td>';
    html += '<td style="padding:6px 8px;font-family:var(--mono,monospace)">' + r.ports.join(', ') + '</td>';
    html += '</tr>';
  }
  html += '</tbody></table></div>';
  return html;
}

export function renderSubdomainFinder(main) {
  var scanResults = [];

  main.innerHTML =
    '<h1 class="pg-h1">Subdomain Finder</h1>' +
    '<p class="muted pg-sub">Subdomain enumeration, DNS reconnaissance, takeover detection, and typosquat generation. All analysis is client-side simulation.</p>' +
    '<div class="tab-bar" id="sf-tabs">' +
      '<button class="tab active" data-tab="enum">Enumeration</button>' +
      '<button class="tab" data-tab="takeover">Takeover Check</button>' +
      '<button class="tab" data-tab="permute">Permutation</button>' +
      '<button class="tab" data-tab="ct">CT Logs</button>' +
      '<button class="tab" data-tab="wordlist">Wordlist</button>' +
    '</div>' +
    '<div id="sf-content"></div>';

  var content = main.querySelector('#sf-content');
  var tabs = main.querySelector('#sf-tabs');

  function switchTab(id) {
    tabs.querySelectorAll('.tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === id); });
    if (id === 'enum') renderEnum();
    else if (id === 'takeover') renderTakeover();
    else if (id === 'permute') renderPermute();
    else if (id === 'ct') renderCT();
    else if (id === 'wordlist') renderWordlistTab();
  }

  function renderEnum() {
    content.innerHTML =
      '<div style="margin-top:12px">' +
        '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
          '<input type="text" class="tk-in" id="sf-domain" placeholder="example.com" style="flex:1;min-width:200px">' +
          '<button class="btn sm" id="sf-scan">Scan Subdomains</button>' +
          '<button class="btn sm ghost" id="sf-export-csv">Export CSV</button>' +
          '<button class="btn sm ghost" id="sf-export-json">Export JSON</button>' +
        '</div>' +
        '<div style="margin-top:6px;font-size:.75rem;color:var(--mut)">Uses a built-in wordlist of ' + WORDLIST.length + ' common subdomains. Results are simulated for educational purposes.</div>' +
        '<div id="sf-results" style="margin-top:12px"></div>' +
        '<div id="sf-stats" style="margin-top:8px;font-size:.8rem;color:var(--mut)"></div>' +
      '</div>';

    main.querySelector('#sf-scan').onclick = function() {
      var domain = main.querySelector('#sf-domain').value.trim();
      if (!domain) return;
      var results = main.querySelector('#sf-results');
      results.innerHTML = '<p style="color:var(--acc)">Scanning ' + esc(domain) + ' with ' + WORDLIST.length + ' subdomains...</p>';
      setTimeout(function() {
        scanResults = simulateScan(domain, WORDLIST);
        results.innerHTML = renderResultsTable(scanResults);
        main.querySelector('#sf-stats').textContent = 'Found ' + scanResults.length + ' subdomains out of ' + WORDLIST.length + ' tested (' + ((scanResults.length / WORDLIST.length) * 100).toFixed(1) + '% hit rate)';
      }, 500);
    };

    main.querySelector('#sf-export-csv').onclick = function() {
      if (!scanResults.length) return;
      var csv = 'Subdomain,IP,Status,Title,Server,Ports\n';
      for (var i = 0; i < scanResults.length; i++) {
        var r = scanResults[i];
        csv += r.subdomain + ',' + r.ip + ',' + r.status + ',' + r.title + ',' + r.server + ',"' + r.ports.join(';') + '"\n';
      }
      var el = document.createElement('textarea');
      el.value = csv; document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
      main.querySelector('#sf-stats').textContent = 'CSV copied to clipboard (' + scanResults.length + ' rows)';
    };

    main.querySelector('#sf-export-json').onclick = function() {
      if (!scanResults.length) return;
      var el = document.createElement('textarea');
      el.value = JSON.stringify(scanResults, null, 2); document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
      main.querySelector('#sf-stats').textContent = 'JSON copied to clipboard (' + scanResults.length + ' entries)';
    };
  }

  function renderTakeover() {
    var html = '<div style="margin-top:12px">' +
      '<h2 class="pg-h2">Subdomain Takeover Fingerprints</h2>' +
      '<p class="muted" style="margin-bottom:12px">Dangling CNAME records pointing to decommissioned services can be claimed by attackers. Check your subdomains against these ' + TAKEOVER_FINGERPRINTS.length + ' service fingerprints.</p>' +
      '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">' +
        '<input type="text" class="tk-in" id="sf-takeover-cname" placeholder="CNAME value (e.g. myapp.herokuapp.com)" style="flex:1;min-width:200px">' +
        '<button class="btn sm" id="sf-check-takeover">Check</button>' +
      '</div>' +
      '<div id="sf-takeover-result" style="margin-bottom:12px"></div>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line);text-align:left">' +
      '<th style="padding:6px 8px">Service</th><th style="padding:6px 8px">CNAME Patterns</th><th style="padding:6px 8px">Fingerprint</th><th style="padding:6px 8px">Vulnerable</th></tr></thead><tbody>';
    for (var i = 0; i < TAKEOVER_FINGERPRINTS.length; i++) {
      var fp = TAKEOVER_FINGERPRINTS[i];
      var vulnColor = fp.vulnerable ? '#ef4444' : '#22c55e';
      html += '<tr style="border-bottom:1px solid var(--line)">' +
        '<td style="padding:6px 8px;font-weight:500">' + esc(fp.service) + '</td>' +
        '<td style="padding:6px 8px;font-family:var(--mono,monospace);font-size:.72rem">' + fp.cname.map(function(c) { return esc(c); }).join(', ') + '</td>' +
        '<td style="padding:6px 8px;font-size:.72rem;color:var(--mut)">' + esc(fp.fingerprint.slice(0, 50)) + '</td>' +
        '<td style="padding:6px 8px;color:' + vulnColor + ';font-weight:600">' + (fp.vulnerable ? 'YES' : 'NO') + '</td>' +
        '</tr>';
    }
    html += '</tbody></table></div></div>';
    content.innerHTML = html;

    main.querySelector('#sf-check-takeover').onclick = function() {
      var cname = main.querySelector('#sf-takeover-cname').value.trim().toLowerCase();
      if (!cname) return;
      var resultDiv = main.querySelector('#sf-takeover-result');
      var matched = TAKEOVER_FINGERPRINTS.filter(function(fp) {
        return fp.cname.some(function(c) { return cname.indexOf(c) !== -1; });
      });
      if (!matched.length) {
        resultDiv.innerHTML = '<div style="padding:10px;background:var(--card);border:1px solid var(--line);border-radius:6px;color:var(--mut)">No matching service fingerprint found for: ' + esc(cname) + '</div>';
      } else {
        var m = matched[0];
        var color = m.vulnerable ? '#ef4444' : '#22c55e';
        resultDiv.innerHTML = '<div style="padding:10px;background:var(--card);border:1px solid ' + color + ';border-radius:6px">' +
          '<strong style="color:' + color + '">' + (m.vulnerable ? 'POTENTIALLY VULNERABLE' : 'NOT VULNERABLE') + '</strong> - ' + esc(m.service) +
          '<div style="margin-top:4px;font-size:.8rem;color:var(--mut)">Fingerprint: ' + esc(m.fingerprint) + '</div></div>';
      }
    };
  }

  function renderPermute() {
    content.innerHTML =
      '<div style="margin-top:12px">' +
        '<h2 class="pg-h2">Domain Permutation Generator</h2>' +
        '<p class="muted" style="margin-bottom:12px">Generate typosquat, homoglyph, and look-alike domains for brand protection monitoring.</p>' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
          '<input type="text" class="tk-in" id="sf-perm-domain" placeholder="example.com" style="flex:1;min-width:200px">' +
          '<button class="btn sm" id="sf-perm-gen">Generate</button>' +
        '</div>' +
        '<div id="sf-perm-results" style="margin-top:12px"></div>' +
      '</div>';

    main.querySelector('#sf-perm-gen').onclick = function() {
      var domain = main.querySelector('#sf-perm-domain').value.trim();
      if (!domain) return;
      var perms = generatePermutations(domain);
      var types = {};
      for (var i = 0; i < perms.length; i++) {
        var t = perms[i].type;
        if (!types[t]) types[t] = [];
        types[t].push(perms[i]);
      }
      var html = '<div style="font-size:.8rem;color:var(--mut);margin-bottom:8px">' + perms.length + ' permutations generated</div>';
      var typeNames = Object.keys(types);
      for (var j = 0; j < typeNames.length; j++) {
        var tn = typeNames[j];
        var items = types[tn];
        html += '<details style="margin-bottom:8px"><summary style="cursor:pointer;font-weight:600;padding:6px 0">' + esc(tn) + ' (' + items.length + ')</summary>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:4px;padding:8px 0">';
        for (var k = 0; k < Math.min(items.length, 50); k++) {
          html += '<span style="background:var(--card);border:1px solid var(--line);padding:2px 8px;border-radius:4px;font-family:var(--mono,monospace);font-size:.75rem">' + esc(items[k].domain) + '</span>';
        }
        if (items.length > 50) html += '<span style="color:var(--mut);font-size:.75rem;padding:2px 8px">...and ' + (items.length - 50) + ' more</span>';
        html += '</div></details>';
      }
      main.querySelector('#sf-perm-results').innerHTML = html;
    };
  }

  function renderCT() {
    content.innerHTML =
      '<div style="margin-top:12px">' +
        '<h2 class="pg-h2">Certificate Transparency Logs</h2>' +
        '<p class="muted" style="margin-bottom:16px">Certificate Transparency (CT) is a system for monitoring and auditing SSL/TLS certificates. Every publicly trusted CA must submit certificates to CT logs, making them searchable.</p>' +
        '<div style="background:var(--card);border:1px solid var(--line);padding:16px;border-radius:6px;margin-bottom:16px">' +
          '<h3 style="margin-top:0;font-size:.95rem">How CT Works</h3>' +
          '<ol style="font-size:.85rem;line-height:1.8;padding-left:20px;color:var(--txt)">' +
            '<li>CA issues a certificate for a domain</li>' +
            '<li>CA submits the certificate to one or more CT logs</li>' +
            '<li>CT log returns a Signed Certificate Timestamp (SCT)</li>' +
            '<li>SCT is embedded in the certificate or delivered via TLS extension</li>' +
            '<li>Browsers verify SCTs to ensure certificate was logged</li>' +
            '<li>Domain owners and monitors can query logs to find all certificates for their domains</li>' +
          '</ol>' +
        '</div>' +
        '<div style="background:var(--card);border:1px solid var(--line);padding:16px;border-radius:6px;margin-bottom:16px">' +
          '<h3 style="margin-top:0;font-size:.95rem">Using CT for Subdomain Enumeration</h3>' +
          '<p style="font-size:.85rem;line-height:1.7">CT logs reveal all certificates issued for a domain, including wildcard and subdomain certs. This is one of the most effective passive recon techniques.</p>' +
          '<div style="margin-top:12px">' +
            '<h4 style="font-size:.85rem;margin-bottom:6px">Tools and Services</h4>' +
            '<table style="width:100%;border-collapse:collapse;font-size:.8rem">' +
              '<tr style="border-bottom:1px solid var(--line)"><td style="padding:6px 8px;font-weight:500">crt.sh</td><td style="padding:6px 8px">Comodo CT log search engine. Query: %.example.com</td></tr>' +
              '<tr style="border-bottom:1px solid var(--line)"><td style="padding:6px 8px;font-weight:500">certspotter</td><td style="padding:6px 8px">SSLMate CT monitoring. API at sslmate.com/certspotter</td></tr>' +
              '<tr style="border-bottom:1px solid var(--line)"><td style="padding:6px 8px;font-weight:500">Google CT</td><td style="padding:6px 8px">transparencyreport.google.com/https/certificates</td></tr>' +
              '<tr style="border-bottom:1px solid var(--line)"><td style="padding:6px 8px;font-weight:500">Censys</td><td style="padding:6px 8px">search.censys.io - search by certificate fields</td></tr>' +
              '<tr style="border-bottom:1px solid var(--line)"><td style="padding:6px 8px;font-weight:500">subfinder</td><td style="padding:6px 8px">CLI tool that queries CT logs among other sources</td></tr>' +
              '<tr><td style="padding:6px 8px;font-weight:500">amass</td><td style="padding:6px 8px">OWASP tool with CT log integration for subdomain enum</td></tr>' +
            '</table>' +
          '</div>' +
          '<div style="margin-top:12px">' +
            '<h4 style="font-size:.85rem;margin-bottom:6px">Example Queries</h4>' +
            '<pre class="tk-out" style="font-size:.78rem">' +
              '# crt.sh via curl\n' +
              'curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r ".[].name_value" | sort -u\n\n' +
              '# crt.sh SQL interface\n' +
              'curl -s "https://crt.sh/?q=%25.example.com&output=json" | \\\n' +
              '  jq -r ".[].name_value" | sed "s/\\*\\.//g" | sort -u\n\n' +
              '# subfinder\n' +
              'subfinder -d example.com -sources crtsh,certspotter -o subs.txt\n\n' +
              '# amass passive enum\n' +
              'amass enum -passive -d example.com -src' +
            '</pre>' +
          '</div>' +
        '</div>' +
        '<div style="background:var(--card);border:1px solid var(--line);padding:16px;border-radius:6px">' +
          '<h3 style="margin-top:0;font-size:.95rem">Monitoring Your Domains</h3>' +
          '<p style="font-size:.85rem;line-height:1.7">Set up CT monitoring to detect unauthorized certificate issuance for your domains:</p>' +
          '<ul style="font-size:.85rem;line-height:1.8;padding-left:20px">' +
            '<li>Use CAA DNS records to restrict which CAs can issue certs</li>' +
            '<li>Monitor CT logs with certspotter, Facebook CT monitor, or crt.sh alerts</li>' +
            '<li>Set up alerting for any unexpected certificate issuance</li>' +
            '<li>Review certificates periodically for unauthorized subdomains</li>' +
          '</ul>' +
        '</div>' +
      '</div>';
  }

  function renderWordlistTab() {
    var cats = {};
    var catLabels = ['Infrastructure', 'Services', 'Dev/CI', 'Mail', 'Security', 'Database', 'Cloud', 'Misc'];
    var catRanges = [
      { start: 0, end: 100, label: 'Infrastructure' },
      { start: 100, end: 200, label: 'Services' },
      { start: 200, end: 400, label: 'Dev/CI' },
      { start: 400, end: 500, label: 'Mail' },
      { start: 500, end: 600, label: 'Security' },
      { start: 600, end: 700, label: 'Database' },
      { start: 700, end: WORDLIST.length, label: 'Misc' },
    ];
    content.innerHTML =
      '<div style="margin-top:12px">' +
        '<h2 class="pg-h2">Built-in Wordlist</h2>' +
        '<p class="muted" style="margin-bottom:8px">' + WORDLIST.length + ' common subdomain names. Filter and copy for use with external tools.</p>' +
        '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">' +
          '<input type="text" class="tk-in" id="sf-wl-filter" placeholder="Filter wordlist..." style="flex:1;min-width:200px">' +
          '<button class="btn sm" id="sf-wl-copy">Copy All</button>' +
        '</div>' +
        '<div id="sf-wl-list" style="max-height:500px;overflow-y:auto;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;font-family:var(--mono,monospace);font-size:.72rem;line-height:1.6;columns:3;column-gap:16px"></div>' +
      '</div>';

    function updateList(filter) {
      var list = main.querySelector('#sf-wl-list');
      var filtered = filter ? WORDLIST.filter(function(w) { return w.indexOf(filter) !== -1; }) : WORDLIST;
      list.innerHTML = filtered.map(function(w) { return '<div>' + esc(w) + '</div>'; }).join('');
    }
    updateList('');

    main.querySelector('#sf-wl-filter').oninput = function(e) { updateList(e.target.value.trim().toLowerCase()); };
    main.querySelector('#sf-wl-copy').onclick = function() {
      var filter = main.querySelector('#sf-wl-filter').value.trim().toLowerCase();
      var filtered = filter ? WORDLIST.filter(function(w) { return w.indexOf(filter) !== -1; }) : WORDLIST;
      var el = document.createElement('textarea');
      el.value = filtered.join('\n'); document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
    };
  }

  tabs.onclick = function(e) {
    var btn = e.target.closest('.tab');
    if (btn) switchTab(btn.dataset.tab);
  };

  renderEnum();
}
