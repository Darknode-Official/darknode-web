// Mobile Security Lab — Android/iOS security testing reference tool
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const DANGEROUS_PERMISSIONS = [
  {perm: 'android.permission.READ_CONTACTS', risk: 'high', desc: 'Read user contacts — data exfiltration risk'},
  {perm: 'android.permission.WRITE_CONTACTS', risk: 'high', desc: 'Modify contacts — integrity risk'},
  {perm: 'android.permission.READ_CALL_LOG', risk: 'high', desc: 'Read call history — privacy violation'},
  {perm: 'android.permission.READ_SMS', risk: 'critical', desc: 'Read SMS messages — can intercept 2FA codes'},
  {perm: 'android.permission.SEND_SMS', risk: 'critical', desc: 'Send SMS — premium rate fraud, C2 channel'},
  {perm: 'android.permission.RECEIVE_SMS', risk: 'critical', desc: 'Intercept incoming SMS — 2FA bypass'},
  {perm: 'android.permission.CAMERA', risk: 'high', desc: 'Access camera — surveillance capability'},
  {perm: 'android.permission.RECORD_AUDIO', risk: 'high', desc: 'Record audio — eavesdropping capability'},
  {perm: 'android.permission.ACCESS_FINE_LOCATION', risk: 'high', desc: 'GPS location — tracking capability'},
  {perm: 'android.permission.ACCESS_COARSE_LOCATION', risk: 'medium', desc: 'Approximate location — tracking'},
  {perm: 'android.permission.READ_EXTERNAL_STORAGE', risk: 'medium', desc: 'Read files — data access'},
  {perm: 'android.permission.WRITE_EXTERNAL_STORAGE', risk: 'medium', desc: 'Write files — can drop payloads'},
  {perm: 'android.permission.INTERNET', risk: 'low', desc: 'Network access — required for most apps, enables C2'},
  {perm: 'android.permission.ACCESS_NETWORK_STATE', risk: 'low', desc: 'Check network status'},
  {perm: 'android.permission.RECEIVE_BOOT_COMPLETED', risk: 'medium', desc: 'Auto-start on boot — persistence mechanism'},
  {perm: 'android.permission.SYSTEM_ALERT_WINDOW', risk: 'high', desc: 'Draw over other apps — overlay attacks, credential theft'},
  {perm: 'android.permission.INSTALL_PACKAGES', risk: 'critical', desc: 'Install apps silently — dropper capability'},
  {perm: 'android.permission.REQUEST_INSTALL_PACKAGES', risk: 'high', desc: 'Prompt to install APKs — social engineering'},
  {perm: 'android.permission.READ_PHONE_STATE', risk: 'medium', desc: 'Read IMEI, phone number — device fingerprinting'},
  {perm: 'android.permission.BIND_ACCESSIBILITY_SERVICE', risk: 'critical', desc: 'Accessibility service — can read/interact with all UI elements'},
  {perm: 'android.permission.BIND_DEVICE_ADMIN', risk: 'critical', desc: 'Device admin — can lock device, wipe data'},
  {perm: 'android.permission.USE_BIOMETRIC', risk: 'medium', desc: 'Access biometric hardware'},
  {perm: 'android.permission.MANAGE_EXTERNAL_STORAGE', risk: 'high', desc: 'Full file system access (Android 11+)'},
  {perm: 'android.permission.QUERY_ALL_PACKAGES', risk: 'medium', desc: 'List all installed apps — reconnaissance'},
  {perm: 'android.permission.FOREGROUND_SERVICE', risk: 'low', desc: 'Run foreground service — persistence'},
  {perm: 'android.permission.WAKE_LOCK', risk: 'low', desc: 'Prevent device sleep — keep malware running'},
  {perm: 'android.permission.CHANGE_WIFI_STATE', risk: 'medium', desc: 'Modify WiFi settings — evil twin setup'},
  {perm: 'android.permission.BLUETOOTH', risk: 'medium', desc: 'Bluetooth access — proximity attacks'},
  {perm: 'android.permission.NFC', risk: 'medium', desc: 'NFC access — relay attacks'},
  {perm: 'android.permission.READ_CALENDAR', risk: 'medium', desc: 'Read calendar events — information gathering'},
];

const OWASP_MOBILE_TOP10 = [
  {id: 'M1', name: 'Improper Credential Usage', desc: 'Hardcoded credentials, insecure credential storage, weak authentication', checks: ['Check for hardcoded API keys in source/APK', 'Verify credentials stored in Android Keystore/iOS Keychain', 'Check for credentials in SharedPreferences/NSUserDefaults', 'Test for credential exposure in logs/backups']},
  {id: 'M2', name: 'Inadequate Supply Chain Security', desc: 'Third-party libraries with known vulnerabilities, compromised SDKs', checks: ['Audit all third-party dependencies', 'Check libraries against CVE databases', 'Verify SDK integrity and source', 'Monitor for supply chain attacks on dependencies']},
  {id: 'M3', name: 'Insecure Authentication/Authorization', desc: 'Weak authentication, missing session management, broken access controls', checks: ['Test for authentication bypass', 'Verify session token management', 'Check for proper logout/session invalidation', 'Test role-based access controls']},
  {id: 'M4', name: 'Insufficient Input/Output Validation', desc: 'SQL injection, XSS, command injection in mobile context', checks: ['Test all input fields for injection', 'Verify server-side validation', 'Check WebView JavaScript injection', 'Test deep link/intent handling for injection']},
  {id: 'M5', name: 'Insecure Communication', desc: 'Missing TLS, improper certificate validation, cleartext traffic', checks: ['Verify all traffic uses TLS 1.2+', 'Test for certificate pinning', 'Check for cleartext traffic (HTTP)', 'Test certificate validation bypass']},
  {id: 'M6', name: 'Inadequate Privacy Controls', desc: 'PII exposure, excessive data collection, missing consent', checks: ['Review data collection practices', 'Check for PII in logs/analytics', 'Verify data minimization', 'Test data deletion functionality']},
  {id: 'M7', name: 'Insufficient Binary Protections', desc: 'Missing obfuscation, anti-tampering, root/jailbreak detection', checks: ['Check for code obfuscation (ProGuard/R8)', 'Test root/jailbreak detection bypass', 'Verify anti-debugging protections', 'Check for integrity verification']},
  {id: 'M8', name: 'Security Misconfiguration', desc: 'Debug mode, export of components, backup enabled', checks: ['Check android:debuggable flag', 'Review exported components (activities, services, receivers)', 'Check android:allowBackup', 'Verify android:usesCleartextTraffic']},
  {id: 'M9', name: 'Insecure Data Storage', desc: 'Sensitive data in plaintext, shared preferences, SQLite, logs', checks: ['Check SharedPreferences for sensitive data', 'Examine SQLite databases', 'Review application logs', 'Check for sensitive data in app backups']},
  {id: 'M10', name: 'Insufficient Cryptography', desc: 'Weak algorithms, hardcoded keys, improper implementation', checks: ['Check for weak algorithms (MD5, SHA1, DES, RC4)', 'Verify key storage mechanism', 'Test for hardcoded encryption keys', 'Review crypto implementation for known weaknesses']},
];

const ADB_COMMANDS = {
  'Device Info': [
    {cmd: 'adb devices', desc: 'List connected devices'},
    {cmd: 'adb shell getprop ro.build.version.release', desc: 'Get Android version'},
    {cmd: 'adb shell getprop ro.product.model', desc: 'Get device model'},
    {cmd: 'adb shell getprop ro.build.fingerprint', desc: 'Get build fingerprint'},
    {cmd: 'adb shell id', desc: 'Check current user/permissions'},
    {cmd: 'adb shell cat /proc/version', desc: 'Get kernel version'},
    {cmd: 'adb shell settings list secure', desc: 'List secure settings'},
    {cmd: 'adb shell dumpsys battery', desc: 'Battery info'},
  ],
  'Package Management': [
    {cmd: 'adb shell pm list packages', desc: 'List all packages'},
    {cmd: 'adb shell pm list packages -3', desc: 'List third-party packages'},
    {cmd: 'adb shell pm list packages -f', desc: 'List packages with APK paths'},
    {cmd: 'adb shell dumpsys package <pkg>', desc: 'Get package details'},
    {cmd: 'adb shell pm path <pkg>', desc: 'Get APK path'},
    {cmd: 'adb pull <apk_path> .', desc: 'Extract APK to local machine'},
    {cmd: 'adb install <apk>', desc: 'Install APK'},
    {cmd: 'adb uninstall <pkg>', desc: 'Uninstall package'},
  ],
  'Data Extraction': [
    {cmd: 'adb shell content query --uri content://sms', desc: 'Read SMS messages'},
    {cmd: 'adb shell content query --uri content://call_log/calls', desc: 'Read call log'},
    {cmd: 'adb shell content query --uri content://contacts/phones', desc: 'Read contacts'},
    {cmd: 'adb shell ls /data/data/<pkg>/shared_prefs/', desc: 'List SharedPreferences files'},
    {cmd: 'adb shell cat /data/data/<pkg>/shared_prefs/<file>.xml', desc: 'Read SharedPreferences'},
    {cmd: 'adb shell ls /data/data/<pkg>/databases/', desc: 'List SQLite databases'},
    {cmd: 'adb pull /data/data/<pkg>/databases/<db>', desc: 'Extract database'},
    {cmd: 'adb backup -apk -shared <pkg>', desc: 'Create app backup (check allowBackup)'},
  ],
  'Network Analysis': [
    {cmd: 'adb shell netstat -tlnp', desc: 'Show open ports'},
    {cmd: 'adb shell ip addr show', desc: 'Show network interfaces'},
    {cmd: 'adb shell dumpsys connectivity', desc: 'Network connectivity info'},
    {cmd: 'adb shell settings get global http_proxy', desc: 'Check proxy setting'},
    {cmd: 'adb shell settings put global http_proxy <ip>:<port>', desc: 'Set HTTP proxy (for Burp)'},
    {cmd: 'adb shell settings delete global http_proxy', desc: 'Remove proxy'},
    {cmd: 'adb reverse tcp:8080 tcp:8080', desc: 'Reverse port forward (device to host)'},
    {cmd: 'adb forward tcp:8080 tcp:8080', desc: 'Forward port (host to device)'},
  ],
  'Security Testing': [
    {cmd: 'adb shell su', desc: 'Get root shell (rooted devices)'},
    {cmd: 'adb shell am start -a android.intent.action.VIEW -d "http://evil.com"', desc: 'Test deep link handling'},
    {cmd: 'adb shell am start -n <pkg>/<activity>', desc: 'Start exported activity directly'},
    {cmd: 'adb shell am broadcast -a <action>', desc: 'Send broadcast to exported receiver'},
    {cmd: 'adb shell content query --uri content://<provider>', desc: 'Query exported content provider'},
    {cmd: 'adb logcat | grep -i password', desc: 'Search logs for sensitive data'},
    {cmd: 'adb logcat -d | grep -i "api\\|key\\|token\\|secret"', desc: 'Search logs for keys/tokens'},
    {cmd: 'adb shell screencap -p /sdcard/screen.png && adb pull /sdcard/screen.png', desc: 'Take screenshot'},
  ],
  'Frida': [
    {cmd: 'adb push frida-server /data/local/tmp/', desc: 'Push Frida server to device'},
    {cmd: 'adb shell chmod 755 /data/local/tmp/frida-server', desc: 'Make Frida server executable'},
    {cmd: 'adb shell /data/local/tmp/frida-server &', desc: 'Start Frida server'},
    {cmd: 'frida-ps -U', desc: 'List processes on USB device'},
    {cmd: 'frida -U -f <pkg> -l script.js --no-pause', desc: 'Spawn app with Frida script'},
    {cmd: 'frida -U <pkg> -l script.js', desc: 'Attach to running app'},
    {cmd: 'objection -g <pkg> explore', desc: 'Start Objection (Frida wrapper)'},
  ],
};

const FRIDA_SCRIPTS = [
  {name: 'Bypass SSL Pinning', desc: 'Disable certificate pinning for traffic interception', code: "Java.perform(function() {\n  var TrustManager = Java.registerClass({\n    name: 'com.custom.TrustManager',\n    implements: [javax.net.ssl.X509TrustManager],\n    methods: {\n      checkClientTrusted: function(chain, authType) {},\n      checkServerTrusted: function(chain, authType) {},\n      getAcceptedIssuers: function() { return []; }\n    }\n  });\n  var SSLContext = javax.net.ssl.SSLContext.getInstance('TLS');\n  SSLContext.init(null, [TrustManager.$new()], null);\n  javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(SSLContext.getSocketFactory());\n});"},
  {name: 'Bypass Root Detection', desc: 'Hook common root detection methods to return false', code: "Java.perform(function() {\n  // Hook Runtime.exec to hide su\n  var Runtime = Java.use('java.lang.Runtime');\n  Runtime.exec.overload('java.lang.String').implementation = function(cmd) {\n    if (cmd.indexOf('su') !== -1) { throw new Error('not found'); }\n    return this.exec(cmd);\n  };\n  // Hook File.exists to hide root files\n  var File = Java.use('java.io.File');\n  File.exists.implementation = function() {\n    var name = this.getAbsolutePath();\n    if (name.indexOf('su') !== -1 || name.indexOf('Superuser') !== -1 || name.indexOf('magisk') !== -1) return false;\n    return this.exists();\n  };\n});"},
  {name: 'Hook Crypto Operations', desc: 'Log all encryption/decryption operations', code: "Java.perform(function() {\n  var Cipher = Java.use('javax.crypto.Cipher');\n  Cipher.doFinal.overload('[B').implementation = function(input) {\n    console.log('[Cipher] Mode: ' + this.getAlgorithm() + ' Input: ' + bytesToHex(input));\n    var result = this.doFinal(input);\n    console.log('[Cipher] Output: ' + bytesToHex(result));\n    return result;\n  };\n});"},
  {name: 'Dump SharedPreferences', desc: 'Read all SharedPreferences data', code: "Java.perform(function() {\n  var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();\n  var prefs_dir = context.getFilesDir().getParent() + '/shared_prefs/';\n  var File = Java.use('java.io.File');\n  var dir = File.$new(prefs_dir);\n  var files = dir.listFiles();\n  for (var i = 0; i < files.length; i++) {\n    console.log('=== ' + files[i].getName() + ' ===');\n    // Read each file...\n  }\n});"},
  {name: 'Hook WebView', desc: 'Monitor WebView URL loading and JavaScript execution', code: "Java.perform(function() {\n  var WebView = Java.use('android.webkit.WebView');\n  WebView.loadUrl.overload('java.lang.String').implementation = function(url) {\n    console.log('[WebView] loadUrl: ' + url);\n    this.loadUrl(url);\n  };\n  WebView.evaluateJavascript.implementation = function(script, callback) {\n    console.log('[WebView] evaluateJS: ' + script.substring(0,200));\n    this.evaluateJavascript(script, callback);\n  };\n});"},
  {name: 'Intercept HTTP Requests', desc: 'Log all HTTP/HTTPS requests from the app', code: "Java.perform(function() {\n  var URL = Java.use('java.net.URL');\n  URL.openConnection.overload().implementation = function() {\n    console.log('[HTTP] ' + this.toString());\n    return this.openConnection();\n  };\n  // OkHttp\n  try {\n    var OkHttpClient = Java.use('okhttp3.OkHttpClient');\n    OkHttpClient.newCall.implementation = function(request) {\n      console.log('[OkHttp] ' + request.method() + ' ' + request.url().toString());\n      return this.newCall(request);\n    };\n  } catch(e) {}\n});"},
];

const MOBILE_MALWARE_INDICATORS = [
  {indicator: 'Requests SEND_SMS + RECEIVE_SMS + READ_SMS', risk: 'critical', type: 'Banking trojan / SMS stealer'},
  {indicator: 'Requests BIND_ACCESSIBILITY_SERVICE', risk: 'critical', type: 'Overlay attack / Credential stealer'},
  {indicator: 'Requests BIND_DEVICE_ADMIN', risk: 'critical', type: 'Ransomware / MDM abuse'},
  {indicator: 'Requests SYSTEM_ALERT_WINDOW + ACCESSIBILITY', risk: 'critical', type: 'Overlay attack trojan'},
  {indicator: 'Requests CAMERA + RECORD_AUDIO + LOCATION', risk: 'high', type: 'Spyware / Stalkerware'},
  {indicator: 'Requests INSTALL_PACKAGES', risk: 'critical', type: 'Dropper / Loader'},
  {indicator: 'Uses DexClassLoader / reflection', risk: 'high', type: 'Dynamic code loading (evasion)'},
  {indicator: 'Connects to raw IP addresses', risk: 'high', type: 'C2 communication'},
  {indicator: 'Uses native code (JNI/NDK)', risk: 'medium', type: 'Packed/obfuscated malware'},
  {indicator: 'Requests WAKE_LOCK + RECEIVE_BOOT_COMPLETED', risk: 'medium', type: 'Persistence mechanism'},
  {indicator: 'Contains encoded/encrypted strings', risk: 'medium', type: 'Anti-analysis / Obfuscation'},
  {indicator: 'Checks for emulator/VM environment', risk: 'medium', type: 'Anti-analysis'},
  {indicator: 'Requests READ_PHONE_STATE + READ_CONTACTS', risk: 'medium', type: 'Information stealer'},
  {indicator: 'Uses WebView with JavaScript enabled + addJavascriptInterface', risk: 'high', type: 'WebView exploitation'},
];

const TABS = [
  {id: 'perms', label: 'Permission Analyzer'},
  {id: 'owasp', label: 'OWASP Mobile Top 10'},
  {id: 'adb', label: 'ADB Commands'},
  {id: 'frida', label: 'Frida Scripts'},
  {id: 'malware', label: 'Malware Indicators'},
  {id: 'methodology', label: 'Pentest Methodology'},
  {id: 'ios', label: 'iOS Reference'},
];

export function renderMobileSecurityLab(main) {
  var activeTab = 'perms';

  function render() {
    var tabsHtml = TABS.map(function(t) {
      return '<button class="tab' + (activeTab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>';
    }).join('');

    main.innerHTML =
      '<h1 class="pg-h1">Mobile Security Lab</h1>' +
      '<p class="muted pg-sub">Android and iOS security testing reference — permission analysis, ADB commands, Frida scripts, and pentest methodology.</p>' +
      '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' + tabsHtml + '</div>' +
      '<div id="msl-content" style="margin-top:12px"></div>';

    main.querySelector('.tab-bar').onclick = function(e) {
      var b = e.target.closest('.tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      render();
    };

    var content = main.querySelector('#msl-content');
    if (activeTab === 'perms') renderPermsTab(content);
    else if (activeTab === 'owasp') renderOwaspTab(content);
    else if (activeTab === 'adb') renderAdbTab(content);
    else if (activeTab === 'frida') renderFridaTab(content);
    else if (activeTab === 'malware') renderMalwareTab(content);
    else if (activeTab === 'methodology') renderMethodologyTab(content);
    else if (activeTab === 'ios') renderIOSTab(content);
  }

  function renderPermsTab(el) {
    el.innerHTML =
      '<h2 class="pg-h2">Android Permission Analyzer</h2>' +
      '<p class="muted" style="margin-bottom:12px">Paste an AndroidManifest.xml below to analyze permissions, or browse the dangerous permissions reference.</p>' +
      '<textarea class="tk-in" id="msl-manifest" rows="8" placeholder="Paste AndroidManifest.xml content here..."></textarea>' +
      '<div class="tk-btns"><button class="btn sm" id="msl-analyze">Analyze Permissions</button></div>' +
      '<div id="msl-perm-results" style="margin-top:12px"></div>' +
      '<h3 class="pg-h2" style="margin-top:20px">Dangerous Permissions Reference</h3>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Permission</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Risk</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Description</th>' +
      '</tr></thead><tbody>' +
      DANGEROUS_PERMISSIONS.map(function(p) {
        var color = p.risk === 'critical' ? '#ff1744' : p.risk === 'high' ? '#ff9100' : p.risk === 'medium' ? '#ffd600' : 'var(--mut)';
        return '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:8px;font-family:var(--mono,monospace);font-size:.72rem">' + esc(p.perm.replace('android.permission.', '')) + '</td>' +
          '<td style="padding:8px;color:' + color + ';font-weight:600;text-transform:uppercase;font-size:.7rem">' + esc(p.risk) + '</td>' +
          '<td style="padding:8px;color:var(--mut)">' + esc(p.desc) + '</td></tr>';
      }).join('') +
      '</tbody></table></div>';

    el.querySelector('#msl-analyze').onclick = function() {
      var manifest = el.querySelector('#msl-manifest').value;
      var results = el.querySelector('#msl-perm-results');
      if (!manifest.trim()) { results.innerHTML = '<p class="muted">Paste a manifest first.</p>'; return; }
      var found = [];
      DANGEROUS_PERMISSIONS.forEach(function(p) {
        if (manifest.indexOf(p.perm) !== -1 || manifest.indexOf(p.perm.replace('android.permission.', '')) !== -1) {
          found.push(p);
        }
      });
      var critCount = found.filter(function(p){return p.risk==='critical'}).length;
      var highCount = found.filter(function(p){return p.risk==='high'}).length;
      results.innerHTML =
        '<div style="padding:12px;background:var(--card);border:1px solid var(--line);border-radius:6px">' +
        '<div style="font-weight:600;margin-bottom:8px">Found ' + found.length + ' sensitive permissions</div>' +
        '<div style="display:flex;gap:12px;margin-bottom:12px">' +
        '<span style="color:#ff1744;font-weight:600">' + critCount + ' Critical</span>' +
        '<span style="color:#ff9100;font-weight:600">' + highCount + ' High</span>' +
        '<span style="color:#ffd600">' + (found.length - critCount - highCount) + ' Medium/Low</span></div>' +
        found.map(function(p) {
          var color = p.risk === 'critical' ? '#ff1744' : p.risk === 'high' ? '#ff9100' : '#ffd600';
          return '<div style="border-left:3px solid ' + color + ';padding:6px 12px;margin:4px 0;font-size:.78rem">' +
            '<span style="color:' + color + ';font-weight:600">[' + p.risk.toUpperCase() + ']</span> ' +
            '<span style="font-family:var(--mono,monospace)">' + esc(p.perm.replace('android.permission.', '')) + '</span>' +
            '<div style="color:var(--mut);font-size:.72rem;margin-top:2px">' + esc(p.desc) + '</div></div>';
        }).join('') +
        '</div>';
    };
  }

  function renderOwaspTab(el) {
    el.innerHTML =
      '<h2 class="pg-h2">OWASP Mobile Top 10 (2024)</h2>' +
      '<p class="muted" style="margin-bottom:12px">Interactive checklist for mobile application security testing.</p>' +
      OWASP_MOBILE_TOP10.map(function(item) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:10px">' +
          '<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">' +
          '<span style="color:var(--acc);font-weight:700;font-size:.9rem">' + esc(item.id) + '</span>' +
          '<span style="font-weight:600">' + esc(item.name) + '</span></div>' +
          '<p style="color:var(--mut);font-size:.78rem;margin:0 0 8px">' + esc(item.desc) + '</p>' +
          '<div style="font-size:.75rem">' +
          item.checks.map(function(c) {
            return '<label style="display:flex;gap:6px;align-items:flex-start;margin:3px 0;cursor:pointer;color:var(--txt)">' +
              '<input type="checkbox" style="margin-top:2px"> ' + esc(c) + '</label>';
          }).join('') +
          '</div></div>';
      }).join('');
  }

  function renderAdbTab(el) {
    var cats = Object.keys(ADB_COMMANDS);
    el.innerHTML =
      '<h2 class="pg-h2">ADB Command Reference</h2>' +
      '<p class="muted" style="margin-bottom:12px">' + cats.reduce(function(a,c){return a + ADB_COMMANDS[c].length}, 0) + ' commands organized by category. Click any command to copy.</p>' +
      cats.map(function(cat) {
        return '<h3 style="margin:16px 0 8px;font-size:.85rem;color:var(--acc)">' + esc(cat) + '</h3>' +
          '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
          ADB_COMMANDS[cat].map(function(c) {
            return '<tr style="border-bottom:1px solid var(--line)">' +
              '<td style="padding:6px 8px;font-family:var(--mono,monospace);font-size:.72rem;cursor:pointer;color:var(--acc)" onclick="navigator.clipboard.writeText(this.textContent).then(()=>{this.style.color=\'#00e676\';setTimeout(()=>this.style.color=\'\',500)})">' + esc(c.cmd) + '</td>' +
              '<td style="padding:6px 8px;color:var(--mut)">' + esc(c.desc) + '</td></tr>';
          }).join('') +
          '</table></div>';
      }).join('');
  }

  function renderFridaTab(el) {
    el.innerHTML =
      '<h2 class="pg-h2">Frida Script Library</h2>' +
      '<p class="muted" style="margin-bottom:12px">' + FRIDA_SCRIPTS.length + ' ready-to-use Frida scripts for mobile security testing. Click "Copy" to copy the script.</p>' +
      FRIDA_SCRIPTS.map(function(s) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:10px">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
          '<span style="font-weight:600">' + esc(s.name) + '</span>' +
          '<span style="flex:1"></span>' +
          '<button class="btn sm" onclick="navigator.clipboard.writeText(this.parentElement.parentElement.querySelector(\'pre\').textContent).then(()=>{this.textContent=\'Copied!\';setTimeout(()=>this.textContent=\'Copy\',1000)})">Copy</button>' +
          '</div>' +
          '<p style="color:var(--mut);font-size:.78rem;margin:0 0 8px">' + esc(s.desc) + '</p>' +
          '<pre style="background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:12px;font-size:.72rem;overflow-x:auto;white-space:pre;color:var(--acc)">' + esc(s.code) + '</pre>' +
          '</div>';
      }).join('');
  }

  function renderMalwareTab(el) {
    el.innerHTML =
      '<h2 class="pg-h2">Mobile Malware Indicators</h2>' +
      '<p class="muted" style="margin-bottom:12px">Common indicators of malicious mobile applications.</p>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Indicator</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Risk</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Malware Type</th>' +
      '</tr></thead><tbody>' +
      MOBILE_MALWARE_INDICATORS.map(function(m) {
        var color = m.risk === 'critical' ? '#ff1744' : m.risk === 'high' ? '#ff9100' : '#ffd600';
        return '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:8px">' + esc(m.indicator) + '</td>' +
          '<td style="padding:8px;color:' + color + ';font-weight:600;text-transform:uppercase;font-size:.7rem">' + esc(m.risk) + '</td>' +
          '<td style="padding:8px;color:var(--mut)">' + esc(m.type) + '</td></tr>';
      }).join('') +
      '</tbody></table></div>';
  }

  function renderMethodologyTab(el) {
    var phases = [
      {name: 'Reconnaissance', steps: ['Identify app package name and version', 'Download APK (adb pull or APKPure)', 'Check app store reviews for security concerns', 'Identify backend API endpoints', 'Check for related web apps or admin panels']},
      {name: 'Static Analysis', steps: ['Decompile APK (jadx, apktool)', 'Review AndroidManifest.xml permissions and components', 'Search for hardcoded secrets (API keys, credentials, URLs)', 'Analyze crypto implementations', 'Check for obfuscation (ProGuard/R8)', 'Review native libraries (if any)', 'Check third-party SDK versions for known CVEs']},
      {name: 'Dynamic Analysis', steps: ['Set up proxy (Burp Suite) and install CA certificate', 'Bypass SSL pinning (Frida or Objection)', 'Intercept and analyze API traffic', 'Test authentication and session management', 'Check for sensitive data in device logs', 'Examine app data storage (SharedPreferences, SQLite, files)', 'Test deep links and intent handling']},
      {name: 'API Testing', steps: ['Map all API endpoints from traffic intercept', 'Test for broken authentication and authorization', 'Test for IDOR on user-specific endpoints', 'Check rate limiting', 'Test input validation (SQLi, XSS, command injection)', 'Verify proper error handling (no stack traces)', 'Check for sensitive data in responses']},
      {name: 'Reporting', steps: ['Document all findings with severity', 'Include reproduction steps with screenshots', 'Provide remediation guidance per finding', 'Map findings to OWASP Mobile Top 10', 'Calculate CVSS scores for each finding']},
    ];
    el.innerHTML =
      '<h2 class="pg-h2">Mobile Pentest Methodology</h2>' +
      phases.map(function(phase, i) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:10px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:8px">Phase ' + (i+1) + ': ' + esc(phase.name) + '</div>' +
          '<ol style="margin:0;padding-left:20px;font-size:.78rem;color:var(--txt);line-height:1.8">' +
          phase.steps.map(function(s){return '<li>' + esc(s) + '</li>'}).join('') +
          '</ol></div>';
      }).join('');
  }

  function renderIOSTab(el) {
    var iosChecks = [
      {cat: 'Data Storage', items: ['Check Keychain for sensitive data (keychain-dumper)', 'Examine NSUserDefaults plist files', 'Check Core Data SQLite databases', 'Review app cache and cookie storage', 'Check for data in device backups']},
      {cat: 'Network Security', items: ['Verify ATS (App Transport Security) configuration', 'Test certificate pinning (ssl-kill-switch2)', 'Check for cleartext HTTP exceptions', 'Analyze API traffic via Burp proxy', 'Check for WebSocket security']},
      {cat: 'Authentication', items: ['Test biometric authentication bypass', 'Check Keychain access controls', 'Test session token management', 'Verify logout invalidates sessions', 'Check for credential caching']},
      {cat: 'Binary Analysis', items: ['Check PIE (Position Independent Executable)', 'Verify stack canaries enabled', 'Check ARC (Automatic Reference Counting)', 'Test for anti-debugging (ptrace)', 'Check for jailbreak detection', 'Dump class information (class-dump, dsdump)']},
      {cat: 'Tools', items: ['Objection: runtime exploration', 'Frida: dynamic instrumentation', 'ipatool: download IPA from App Store', 'otool: binary analysis', 'ldid: code signing', 'Hopper/IDA: disassembly', 'Burp Suite: traffic interception', 'ssl-kill-switch2: bypass SSL pinning']},
    ];
    el.innerHTML =
      '<h2 class="pg-h2">iOS Security Reference</h2>' +
      '<p class="muted" style="margin-bottom:12px">Key areas for iOS application security testing.</p>' +
      iosChecks.map(function(cat) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:10px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:8px">' + esc(cat.cat) + '</div>' +
          '<ul style="margin:0;padding-left:18px;font-size:.78rem;color:var(--txt);line-height:1.8">' +
          cat.items.map(function(it){return '<li>' + esc(it) + '</li>'}).join('') +
          '</ul></div>';
      }).join('');
  }

  render();
}
