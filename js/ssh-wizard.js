// SSH setup wizard (client-side only). Scaffold stub.
// Guides the user to install OpenSSH on THEIR OWN device, then builds the exact
// ssh command from the fields they fill in. Nothing is executed or stored server-side.

// Example generator the wizard will use (starter):
export function buildSshCommand({ host, port = 22, user, keyPath }) {
  if (!host || !user) return "";
  const parts = ["ssh"];
  if (keyPath) parts.push("-i", keyPath);
  if (String(port) !== "22") parts.push("-p", String(port));
  parts.push(`${user}@${host}`);
  return parts.join(" ");
}

// The build will render: OS-specific "install OpenSSH" steps (Windows optional feature,
// apt install openssh-client, macOS built-in), labelled fields (host/port/user/key) each
// with inline help, and a copy button for the generated command above.
console.log("[sentinel] ssh-wizard module loaded");
