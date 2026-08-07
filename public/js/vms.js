// Downloadable intentionally-vulnerable virtual machines to practice on locally.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const HYPERVISORS = [
  ["VirtualBox", "Free, cross-platform hypervisor", "download", "https://www.virtualbox.org/wiki/Downloads"],
  ["VMware Workstation Player", "Free for personal use", "download", "https://www.vmware.com/products/workstation-player.html"],
  ["Vagrant", "Needed for Metasploitable 3", "download", "https://developer.hashicorp.com/vagrant/downloads"],
];
const VMS = [
  ["Metasploitable 2", "The classic vulnerable Linux box — dozens of exploitable services", "msfadmin / msfadmin", "https://sourceforge.net/projects/metasploitable/files/Metasploitable2/"],
  ["Metasploitable 3", "Windows & Linux vulnerable VMs, built with Vagrant", "vagrant / vagrant", "https://github.com/rapid7/metasploitable3"],
  ["OWASP Broken Web Apps", "A dozen deliberately vulnerable web apps in one VM", "root / owaspbwa", "https://sourceforge.net/projects/owaspbwa/files/"],
  ["bWAPP bee-box", "VM edition of the buggy web app (100+ bugs)", "bee / bug", "https://sourceforge.net/projects/bwapp/files/bee-box/"],
  ["Kioptrix (1–5)", "The beginner boot2root series everyone starts with", "boot2root", "https://www.vulnhub.com/series/kioptrix,8/"],
  ["Mr-Robot", "TV-themed boot2root CTF box", "boot2root", "https://www.vulnhub.com/entry/mr-robot-1,151/"],
  ["Basic Pentesting 1", "A gentle first boot2root", "boot2root", "https://www.vulnhub.com/entry/basic-pentesting-1,216/"],
  ["VulnOS v2", "Web-to-root practice VM", "boot2root", "https://www.vulnhub.com/entry/vulnos-2,147/"],
  ["DC-1", "Popular Drupal-based boot2root", "boot2root", "https://www.vulnhub.com/entry/dc-1,292/"],
  ["DVWA (source)", "Damn Vulnerable Web App — run as Docker or LAMP", "admin / password", "https://github.com/digininja/DVWA"],
  ["VulnHub (browse all)", "Hundreds more downloadable vulnerable VMs", "varies", "https://www.vulnhub.com/"],
];

const card = ([n, d, meta, u]) => `<a class="arse-card" href="${esc(u)}" target="_blank" rel="noopener"><div class="an">${esc(n)} <span class="ax">&#8599;</span></div><div class="ad">${esc(d)}</div><div class="au">${esc(meta)}</div></a>`;

export function renderVMs(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Vulnerable VMs</h1>
    <p class="muted pg-sub">Download popular intentionally-vulnerable machines and run them locally. Keep them on a host-only / isolated network &mdash; never expose them to the internet. For authorized practice only.</p>
    <h2 class="pg-h2" style="margin:16px 0 10px">1 &middot; Get a hypervisor</h2>
    <div class="arse-grid">${HYPERVISORS.map(card).join("")}</div>
    <h2 class="pg-h2" style="margin:22px 0 10px">2 &middot; Grab a machine</h2>
    <div class="arse-grid">${VMS.map(card).join("")}</div>
    <p class="muted" style="font-size:.8rem;margin-top:16px">Import the downloaded <code>.ova</code>/<code>.vmdk</code> into VirtualBox (File &rarr; Import Appliance) or VMware, set the network adapter to Host-only, and boot.</p>`;
}
