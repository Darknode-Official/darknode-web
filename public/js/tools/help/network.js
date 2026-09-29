// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the network.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "n-subnet-calc": {
    what: "Type a network in CIDR form (an address plus a slash and a size, like 192.168.1.0/24) and get its full breakdown: netmask, network and broadcast addresses, first and last usable address, and how many devices fit.",
    when: "You are planning or checking a network and need to know exactly which addresses belong to a block. IPv4 only.",
    example: { cidr: "192.168.10.0/26" },
  },
  "n-cidr-to-mask": {
    what: "Turns a prefix length (the number after the slash, such as 24) into the matching dotted netmask, such as 255.255.255.0.",
    when: "You are filling in a router or OS setting that asks for a netmask but you only know the /number.",
    example: { bits: "27" },
  },
  "n-mask-to-cidr": {
    what: "Turns a dotted netmask such as 255.255.255.0 into its short slash form such as /24. It tells you if the mask is not valid (the 1 bits must all be together at the start).",
    when: "You see a netmask in a config file and want the shorter /number that most tools and docs use.",
    example: { mask: "255.255.255.224" },
  },
  "n-wildcard-mask": {
    what: "Flips a netmask to give the wildcard mask, where every bit is reversed (255.255.255.0 becomes 0.0.0.255).",
    when: "You are writing Cisco-style access lists or OSPF settings, which ask for a wildcard mask instead of a normal netmask.",
    example: { mask: "255.255.255.240" },
  },
  "n-ip-to-int": {
    what: "Converts an IPv4 address like 192.0.2.10 into the single whole number a computer stores it as.",
    when: "You need to store, sort or compare IP addresses as plain numbers, for example in a database column.",
    example: { ip: "192.0.2.10" },
  },
  "n-int-to-ip": {
    what: "Converts a whole number between 0 and 4294967295 back into a normal dotted IPv4 address.",
    when: "You found an IP stored as a number in a log or database and want to read it as a normal address.",
    example: { int: "3221225994" },
  },
  "n-ip-class": {
    what: "Tells you which old-style address class (A, B, C, D or E) an IPv4 address falls into, based on its first number.",
    when: "You are studying for a networking exam or reading older docs that talk about classes. Modern networks use CIDR instead, so the class says little about real network size.",
    example: { ip: "172.16.5.4" },
  },
  "n-ip-type": {
    what: "Tells you what kind of IPv4 address you have: private (home or office only), loopback (this machine), link-local, documentation, multicast, reserved, or a normal public internet address.",
    when: "You see an unfamiliar IP in a log or config and want to know if it is on the public internet or only inside a local network.",
    example: { ip: "10.20.30.40" },
  },
  "n-ip-in-cidr": {
    what: "Checks whether one IPv4 address is inside a given network range written in CIDR form (like 10.0.0.0/8) and answers yes or no.",
    when: "You are writing a firewall or allow-list rule and want to confirm a specific address is covered by it.",
    example: { ip: "198.51.100.77", cidr: "198.51.100.0/25" },
  },
  "n-cidr-hosts": {
    what: "Give it a prefix length (the number after the slash) and it tells you how many addresses the block has in total and how many can be given to devices.",
    when: "You are sizing a subnet and want to know if /26 or /27 is big enough for your devices.",
    example: { bits: "26" },
  },
  "n-range-to-cidr": {
    what: "Takes a start and end IPv4 address and returns the smallest list of CIDR blocks that together cover exactly that range.",
    when: "You have a range like 192.0.2.10 to 192.0.2.40 but your firewall only accepts CIDR blocks.",
    example: { start: "192.0.2.10", end: "192.0.2.40" },
  },
  "n-cidr-split": {
    what: "Splits one CIDR network into a number of equal smaller networks and lists each one. The count must be a power of 2 (2, 4, 8, 16 and so on).",
    when: "You have one address block and want to divide it evenly between teams, floors or VLANs.",
    example: { cidr: "10.0.0.0/24", count: "4" },
  },
  "n-ipv6-expand": {
    what: "Takes a shortened IPv6 address (with :: and missing zeros) and writes it out in full, all 8 groups of 4 hex digits.",
    when: "You need to compare or sort IPv6 addresses, or a tool demands the full written-out form.",
    example: { addr: "2001:db8::1" },
  },
  "n-ipv6-compress": {
    what: "Takes a long IPv6 address and gives the shortest standard way to write it, dropping leading zeros and replacing a run of zero groups with ::.",
    when: "You want a tidy IPv6 address for docs, configs or comparing against what a system prints.",
    example: { addr: "2001:0db8:0000:0000:0000:ff00:0042:8329" },
  },
  "n-ipv6-eui64": {
    what: "Turns a MAC address (a network card's hardware ID) into the 64-bit interface ID that IPv6 auto-configuration builds from it (modified EUI-64).",
    when: "You want to predict the second half of the IPv6 address a device will give itself from its MAC.",
    example: { mac: "00:1A:2B:3C:4D:5E" },
  },
  "n-mac-format": {
    what: "Takes a MAC address (a network card's hardware ID) written any way and shows it in the common styles: colon, dash, Cisco dotted, bare, and uppercase.",
    when: "You copied a MAC from one system and need it in the exact format another system or switch expects.",
    example: { mac: "001A.2B3C.4D5E" },
  },
  "n-mac-eui64": {
    what: "Builds a full IPv6 address from a MAC address and a 64-bit prefix (fe80:: by default, the local-link range) using the modified EUI-64 method.",
    when: "You want to work out a device's automatic IPv6 link-local or SLAAC address from its MAC. Devices using privacy addresses will not match.",
    example: { mac: "00:1A:2B:3C:4D:5E", prefix: "fe80::" },
  },
  "n-mac-vendor": {
    what: "Looks at the first half of a MAC address to guess which company made the network card, such as VMware, Apple or Raspberry Pi.",
    when: "You see an unknown device on your network and want a hint of what it is. It only knows about 25 common vendors, not the full official list.",
    example: { mac: "B8:27:EB:12:34:56" },
  },
  "n-port-lookup": {
    what: "Type a port number and it tells you which well-known service usually uses it, such as 22 for SSH or 443 for HTTPS.",
    when: "You see an open port in a scan or firewall log and want to know what it is probably for. It uses a small built-in table, so rare ports may not be listed.",
    example: { port: "3306" },
  },
  "n-ports-reference": {
    what: "Searches a built-in list of common network ports by service name or number, or shows the whole list if you leave it blank.",
    when: "You remember a service name like postgres or rdp and need its usual port number.",
    example: { q: "sql" },
  },
  "n-tcp-flags": {
    what: "Decodes the TCP flags number from a packet into names like SYN, ACK and FIN, or does the reverse and turns flag names into the number.",
    when: "You are reading packet captures or writing firewall rules and need to know which connection flags a value means.",
    example: { mode: "Number → Flags", value: "18" },
  },
  "n-http-status": {
    what: "Type an HTTP status code (the number a web server replies with, like 404) and get its name and group, such as success or client error.",
    when: "You see a status code in a browser, log or API response and want to know what it means.",
    example: { code: "503" },
  },
  "n-http-methods": {
    what: "Explains what each HTTP request method (GET, POST, PUT, DELETE and so on) is for. Pick one, or leave it blank to see all of them.",
    when: "You are building or testing a web API and want to choose the right method for an action.",
    example: { method: "PUT" },
  },
  "n-mime-type": {
    what: "Type a file extension like pdf or .png and get its MIME type, the label web servers send so browsers know what kind of file it is.",
    when: "You are setting a Content-Type header or server config and need the right type for a file. It uses a table of about 50 common extensions.",
    example: { ext: "svg" },
  },
  "n-url-parser": {
    what: "Breaks a full web address into its parts: scheme, host, port, path, query, fragment, login details, and each query parameter on its own line.",
    when: "You are debugging a long or confusing link and want to see exactly what each part contains. The URL must include the scheme, such as https://.",
    example: { url: "https://shop.example.com:8443/cart/items?id=42&color=blue#reviews" },
  },
  "n-query-parser": {
    what: "Takes the part of a URL after the ? and lists every parameter as a name = value line, with encoded characters decoded.",
    when: "You have a long tracking or API query string and want to read its values clearly.",
    example: { qs: "?q=network+tools&page=2&sort=price%20asc" },
  },
  "n-user-agent": {
    what: "Reads a browser's User-Agent text (the ID string browsers send to websites) and makes a best guess at the browser, its version, the operating system, and mobile or desktop.",
    when: "You are looking at a web log entry and want to know what kind of visitor made the request. It is a guess, and User-Agent strings can be faked.",
    example: { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" },
  },
  "n-dns-types": {
    what: "Explains what a DNS record type (A, AAAA, MX, TXT and others) is used for. Leave it blank to see the whole list.",
    when: "You are editing your domain's DNS settings and are not sure which record type you need.",
    example: { type: "MX" },
  },
  "n-ptr-name": {
    what: "Builds the special reverse-DNS name (ending in in-addr.arpa or ip6.arpa) used to look up the hostname that belongs to an IP address.",
    when: "You are setting up or querying reverse DNS for a mail server or log lookup and need the exact PTR record name.",
    example: { ip: "192.0.2.25", mode: "IPv4" },
  },
  "n-cidr-compare": {
    what: "Compares two CIDR network blocks and tells you if they are the same, if one contains the other, or if they do not overlap.",
    when: "You are checking firewall rules or routes for overlaps or duplicates.",
    example: { a: "10.0.0.0/16", b: "10.0.5.0/24" },
  },
  "n-dig-builder": {
    what: "Builds a ready-to-copy dig command (a DNS lookup tool) for a name and record type, with an optional DNS server to ask.",
    when: "You want to check a domain's DNS records from a terminal without remembering dig's syntax. It only builds the command; you run it yourself.",
    example: { name: "example.com", type: "MX", server: "1.1.1.1" },
  },
  "n-nslookup-builder": {
    what: "Builds a ready-to-copy nslookup command (a DNS lookup tool on Windows, macOS and Linux) for a name, record type and optional server.",
    when: "You are on a machine without dig, such as Windows, and want to look up DNS records. It only builds the command.",
    example: { name: "example.com", type: "TXT", server: "8.8.8.8" },
  },
  "n-ping-builder": {
    what: "Builds a ping command with the number of packets and packet size, using the right flags for Linux, macOS or Windows.",
    when: "You want to test whether a host is reachable and cannot remember that Windows uses -n and -l while Linux uses -c and -s.",
    example: { host: "example.com", count: "5", size: "56", os: "Windows" },
  },
  "n-traceroute-builder": {
    what: "Builds the command that shows the path packets take to a host: traceroute on Linux and macOS, tracert on Windows.",
    when: "A site is slow or unreachable and you want to see where along the route the problem starts.",
    example: { host: "example.com", os: "Linux" },
  },
  "n-nmap-builder": {
    what: "Builds an nmap command (a network scanner) from a target, a scan type, optional ports, optional scripts and a faster timing option.",
    when: "You are doing an authorized scan of your own systems and want the right flags without reading the manual. Only scan networks you have permission to test.",
    example: { target: "192.0.2.0/28", scanType: "Version detection", ports: "22,80,443", timing: true },
  },
  "n-curl-builder": {
    what: "Builds a curl command (a command-line web request tool) with your chosen method, URL, headers and body, plus options to skip certificate checks or show details.",
    when: "You are testing a web API from a terminal and want a correctly quoted command you can paste.",
    example: { method: "POST", url: "https://api.example.com/v1/users", headers: "Content-Type: application/json\nAuthorization: Bearer TEST_TOKEN", data: "{\"name\":\"Jane Doe\"}" },
  },
  "n-wget-builder": {
    what: "Builds a wget command to download a file, with options for the saved file name, resuming a broken download, quiet mode and a custom User-Agent.",
    when: "You need to download a file on a server from the terminal and want the right flags.",
    example: { url: "https://example.com/files/report.pdf", output: "report.pdf", continueDl: true },
  },
  "n-netcat-builder": {
    what: "Builds a netcat (nc) command that either listens on a port or connects to a host and port, with UDP and verbose options.",
    when: "You are testing whether a port is open or passing text between two of your own machines. Only use it on systems you are allowed to test.",
    example: { mode: "Connect", host: "192.0.2.10", port: "8080", verbose: true },
  },
  "n-tcpdump-builder": {
    what: "Builds a tcpdump command (a packet capture tool) with a filter for a network interface, host, port and protocol.",
    when: "You want to capture only the traffic you care about on a server, for example everything to one host on port 443.",
    example: { iface: "eth0", host: "192.0.2.10", port: "443", proto: "tcp" },
  },
  "n-spf-check": {
    what: "Reads an SPF record (the DNS text entry that lists which servers may send email for a domain) and explains each part and whether it passes or fails mail.",
    when: "You are setting up email for a domain and want to check the SPF record makes sense before publishing it. It checks the syntax only; it does not look anything up.",
    example: { spf: "v=spf1 ip4:192.0.2.0/24 include:_spf.example.com mx ~all" },
  },
  "n-ipv6-ula": {
    what: "Generates a random private IPv6 network prefix (a Unique Local Address block starting with fd) that you can use inside your own network. No input needed.",
    when: "You are setting up IPv6 on a home lab or office network and need a private prefix that is unlikely to clash with anyone else's.",
    example: {},
  },
  "n-ipv4-mapped-ipv6": {
    what: "Shows how an IPv4 address is written inside IPv6, in the IPv4-mapped form (::ffff:...) and the old IPv4-compatible form.",
    when: "You see addresses like ::ffff:192.0.2.1 in server logs and want to understand or build them.",
    example: { ip: "192.0.2.1" },
  },
  "n-whois-builder": {
    what: "Builds a whois command to look up who registered a domain or owns an IP address, with an optional whois server.",
    when: "You want to find the registrar or owner of a domain or IP from the terminal. It only builds the command.",
    example: { target: "example.com", server: "whois.iana.org" },
  },
  "n-ssh-builder": {
    what: "Builds an ssh command (for logging in to a remote machine) with the user, port, private key file and options you choose.",
    when: "You connect to a server on a non-standard port or with a specific key and want the command right the first time.",
    example: { host: "server.example.com", user: "deploy", port: "2222", key: "~/.ssh/id_ed25519" },
  },
  "n-openssl-builder": {
    what: "Builds an openssl s_client command that connects to a secure (TLS/HTTPS) server so you can see its certificate.",
    when: "You are debugging an HTTPS or certificate problem and want to see what certificate a server actually sends.",
    example: { host: "example.com", port: "443", sni: "www.example.com", showCerts: true },
  },
};
