// ============================================================================
// Wireless Attacks Knowledge Base
// Comprehensive reference for WiFi, Bluetooth, IoT, RF attack techniques
// ============================================================================

// ----------------------------------------------------------------------------
// 1. WIFI_ATTACKS -- WiFi attack techniques and methodologies
// ----------------------------------------------------------------------------
const WIFI_ATTACKS = [
  {
    name: "Evil Twin Access Point",
    description: "An Evil Twin attack involves creating a rogue wireless access point that mimics a legitimate network by broadcasting the same SSID and, in many cases, spoofing the same BSSID (MAC address). When victims connect to the attacker-controlled AP, all their traffic passes through the attacker's system, enabling traffic interception, credential harvesting, session hijacking, and DNS manipulation. The attack is particularly effective in environments where users routinely connect to open or known networks such as coffee shops, airports, hotels, and corporate guest networks.\n\nThe attacker typically sets up the rogue AP using a wireless adapter in monitor/AP mode alongside software like hostapd for AP management and dnsmasq for DHCP/DNS services. To force victims onto the Evil Twin, the attacker may combine this with a deauthentication attack against the legitimate AP, causing clients to disconnect and automatically reconnect to the stronger (closer) rogue signal. More advanced variants use captive portal frameworks to present convincing login pages that harvest WPA passphrases or corporate credentials. Tools like Fluxion automate the entire workflow from target selection through credential capture.",
    tools: [
      {
        name: "hostapd",
        commands: [
          "hostapd evil_twin.conf",
          "echo 'interface=wlan0\ndriver=nl80211\nssid=TargetNetwork\nhw_mode=g\nchannel=6\nwmm_enabled=0' > evil_twin.conf"
        ]
      },
      {
        name: "dnsmasq",
        commands: [
          "dnsmasq -C dnsmasq.conf --no-daemon",
          "echo 'interface=wlan0\ndhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h\ndhcp-option=3,192.168.1.1\ndhcp-option=6,192.168.1.1\nserver=8.8.8.8\nlog-queries\nlog-dhcp\naddress=/#/192.168.1.1' > dnsmasq.conf"
        ]
      },
      {
        name: "airbase-ng",
        commands: [
          "airbase-ng -a AA:BB:CC:DD:EE:FF --essid TargetNetwork -c 6 wlan0mon"
        ]
      },
      {
        name: "Fluxion",
        commands: [
          "git clone https://github.com/FluxionNetwork/fluxion.git",
          "cd fluxion && sudo ./fluxion.sh"
        ]
      }
    ],
    prerequisites: [
      "Wireless adapter supporting AP/monitor mode (e.g., Alfa AWUS036ACH)",
      "Two wireless interfaces (one for AP, one for deauth) or one interface plus Ethernet uplink",
      "Knowledge of target network SSID, channel, and BSSID",
      "Root/sudo access on attacking system"
    ],
    detection: [
      "Wireless IDS detecting duplicate SSIDs with different BSSIDs",
      "Monitoring for abnormal AP beacon patterns or signal strength anomalies",
      "802.11w Management Frame Protection detecting spoofed deauth frames",
      "Client-side certificate validation failures on WPA2-Enterprise networks",
      "Unusual DHCP server responses or DNS resolution changes"
    ],
    prevention: [
      "Deploy WPA2/WPA3-Enterprise with mutual certificate authentication (EAP-TLS)",
      "Enable 802.11w Protected Management Frames (PMF) on all APs",
      "Use a Wireless Intrusion Prevention System (WIPS) to detect rogue APs",
      "Educate users to verify network authenticity before connecting",
      "Disable automatic WiFi connection on client devices",
      "Implement DNSSEC and DNS-over-HTTPS on endpoints"
    ],
    difficulty: "intermediate"
  },
  {
    name: "Deauthentication Attack",
    description: "A deauthentication attack exploits the IEEE 802.11 management frame specification, which in networks without 802.11w (Protected Management Frames) allows any device to send unauthenticated deauthentication and disassociation frames. The attacker sends spoofed deauth frames appearing to come from the legitimate AP to one or more clients, or broadcast deauth frames to disconnect all clients simultaneously. This forces clients to drop their current connection and re-associate, which can be used as a denial-of-service attack or as a precursor to handshake capture and Evil Twin attacks.\n\nThe attack is trivially simple to execute with tools like aireplay-ng or mdk4 and requires only a wireless adapter capable of packet injection. The IEEE 802.11w amendment (mandatory in WPA3) adds cryptographic protection to management frames, making spoofed deauth frames detectable and rejectable. However, the vast majority of deployed networks still lack PMF support, leaving them vulnerable. Continuous deauthentication can render a wireless network completely unusable, and targeted deauthentication of specific clients enables selective denial of service.",
    tools: [
      {
        name: "aireplay-ng",
        commands: [
          "aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon",
          "aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon",
          "aireplay-ng --deauth 50 -a AA:BB:CC:DD:EE:FF wlan0mon"
        ]
      },
      {
        name: "mdk4",
        commands: [
          "mdk4 wlan0mon d -b blacklist.txt",
          "mdk4 wlan0mon d -c 6"
        ]
      },
      {
        name: "Scapy",
        commands: [
          "python3 -c \"from scapy.all import *; sendp(RadioTap()/Dot11(addr1='FF:FF:FF:FF:FF:FF',addr2='AA:BB:CC:DD:EE:FF',addr3='AA:BB:CC:DD:EE:FF')/Dot11Deauth(reason=7),iface='wlan0mon',count=100,inter=0.1)\""
        ]
      }
    ],
    prerequisites: [
      "Wireless adapter with monitor mode and packet injection support",
      "Target network BSSID and channel information",
      "Root/sudo privileges"
    ],
    detection: [
      "High volume of deauthentication/disassociation frames in wireless logs",
      "WIDS/WIPS alerts on management frame floods",
      "Client-side repeated disconnection and reassociation events",
      "Anomalous frame source addresses not matching known infrastructure"
    ],
    prevention: [
      "Enable 802.11w Protected Management Frames (PMF) on all access points",
      "Upgrade to WPA3 which mandates PMF",
      "Deploy a Wireless Intrusion Prevention System (WIPS)",
      "Use wired connections for critical systems where possible",
      "Monitor for and alert on deauth frame floods"
    ],
    difficulty: "beginner"
  },
  {
    name: "WPA/WPA2 Handshake Capture and Cracking",
    description: "WPA/WPA2 Personal (PSK) networks authenticate clients through a four-way EAPOL handshake that derives session keys from the Pre-Shared Key (the WiFi password). An attacker who captures this handshake can perform an offline dictionary or brute-force attack against the captured handshake to recover the plaintext passphrase. The attack works because the handshake contains sufficient cryptographic material (ANonce, SNonce, and MIC values) to verify candidate passwords without further interaction with the access point.\n\nThe standard workflow begins with placing a wireless adapter into monitor mode using airmon-ng, then using airodump-ng to identify the target network and capture traffic on its channel. To accelerate the process, the attacker sends deauthentication frames to force a client to reconnect, generating a fresh handshake. Once captured, the handshake file is processed offline using tools like aircrack-ng for CPU-based cracking, or hashcat for GPU-accelerated cracking which can test billions of candidates per second on modern hardware. The time required depends entirely on the password complexity -- common dictionary words and short passwords can be cracked in seconds, while long random passphrases remain computationally infeasible.",
    tools: [
      {
        name: "airmon-ng",
        commands: [
          "airmon-ng start wlan0",
          "airmon-ng check kill",
          "airmon-ng stop wlan0mon"
        ]
      },
      {
        name: "airodump-ng",
        commands: [
          "airodump-ng wlan0mon",
          "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon"
        ]
      },
      {
        name: "aireplay-ng",
        commands: [
          "aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon"
        ]
      },
      {
        name: "aircrack-ng",
        commands: [
          "aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap",
          "aircrack-ng -a2 -b AA:BB:CC:DD:EE:FF -w wordlist.txt capture-01.cap"
        ]
      },
      {
        name: "hashcat",
        commands: [
          "hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt",
          "hashcat -m 22000 capture.hc22000 -a 3 ?d?d?d?d?d?d?d?d",
          "hcxpcapngtool -o capture.hc22000 capture-01.cap"
        ]
      }
    ],
    prerequisites: [
      "Wireless adapter with monitor mode and packet injection capability",
      "At least one client connected to the target network (for deauth-based capture)",
      "Wordlists or computational resources for brute-force cracking",
      "Storage for capture files and cracking dictionaries"
    ],
    detection: [
      "Deauthentication frames preceding handshake capture",
      "Unknown devices in monitor mode near the network",
      "WIDS alerts on suspicious probe and authentication patterns",
      "Repeated EAPOL handshake exchanges from the same client"
    ],
    prevention: [
      "Use WPA3-SAE which replaces PSK with Simultaneous Authentication of Equals",
      "Enforce long, complex, randomly generated passphrases (20+ characters)",
      "Implement WPA2-Enterprise (802.1X) instead of WPA2-Personal",
      "Enable 802.11w PMF to prevent deauth-assisted capture",
      "Regularly rotate WiFi passwords",
      "Monitor for unauthorized wireless capture attempts"
    ],
    difficulty: "intermediate"
  },
  {
    name: "PMKID Attack",
    description: "The PMKID attack, discovered by Jens 'atom' Steube (hashcat developer) in 2018, targets WPA/WPA2 networks by extracting the PMKID value from the first message of the four-way handshake or from RSN IE (Robust Security Network Information Element) in beacon and probe response frames. Unlike traditional handshake capture, this attack does not require any client to be connected to the network. The PMKID is derived as HMAC-SHA1-128(PMK, 'PMK Name' || MAC_AP || MAC_STA), and since the attacker knows all values except the PMK (which is derived from the passphrase), they can perform an offline attack.\n\nThe attack uses hcxdumptool to send association requests to the target AP and capture the PMKID from the AP's response. The captured PMKID is then converted to a hashcat-compatible format using hcxpcapngtool and cracked offline. This technique is significantly faster and more reliable than traditional handshake capture because it requires only a single frame from the AP, no client interaction, no deauthentication, and no waiting for a complete four-way handshake. Not all access points transmit PMKIDs, but a substantial percentage of consumer and enterprise APs do, making this a widely applicable attack vector.",
    tools: [
      {
        name: "hcxdumptool",
        commands: [
          "hcxdumptool -i wlan0mon -o capture.pcapng --filterlist_ap=targets.txt --filtermode=2 --enable_status=1",
          "hcxdumptool -i wlan0mon -o capture.pcapng",
          "hcxdumptool -i wlan0mon -o capture.pcapng --active_beacon --tot=5"
        ]
      },
      {
        name: "hcxpcapngtool",
        commands: [
          "hcxpcapngtool -o hash.hc22000 capture.pcapng",
          "hcxpcapngtool -o hash.hc22000 -E essidlist capture.pcapng"
        ]
      },
      {
        name: "hashcat",
        commands: [
          "hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt",
          "hashcat -m 22000 hash.hc22000 -a 3 ?a?a?a?a?a?a?a?a --increment"
        ]
      }
    ],
    prerequisites: [
      "Wireless adapter supporting monitor mode",
      "Target AP must support and respond with PMKID (not all APs do)",
      "Computational resources for offline hash cracking",
      "hcxdumptool and hcxpcapngtool installed"
    ],
    detection: [
      "Unusual association request patterns from unknown MAC addresses",
      "High volume of association attempts without subsequent data transfer",
      "WIDS detecting rapid association/deassociation cycles",
      "Monitoring for RSN IE extraction attempts"
    ],
    prevention: [
      "Migrate to WPA3-SAE which is not vulnerable to PMKID extraction",
      "Use long, random passphrases that resist dictionary attacks",
      "Disable PMKID generation on APs that support this option",
      "Deploy WPA2-Enterprise (802.1X) which does not use PSK-derived PMKIDs",
      "Implement 802.11w PMF on all access points"
    ],
    difficulty: "intermediate"
  },
  {
    name: "WPS PIN Brute Force",
    description: "Wi-Fi Protected Setup (WPS) was designed to simplify connecting devices to WPA/WPA2 networks by allowing authentication via an 8-digit PIN printed on the router. However, a critical design flaw discovered by Stefan Viehbock in 2011 revealed that the PIN is validated in two halves (first 4 digits, then last 3 digits plus checksum), reducing the effective keyspace from 100,000,000 to approximately 11,000 combinations. This makes online brute-force attacks feasible within hours.\n\nTools like Reaver and Bully systematically try all possible PIN combinations against the target AP's WPS implementation. Once the correct PIN is found, the tool retrieves the WPA/WPA2 passphrase regardless of its complexity. The Pixie Dust attack (implemented in Pixiewps) further accelerates this by exploiting weak random number generation in many router chipsets to recover the PIN offline from a single WPS exchange, often in seconds rather than hours. Many modern routers implement WPS lockout after failed attempts, but some can be bypassed with timing adjustments. Despite its known vulnerabilities, WPS remains enabled by default on many consumer routers.",
    tools: [
      {
        name: "Reaver",
        commands: [
          "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv",
          "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1 -vv",
          "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -d 5 -N -vv",
          "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -p 12345670"
        ]
      },
      {
        name: "Bully",
        commands: [
          "bully -b AA:BB:CC:DD:EE:FF -c 6 wlan0mon",
          "bully -b AA:BB:CC:DD:EE:FF -c 6 -d wlan0mon",
          "bully -b AA:BB:CC:DD:EE:FF -c 6 -S wlan0mon"
        ]
      },
      {
        name: "Pixiewps",
        commands: [
          "pixiewps -e <pke> -r <pkr> -s <e-hash1> -z <e-hash2> -a <authkey> -n <e-nonce>",
          "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1 -vv"
        ]
      },
      {
        name: "wash",
        commands: [
          "wash -i wlan0mon",
          "wash -i wlan0mon -5 -C"
        ]
      }
    ],
    prerequisites: [
      "Target AP must have WPS enabled",
      "Wireless adapter with monitor mode and packet injection",
      "wash tool to identify WPS-enabled networks",
      "Patience for online brute force (hours) or vulnerable chipset for Pixie Dust (seconds)"
    ],
    detection: [
      "High volume of WPS authentication attempts in AP logs",
      "Repeated EAP-WSC (WPS) message exchanges from a single client",
      "WPS lockout events triggered repeatedly",
      "WIDS alerts on WPS brute-force patterns"
    ],
    prevention: [
      "Disable WPS entirely on all access points",
      "If WPS must remain, enable AP rate limiting and lockout after failed attempts",
      "Update router firmware to patch Pixie Dust vulnerable chipsets",
      "Use WPA3 which does not rely on WPS for simplified setup",
      "Monitor logs for WPS brute-force indicators"
    ],
    difficulty: "beginner"
  },
  {
    name: "Karma Attack",
    description: "The Karma attack exploits the WiFi client probing mechanism where devices broadcast probe requests for previously connected networks. In a Karma attack, the rogue access point responds to all probe requests regardless of the SSID being requested, essentially pretending to be every network the client has ever connected to. When a client device receives a probe response matching a known SSID, it automatically connects to the attacker's AP, believing it has found a familiar trusted network.\n\nThis attack is particularly effective against devices with long lists of saved networks, especially open (unencrypted) networks commonly found in airports, hotels, and cafes. Modern operating systems have implemented mitigations such as suppressing directed probe requests and not automatically connecting to open networks, but older devices and certain IoT equipment remain vulnerable. Advanced implementations combine Karma with MANA (an improved version that also responds with commonly seen SSIDs) and Loud MANA (which beacons all observed SSIDs simultaneously). The Hostapd-mana project and WiFi Pineapple hardware are the most common platforms for executing Karma attacks.",
    tools: [
      {
        name: "hostapd-mana",
        commands: [
          "hostapd-mana /etc/hostapd-mana/hostapd-mana.conf",
          "echo 'interface=wlan0\ndriver=nl80211\nhw_mode=g\nchannel=6\nssid=FreeWiFi\nmana_loud=1\nmana_manadir=/tmp/mana\nenable_mana=1' > hostapd-mana.conf"
        ]
      },
      {
        name: "WiFi Pineapple",
        commands: [
          "pineap enable",
          "pineap add_ssid 'Free Airport WiFi'",
          "pineap set_karma on"
        ]
      },
      {
        name: "Bettercap",
        commands: [
          "bettercap -iface wlan0mon -eval 'wifi.recon on; wifi.ap'",
          "set wifi.ap.ssid FreeWiFi; set wifi.ap.channel 6; wifi.ap on"
        ]
      }
    ],
    prerequisites: [
      "Wireless adapter capable of AP mode",
      "Target clients must have saved open network profiles",
      "DHCP and DNS services for connected clients",
      "Internet uplink for convincing the victim they are online"
    ],
    detection: [
      "An AP responding to multiple different SSIDs from the same BSSID",
      "Rapid SSID beacon changes from a single source",
      "WIDS detecting probe response floods",
      "Client connecting to unexpected networks without user action"
    ],
    prevention: [
      "Remove saved open network profiles from devices",
      "Disable automatic connection to known networks",
      "Use VPN for all wireless connections",
      "Modern OS versions suppress directed probes -- keep devices updated",
      "Only save WPA2/WPA3 Enterprise network profiles",
      "Disable WiFi when not in active use"
    ],
    difficulty: "intermediate"
  },
  {
    name: "KRACK (Key Reinstallation Attack)",
    description: "KRACK (Key Reinstallation Attacks), published by Mathy Vanhoef in October 2017, exploits vulnerabilities in the WPA2 four-way handshake and group key handshake implementations. The attack works by manipulating and replaying handshake messages, causing the client to reinstall an already-in-use session key. When the key is reinstalled, associated parameters such as the incremental transmit packet number (nonce) and receive packet number (replay counter) are reset to their initial values. This nonce reuse violates the fundamental security assumptions of the encryption protocol.\n\nFor AES-CCMP (the most common WPA2 cipher), nonce reuse allows an attacker to decrypt packets and forge frames. For TKIP and GCMP, the impact is even more severe -- nonce reuse enables both decryption and key recovery, allowing the attacker to inject arbitrary packets. The attack targets the client (supplicant) implementation rather than the AP, making it a client-side vulnerability. Linux and Android 6.0+ were particularly vulnerable because wpa_supplicant versions 2.4 and above used an all-zero encryption key after reinstallation, enabling trivial full traffic decryption. The vulnerability was assigned multiple CVEs (CVE-2017-13077 through CVE-2017-13088) and required patches to both AP and client firmware.",
    tools: [
      {
        name: "krackattacks-scripts",
        commands: [
          "git clone https://github.com/vanhoefm/krackattacks-scripts.git",
          "cd krackattacks-scripts && sudo python3 krack_all_zero_tk.py wlan0mon",
          "sudo python3 krack-ft-test.py wlan0mon"
        ]
      },
      {
        name: "Scapy",
        commands: [
          "python3 krack_test.py --iface wlan0mon --target-ap AA:BB:CC:DD:EE:FF"
        ]
      }
    ],
    prerequisites: [
      "Target must be using WPA2 without KRACK patches applied",
      "Wireless adapter supporting monitor mode and injection",
      "MitM position between client and AP (same channel)",
      "Understanding of 802.11 state machine and EAPOL handshake",
      "Python 3 with Scapy installed"
    ],
    detection: [
      "Detecting replayed EAPOL handshake messages (messages 3 or group key message 1)",
      "Monitoring for nonce reuse in encrypted frames",
      "IDS signatures for KRACK exploitation patterns",
      "Unusual retransmission patterns in handshake exchanges"
    ],
    prevention: [
      "Apply vendor patches for WPA2 KRACK vulnerabilities on all APs and clients",
      "Upgrade to WPA3 which is designed to be resistant to key reinstallation",
      "Use HTTPS and VPN to encrypt traffic regardless of WiFi encryption state",
      "Update all wireless drivers and firmware to latest versions",
      "Enable client isolation on APs to limit lateral movement"
    ],
    difficulty: "advanced"
  },
  {
    name: "FragAttacks (Fragmentation and Aggregation Attacks)",
    description: "FragAttacks, disclosed by Mathy Vanhoef in May 2021, encompasses a set of twelve vulnerabilities (CVE-2020-24586 through CVE-2020-26145) affecting virtually all WiFi implementations since the original 802.11 standard in 1997. Three of the vulnerabilities are design flaws in the WiFi standard itself, while the remaining nine stem from widespread implementation mistakes. The design flaws include the aggregation attack (mixing plaintext and encrypted frames in A-MSDU aggregation), the mixed key attack (reassembling fragments encrypted under different keys), and the fragment cache attack (using cached fragments across reconnections).\n\nThe implementation vulnerabilities include accepting plaintext frames in protected networks, processing fragmented frames as full frames, accepting plaintext A-MSDU frames with a non-SPP A-MSDU capable flag, and various injection vulnerabilities in specific implementations. Practical exploitation allows an attacker within radio range to inject arbitrary frames, exfiltrate data, and in some scenarios intercept traffic. The most severe attacks can be performed against WPA3 networks, demonstrating that even the latest security protocol does not fully mitigate these issues. All major operating systems, wireless chipset manufacturers, and AP vendors required patches.",
    tools: [
      {
        name: "fragattacks",
        commands: [
          "git clone https://github.com/vanhoefm/fragattacks.git",
          "cd fragattacks && sudo python3 fragattack.py wlan0 --inject-test",
          "sudo python3 fragattack.py wlan0 ping I,E,E --ap",
          "sudo python3 fragattack.py wlan0 amsdu-inject --ap"
        ]
      }
    ],
    prerequisites: [
      "Modified WiFi driver with injection and monitor support (patched ath9k_htc or iwlwifi)",
      "Target device running unpatched WiFi firmware/driver",
      "Python 3 with modified Scapy",
      "Physical proximity to target WiFi network"
    ],
    detection: [
      "Anomalous A-MSDU frame structures with unexpected subframe headers",
      "Fragment reassembly from different encryption contexts",
      "Plaintext frames received within a protected BSS",
      "Unusual fragment sequences or caching patterns"
    ],
    prevention: [
      "Apply firmware and driver patches from vendors for all WiFi devices",
      "Use HTTPS and other application-layer encryption to protect sensitive data",
      "Disable A-MSDU support where possible and where performance impact is acceptable",
      "Keep all operating systems and WiFi drivers up to date",
      "Use VPN to add an additional layer of encryption"
    ],
    difficulty: "advanced"
  },
  {
    name: "Rogue Access Point",
    description: "A rogue access point is an unauthorized wireless access point connected to a corporate or private network without the administrator's knowledge. Unlike an Evil Twin which impersonates an existing AP, a rogue AP introduces an entirely new attack surface by bridging the wired and wireless network segments, potentially bypassing firewalls, network segmentation, and access controls. Rogue APs can be planted by malicious insiders, social engineers, or compromised IoT devices with WiFi capabilities.\n\nAn attacker can deploy a small, concealable device such as a Raspberry Pi, WiFi Pineapple, or modified travel router in a network closet, under a desk, or hidden in the ceiling tiles. Once connected to an Ethernet port, the rogue AP provides wireless access to the internal network from outside the building. Sophisticated rogue APs can be configured with enterprise-grade encryption to blend in with legitimate infrastructure, or intentionally left open to attract connections for traffic interception. Enterprise WIDS/WIPS solutions continuously scan for unauthorized SSIDs and BSSIDs, but detection can be evaded by using low transmit power, infrequent beaconing, or 5GHz channels that some monitoring systems overlook.",
    tools: [
      {
        name: "hostapd",
        commands: [
          "hostapd -B rogue_ap.conf",
          "echo 'interface=wlan0\nbridge=br0\ndriver=nl80211\nssid=CorpWiFi\nhw_mode=a\nchannel=36\nwpa=2\nwpa_passphrase=password123\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP' > rogue_ap.conf"
        ]
      },
      {
        name: "WiFi Pineapple",
        commands: [
          "ssh root@172.16.42.1",
          "pineap enable; pineap set_ssid 'Guest-WiFi'"
        ]
      },
      {
        name: "create_ap",
        commands: [
          "create_ap wlan0 eth0 RogueNet secretpass",
          "create_ap --no-virt -w 2 wlan0 eth0 RogueNet password123"
        ]
      }
    ],
    prerequisites: [
      "Physical access to plant the rogue device on the wired network",
      "Wireless adapter with AP mode support",
      "Knowledge of target network naming conventions and security settings",
      "Power source for the rogue device (PoE, outlet, battery)"
    ],
    detection: [
      "WIDS/WIPS scanning for unauthorized BSSIDs and SSIDs",
      "Network access control (NAC) detecting new MAC addresses on switch ports",
      "Periodic physical security sweeps for unauthorized hardware",
      "Correlation of wired switch port activity with wireless AP appearances",
      "ARP table analysis showing unexpected bridge interfaces"
    ],
    prevention: [
      "Deploy 802.1X port-based authentication on all wired switch ports",
      "Implement network access control (NAC) with device profiling",
      "Conduct regular physical security audits for unauthorized devices",
      "Use a WIPS solution with automatic rogue AP containment",
      "Disable unused Ethernet ports and implement MAC address filtering",
      "Segment the network to limit rogue AP lateral movement"
    ],
    difficulty: "intermediate"
  },
  {
    name: "Captive Portal Phishing",
    description: "Captive portal phishing combines a rogue access point with a web-based phishing interface that mimics legitimate captive portals or login pages. When a victim connects to the attacker's open WiFi network, all HTTP traffic is redirected to a convincing phishing page that requests credentials -- typically the WPA passphrase of a target network, corporate login credentials, social media passwords, or payment information. The technique exploits users' familiarity with captive portals in hotels, airports, and coffee shops.\n\nAdvanced implementations clone the exact HTML, CSS, and JavaScript of the target organization's real login portal, making the phishing page visually indistinguishable from the legitimate one. The attacker may also combine this with deauthentication attacks against the legitimate network, then present the phishing portal as a 'firmware update' or 'reauthentication' page that requests the WPA password. Tools like Wifiphisher, Fluxion, and the WiFi Pineapple's Portal Auth module automate the entire attack chain from AP creation to credential capture. The captured credentials are logged and can be used immediately or stored for later exploitation.",
    tools: [
      {
        name: "Wifiphisher",
        commands: [
          "wifiphisher -aI wlan0 -eI wlan1 -p oauth-login",
          "wifiphisher -aI wlan0 -eI wlan1 -p firmware-upgrade --essid TargetNetwork",
          "wifiphisher --essid FreeWiFi -p plugin_update -kN"
        ]
      },
      {
        name: "Fluxion",
        commands: [
          "cd fluxion && sudo ./fluxion.sh -l en",
          "sudo ./fluxion.sh --target AA:BB:CC:DD:EE:FF"
        ]
      },
      {
        name: "Eaphammer",
        commands: [
          "python3 eaphammer --bssid AA:BB:CC:DD:EE:FF --essid CorpNet --channel 6 --captive-portal",
          "python3 eaphammer --cert-wizard"
        ]
      }
    ],
    prerequisites: [
      "Two wireless interfaces (one for rogue AP, one for deauthentication)",
      "Web server software (Apache, nginx, or Python HTTP server)",
      "Cloned or crafted phishing portal pages",
      "DNS and DHCP services for client management"
    ],
    detection: [
      "SSL certificate warnings when accessing supposedly known sites",
      "URL inspection showing IP addresses instead of domain names",
      "Network monitoring for DNS hijacking to local addresses",
      "WIDS alerts on deauthentication followed by new AP with same SSID"
    ],
    prevention: [
      "Train users to never enter credentials on HTTP pages or pages with certificate warnings",
      "Enforce HSTS on corporate web applications",
      "Use WPA2/WPA3 Enterprise with certificate-based authentication",
      "Deploy browser-based phishing detection extensions",
      "Implement multi-factor authentication for all corporate services",
      "Never enter WPA passwords into web forms"
    ],
    difficulty: "intermediate"
  },
  {
    name: "WiFi Jamming",
    description: "WiFi jamming is a denial-of-service technique that disrupts wireless communications by flooding the 2.4GHz and/or 5GHz frequency bands with noise or interference, preventing legitimate devices from transmitting and receiving data. Unlike deauthentication attacks which exploit protocol-level vulnerabilities, jamming operates at the physical (RF) layer and affects all devices within range regardless of encryption or protocol version. Jamming can range from constant noise transmission (continuous jamming) to intelligent techniques that detect and disrupt only specific transmissions (reactive jamming).\n\nJamming can be achieved with purpose-built hardware (signal generators, HackRF, or dedicated jammers) or improvised devices. Constant jamming transmits continuous noise on the target frequency, while deceptive jamming sends valid-looking but meaningless 802.11 frames to keep the channel busy. Reactive jamming monitors the channel and transmits only when legitimate traffic is detected, making it harder to detect and more energy-efficient. WiFi jamming is illegal in most jurisdictions under radio communications laws (FCC Part 15 in the US, similar regulations globally), and possession of jamming equipment may itself be a criminal offense. However, understanding jamming is essential for assessing wireless network resilience and planning redundancy.",
    tools: [
      {
        name: "mdk4",
        commands: [
          "mdk4 wlan0mon b -c 1,6,11",
          "mdk4 wlan0mon d",
          "mdk4 wlan0mon a -a AA:BB:CC:DD:EE:FF"
        ]
      },
      {
        name: "HackRF",
        commands: [
          "hackrf_transfer -t /dev/urandom -f 2437000000 -s 20000000 -a 1 -x 47",
          "osmocom_fft -f 2412000000 -s 20000000"
        ]
      },
      {
        name: "aireplay-ng (layer 2 jamming)",
        commands: [
          "aireplay-ng -0 0 -a FF:FF:FF:FF:FF:FF wlan0mon"
        ]
      }
    ],
    prerequisites: [
      "RF transmitter capable of operating on 2.4GHz or 5GHz bands",
      "Understanding of local radio regulations (jamming is illegal in most jurisdictions)",
      "For protocol-level jamming: wireless adapter with injection support",
      "For RF-level jamming: SDR hardware like HackRF One"
    ],
    detection: [
      "Sudden loss of connectivity for all clients simultaneously",
      "Elevated noise floor on affected channels observed via spectrum analyzer",
      "No deauth frames present (distinguishes from protocol-level attacks)",
      "Interference patterns visible on spectrum analysis tools (e.g., Kismet, WiFi Explorer)"
    ],
    prevention: [
      "Use frequency-hopping or multi-band APs to reduce jamming impact",
      "Deploy on both 2.4GHz and 5GHz/6GHz bands for redundancy",
      "Use directional antennas to limit exposure to jammers",
      "Implement wired backup connections for critical systems",
      "Use RF shielding for sensitive areas",
      "Report suspected jamming to regulatory authorities"
    ],
    difficulty: "beginner"
  },
  {
    name: "Packet Injection",
    description: "Packet injection is the technique of crafting and transmitting arbitrary 802.11 frames into a wireless network. Unlike normal WiFi operation where the wireless adapter's firmware and driver handle frame construction, packet injection allows an attacker to create frames with arbitrary header fields, payloads, and addressing. This capability underpins many other WiFi attacks including deauthentication, Evil Twin, handshake capture, and protocol fuzzing.\n\nPacket injection requires a wireless adapter with a chipset and driver that support raw frame transmission, and the adapter must be placed in monitor mode. Common chipsets with reliable injection support include Atheros AR9271 (ath9k_htc), Ralink RT3070 (rt2800usb), and Realtek RTL8812AU (rtl8812au with aircrack-ng driver patches). The Scapy framework in Python provides a flexible platform for constructing and injecting any type of 802.11 frame, from management frames (beacons, probes, authentication, deauth) to data frames and control frames. Injection testing can be performed with aireplay-ng to verify adapter capabilities before conducting more complex attacks.",
    tools: [
      {
        name: "aireplay-ng",
        commands: [
          "aireplay-ng -9 wlan0mon",
          "aireplay-ng -9 -i wlan1mon wlan0mon",
          "aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon"
        ]
      },
      {
        name: "Scapy",
        commands: [
          "python3 -c \"from scapy.all import *; sendp(RadioTap()/Dot11(type=0,subtype=8,addr1='ff:ff:ff:ff:ff:ff',addr2='aa:bb:cc:dd:ee:ff',addr3='aa:bb:cc:dd:ee:ff')/Dot11Beacon(cap='ESS+privacy')/Dot11Elt(ID='SSID',info='TestBeacon')/Dot11Elt(ID='Rates',info='\\x82\\x84\\x8b\\x96\\x0c\\x12\\x18\\x24')/Dot11Elt(ID='DSset',info='\\x06'),iface='wlan0mon',count=100,inter=0.1)\"",
          "python3 -c \"from scapy.all import *; conf.iface='wlan0mon'; sniff(prn=lambda x: x.summary(), count=100)\""
        ]
      },
      {
        name: "packetforge-ng",
        commands: [
          "packetforge-ng -0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 -k 192.168.1.1 -l 192.168.1.100 -y keystream.xor -w inject.cap",
          "aireplay-ng -2 -r inject.cap wlan0mon"
        ]
      }
    ],
    prerequisites: [
      "Wireless adapter with chipset supporting packet injection",
      "Appropriate driver with injection patches installed",
      "Adapter placed in monitor mode",
      "Understanding of 802.11 frame format and types"
    ],
    detection: [
      "Malformed or unusual frame types appearing on the network",
      "Frames with unexpected sequence numbers or flags",
      "WIDS signatures for known injection patterns",
      "Anomalous traffic from MAC addresses not in the client table"
    ],
    prevention: [
      "Enable 802.11w PMF to authenticate management frames",
      "Use WPA3 for enhanced frame protection",
      "Deploy WIDS/WIPS to detect injection attacks",
      "Implement client isolation to limit injected frame reach",
      "Keep wireless drivers and firmware updated to patch injection-based attack vectors"
    ],
    difficulty: "intermediate"
  },
  {
    name: "War Driving",
    description: "War driving is the practice of systematically surveying wireless networks by driving (or walking, cycling, or using drones) through an area with WiFi scanning equipment to map access points, their security configurations, signal strengths, and geographic locations. The term originates from 'war dialing' in the 1980s. War driving itself is generally passive reconnaissance -- the scanning device listens for beacon frames and probe responses broadcast by access points, which is typically legal as these are publicly transmitted signals. However, the intelligence gathered enables targeted attacks.\n\nModern war driving setups combine a high-gain omnidirectional antenna, a WiFi adapter in monitor mode, GPS receiver for geolocation, and software such as Kismet or Wigle WiFi. The collected data reveals networks using weak encryption (WEP, open), default SSIDs suggesting unconfigured routers, hidden networks (which still expose their BSSID), and WPS-enabled access points. This intelligence can be used to identify vulnerable targets for further exploitation. The Wigle.net database aggregates war driving data from contributors worldwide, containing hundreds of millions of network records and providing a searchable map of global WiFi deployments.",
    tools: [
      {
        name: "Kismet",
        commands: [
          "kismet -c wlan0mon",
          "kismet -c wlan0mon --override wardrive",
          "kismet -c wlan0mon -c hci0:type=linuxbluetooth"
        ]
      },
      {
        name: "airodump-ng",
        commands: [
          "airodump-ng wlan0mon --gpsd --write wardriving_results -o csv",
          "airodump-ng wlan0mon --band abg --write fullscan"
        ]
      },
      {
        name: "Wigle WiFi",
        commands: [
          "# Android app: WiGLE WiFi Wardriving (FOSS)",
          "# Export results as CSV/KML for mapping"
        ]
      },
      {
        name: "gpsd",
        commands: [
          "gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock",
          "cgps -s"
        ]
      }
    ],
    prerequisites: [
      "Wireless adapter with monitor mode support",
      "GPS receiver for geolocation data",
      "Vehicle or other mobility platform",
      "High-gain antenna for extended range detection",
      "Storage for collected data"
    ],
    detection: [
      "Difficult to detect as war driving is passive (listen-only)",
      "Active probing variants may be detectable via probe request patterns",
      "Physical security cameras may capture war driving vehicles",
      "Unusual vehicles with visible antennas near sensitive facilities"
    ],
    prevention: [
      "Use WPA3 or WPA2 with strong passphrases to reduce attack value",
      "Disable SSID broadcast (provides minimal security but reduces casual discovery)",
      "Reduce AP transmit power to minimize signal leakage beyond the premises",
      "Use directional antennas pointed inward to reduce external signal exposure",
      "Regularly audit wireless security configurations",
      "Implement network monitoring for unauthorized connection attempts"
    ],
    difficulty: "beginner"
  }
];

// ----------------------------------------------------------------------------
// 2. BLUETOOTH_ATTACKS -- Bluetooth Classic and BLE attack techniques
// ----------------------------------------------------------------------------
const BLUETOOTH_ATTACKS = [
  {
    name: "BlueBorne",
    protocol: "Both",
    description: "BlueBorne is a set of eight zero-click vulnerabilities disclosed by Armis Labs in September 2017 that allow remote code execution, man-in-the-middle attacks, and information disclosure over Bluetooth without requiring the target device to be paired, discoverable, or even have an active connection. The attack vector exploits implementation flaws in the Bluetooth stack across Android (CVE-2017-0781, CVE-2017-0782, CVE-2017-0783, CVE-2017-0785), iOS (CVE-2017-14315), Windows (CVE-2017-8628), and Linux/BlueZ (CVE-2017-1000251, CVE-2017-1000250). An attacker within Bluetooth range (approximately 10 meters, extendable with directional antennas) can take complete control of vulnerable devices in under 10 seconds without any user interaction. The Linux kernel RCE (CVE-2017-1000251) exploits a stack buffer overflow in the L2CAP configuration response handling, and the Android RCE exploits a use-after-free vulnerability in the SDP (Service Discovery Protocol) implementation. BlueBorne is wormable -- a compromised device can scan for and infect other nearby Bluetooth-enabled devices, enabling rapid lateral spread through dense environments like offices, airports, and conferences.",
    tools: [
      "BlueBorne Scanner (Armis)",
      "blueborne-scanner (Python PoC)",
      "l2ping",
      "hcitool",
      "bluetoothctl"
    ],
    impact: "Remote code execution with kernel/system-level privileges, complete device compromise without user interaction, wormable propagation across nearby devices, data exfiltration, and man-in-the-middle interception of all Bluetooth communications.",
    mitigation: [
      "Apply OS vendor patches (Android September 2017 security patch, iOS 10.3.3+, Windows September 2017 update, Linux kernel 4.13.1+)",
      "Disable Bluetooth when not in active use",
      "Limit Bluetooth discoverability and set devices to non-discoverable mode",
      "Use Bluetooth 5.0+ devices with updated firmware",
      "Deploy mobile device management (MDM) to enforce Bluetooth policies",
      "Monitor for unusual Bluetooth scanning activity in sensitive areas"
    ]
  },
  {
    name: "KNOB (Key Negotiation of Bluetooth)",
    protocol: "Classic",
    description: "The KNOB attack (CVE-2019-9506), published in August 2019, exploits a fundamental flaw in the Bluetooth BR/EDR (Classic) key negotiation process during connection establishment. The Bluetooth specification allows two devices to negotiate an encryption key length between 1 and 16 bytes during the LMP (Link Manager Protocol) key length negotiation. The KNOB attack intercepts this negotiation and forces both devices to agree on a 1-byte (8-bit) encryption key, reducing the effective keyspace to only 256 possible keys. The attacker can then brute-force this weak key in real time and decrypt all subsequent Bluetooth traffic. The vulnerability exists because the key length negotiation is not authenticated or integrity-protected in the Bluetooth specification, allowing a MitM attacker to modify the negotiation messages. This affects all Bluetooth BR/EDR devices compliant with the specification up to Bluetooth 5.0, making it a specification-level vulnerability rather than an implementation bug.",
    tools: [
      "InternalBlue framework",
      "Ubertooth One",
      "Wireshark with Bluetooth dissectors",
      "custom LMP injection firmware"
    ],
    impact: "Real-time decryption of all Bluetooth Classic communications including voice calls, file transfers, HID (keyboard/mouse) input, and tethered data connections between the target devices.",
    mitigation: [
      "Apply vendor patches that enforce a minimum encryption key length of 7 bytes or higher",
      "Update Bluetooth firmware to versions implementing Bluetooth 5.1+ key length enforcement",
      "Avoid transmitting sensitive data over Bluetooth Classic connections",
      "Use application-layer encryption for sensitive Bluetooth communications",
      "Monitor for Bluetooth connection anomalies indicating MitM positioning"
    ]
  },
  {
    name: "BIAS (Bluetooth Impersonation Attacks)",
    protocol: "Classic",
    description: "BIAS (CVE-2020-10135), published in May 2020, allows an attacker to impersonate a previously paired Bluetooth device and establish a connection without possessing the shared long-term pairing key. The attack exploits multiple flaws in the Bluetooth BR/EDR Secure Simple Pairing and Secure Connections authentication procedures. Specifically, the attacker can: (1) perform role switching to become the authentication verifier instead of the claimant, (2) exploit mutual authentication not being mandatory by downgrading to legacy authentication, and (3) bypass Secure Connections requirements by claiming lack of support. The attacker needs only the Bluetooth address (BD_ADDR) of a device previously paired with the target, which can be obtained through passive sniffing of Bluetooth traffic. Combined with KNOB, an attacker can both impersonate a trusted device and then weaken the encryption, achieving full compromise of the Bluetooth connection.",
    tools: [
      "InternalBlue",
      "Ubertooth One",
      "hcitool",
      "btlejack",
      "Wireshark Bluetooth plugins"
    ],
    impact: "Impersonation of trusted paired devices, unauthorized connection establishment, bypass of authentication requirements, and when combined with KNOB, full decryption of communications.",
    mitigation: [
      "Apply firmware updates that enforce mutual authentication during connection establishment",
      "Require Secure Connections mode and reject legacy authentication fallback",
      "Implement minimum encryption key length enforcement",
      "Remove unnecessary device pairings from Bluetooth device lists",
      "Use Bluetooth 5.2+ with enhanced security features",
      "Monitor pairing databases for unexpected entries"
    ]
  },
  {
    name: "BlueSmack DoS",
    protocol: "Classic",
    description: "BlueSmack is a denial-of-service attack against Bluetooth devices that sends oversized L2CAP echo request (ping) packets, similar to the classic 'Ping of Death' attack against TCP/IP stacks. The attack exploits poor bounds checking in Bluetooth stack implementations, causing the target device to crash, freeze, or reboot when processing excessively large packets. The attack is straightforward to execute using the l2ping utility with a large packet size parameter. While modern Bluetooth stacks have largely mitigated the original vulnerability, variations continue to emerge in embedded devices, IoT equipment, and older systems where Bluetooth firmware updates are infrequent. The attack requires only the target's Bluetooth address (discoverable via inquiry scan or passive sniffing) and does not require pairing.",
    tools: [
      "l2ping",
      "hcitool",
      "bluetoothctl",
      "custom L2CAP scripts"
    ],
    impact: "Denial of service causing device crash, freeze, or reboot; disruption of active Bluetooth connections; potential data loss in unsaved application state.",
    mitigation: [
      "Update Bluetooth firmware to patch L2CAP packet handling vulnerabilities",
      "Implement proper bounds checking on incoming Bluetooth packets",
      "Set devices to non-discoverable mode when pairing is not needed",
      "Disable Bluetooth when not in active use",
      "Use Bluetooth firewalling features where available"
    ]
  },
  {
    name: "BlueSnarfing",
    protocol: "Classic",
    description: "BlueSnarfing is an attack that exploits OBEX (Object Exchange) protocol vulnerabilities in Bluetooth implementations to gain unauthorized access to information stored on a Bluetooth-enabled device. The attack targets the OBEX Push Profile (OPP) and OBEX File Transfer Profile (FTP) services, exploiting improper access controls to read contacts, calendar entries, emails, text messages, pictures, and other files without the device owner's knowledge. The original BlueSnarfing vulnerability allowed unauthenticated OBEX connections on devices that were set to discoverable mode, but even non-discoverable devices can be targeted if their Bluetooth address is known (through prior observation or brute-force scanning). While most modern smartphones have patched the original BlueSnarfing vulnerabilities, many older devices, car infotainment systems, medical devices, and industrial Bluetooth equipment remain vulnerable.",
    tools: [
      "bluesnarfer",
      "obexftp",
      "hcitool",
      "sdptool",
      "nOBEX"
    ],
    impact: "Unauthorized access to contacts, call logs, SMS messages, emails, calendar entries, files, and IMEI numbers on the target device, all without user awareness or consent.",
    mitigation: [
      "Keep Bluetooth firmware and OS updated with latest security patches",
      "Set devices to non-discoverable mode by default",
      "Reject unexpected OBEX connection requests",
      "Disable Bluetooth file transfer services when not needed",
      "Use Bluetooth 4.0+ with Secure Simple Pairing",
      "Implement application-level access controls on OBEX services"
    ]
  },
  {
    name: "BlueJacking",
    protocol: "Classic",
    description: "BlueJacking is a technique of sending unsolicited messages to Bluetooth-enabled devices via the OBEX protocol, specifically through the OBEX Object Push service. The attacker crafts a contact card (vCard) with a message in the name field and pushes it to nearby discoverable devices. While BlueJacking itself is relatively benign -- the attacker cannot access data on the target device -- it can be used as a social engineering vector to trick users into accepting a pairing request or clicking a malicious link embedded in the message. On older devices, repeated BlueJacking can cause notification flooding that disrupts device usability. The attack range is limited to Bluetooth radio range (typically 10-100 meters depending on device class), but can be extended with high-gain directional antennas.",
    tools: [
      "obexpush",
      "ussp-push",
      "hcitool scan",
      "bluetoothctl",
      "bloover (mobile)"
    ],
    impact: "Unsolicited message delivery to target devices, social engineering vector for tricking users into accepting malicious pairings, notification flooding for denial of service, and reconnaissance of nearby Bluetooth device names and addresses.",
    mitigation: [
      "Set Bluetooth to non-discoverable mode when not actively pairing",
      "Reject OBEX push requests from unknown devices",
      "Disable automatic acceptance of incoming Bluetooth file transfers",
      "Educate users about unsolicited Bluetooth messages and social engineering risks",
      "Configure devices to require manual approval for all incoming connections"
    ]
  },
  {
    name: "BLE GATT Exploitation",
    protocol: "BLE",
    description: "BLE (Bluetooth Low Energy) GATT (Generic Attribute Profile) exploitation targets the service discovery and data exchange layer of BLE devices. GATT defines how BLE devices expose their functionality through services and characteristics, and many IoT devices implement insufficient access controls on their GATT profiles. An attacker can enumerate all services, characteristics, and descriptors on a BLE device, read sensitive data from characteristics that should be protected, write to control characteristics to manipulate device behavior, and subscribe to notification characteristics to monitor real-time data. Common targets include smart locks (reading or writing unlock commands), medical devices (modifying configuration or reading patient data), fitness trackers (exfiltrating health data), and industrial sensors (manipulating readings). Many BLE devices implement 'Just Works' pairing which provides no man-in-the-middle protection, and some devices accept connections without any authentication at all.",
    tools: [
      "gatttool",
      "bluetoothctl",
      "Bettercap BLE module",
      "nRF Connect (mobile app)",
      "BtleJuice",
      "GATTacker"
    ],
    impact: "Unauthorized read/write access to BLE device data and controls, manipulation of smart home devices, exfiltration of health and fitness data, unlocking of BLE-secured locks, and modification of sensor readings.",
    mitigation: [
      "Implement proper GATT characteristic permissions (read/write with encryption and authentication required)",
      "Use BLE Secure Connections with LESC (LE Secure Connections) pairing",
      "Require bonding (pairing) before allowing access to sensitive characteristics",
      "Implement application-layer authentication and encryption above GATT",
      "Use passkey or OOB pairing methods instead of Just Works",
      "Disable BLE advertising when not needed"
    ]
  },
  {
    name: "BLE Tracking",
    protocol: "BLE",
    description: "BLE tracking exploits the advertising packets broadcast by Bluetooth Low Energy devices to track individuals' movements and locations over time. BLE devices such as smartphones, fitness trackers, smartwatches, wireless earbuds, and BLE beacons continuously transmit advertising packets containing their MAC address and device information. Even with MAC address randomization (introduced in Bluetooth 4.2), research has shown that devices can still be uniquely fingerprinted through advertising payload analysis, timing patterns, and protocol-level identifiers that persist across MAC rotations. A 2019 study from Boston University demonstrated that the advertising token rotation timing can be correlated across MAC changes to maintain continuous tracking. Passive BLE tracking infrastructure can be deployed using inexpensive receivers (Raspberry Pi with BLE dongle, ESP32 boards) to monitor foot traffic, customer movements in retail environments, or individual movements across a city.",
    tools: [
      "hcitool lescan",
      "bluetoothctl",
      "Bettercap",
      "BLE Scanner apps",
      "Raspberry Pi with BlueZ",
      "ESP32 BLE scanner"
    ],
    impact: "Persistent tracking of individuals through their Bluetooth devices, deanonymization of device owners through movement pattern analysis, retail customer behavior monitoring, and building surveillance capabilities without cameras.",
    mitigation: [
      "Enable BLE MAC address randomization on all devices (Bluetooth 4.2+)",
      "Update to Bluetooth 5.4+ for improved privacy features",
      "Turn off Bluetooth when not actively using it",
      "Use devices that implement frequent advertising address rotation",
      "Be aware that even with randomization, advanced correlation attacks may still track devices",
      "Disable BLE on devices that do not need it"
    ]
  },
  {
    name: "Bluetooth Man-in-the-Middle",
    protocol: "Both",
    description: "A Bluetooth man-in-the-middle (MitM) attack positions the attacker between two communicating Bluetooth devices, intercepting and potentially modifying all traffic. For Bluetooth Classic, the attacker can exploit the Secure Simple Pairing (SSP) 'Just Works' association model, which provides no MitM protection, or leverage the KNOB and BIAS vulnerabilities to weaken or bypass authentication. For BLE, the 'Just Works' pairing method is similarly vulnerable, and the attacker can use tools like BtleJuice or GATTacker to create a proxy that relays GATT communications while inspecting and modifying data in transit. The BtleJuice framework specifically implements a two-device MitM architecture where one device connects to the target BLE peripheral and another advertises as a clone to the victim central device, transparently proxying all GATT operations while giving the attacker full visibility and control over the data exchange.",
    tools: [
      "BtleJuice",
      "GATTacker",
      "Ubertooth One",
      "InternalBlue",
      "Bettercap BLE proxy",
      "btlejack"
    ],
    impact: "Interception of all Bluetooth communications between paired devices, modification of data in transit, credential theft for Bluetooth-authenticated services, manipulation of IoT device commands, and eavesdropping on Bluetooth audio (calls, music).",
    mitigation: [
      "Use Numeric Comparison or Passkey Entry pairing instead of Just Works",
      "Implement Out-of-Band (OOB) pairing for high-security applications",
      "Verify pairing codes match on both devices during initial pairing",
      "Use LE Secure Connections (LESC) with Elliptic Curve Diffie-Hellman",
      "Implement application-layer encryption and mutual authentication",
      "Monitor for unexpected device disconnections and re-pairing requests"
    ]
  }
];

// ----------------------------------------------------------------------------
// 3. IOT_DEFAULT_CREDS -- Default credentials for IoT and network devices
// ----------------------------------------------------------------------------
const IOT_DEFAULT_CREDS = [
  // ---- Routers ----
  { vendor: "Linksys", model: "WRT54G", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Linksys", model: "EA6500", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Linksys", model: "WRT1900AC", username: "admin", password: "admin", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Linksys", model: "E1200", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Linksys", model: "Velop", username: "admin", password: "admin", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Netgear", model: "R7000 Nighthawk", username: "admin", password: "password", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Netgear", model: "R6700", username: "admin", password: "password", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Netgear", model: "WNR2000", username: "admin", password: "password", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Netgear", model: "Orbi RBK50", username: "admin", password: "password", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Netgear", model: "DGN2200", username: "admin", password: "password", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "TP-Link", model: "Archer C7", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "TP-Link", model: "TL-WR841N", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "TP-Link", model: "Archer AX50", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "TP-Link", model: "Deco M5", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "TP-Link", model: "TL-WR940N", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "D-Link", model: "DIR-615", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "D-Link", model: "DIR-825", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "D-Link", model: "DIR-868L", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "D-Link", model: "DIR-890L", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "D-Link", model: "DSL-2750U", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Asus", model: "RT-AC68U", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Asus", model: "RT-AX88U", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Asus", model: "RT-N66U", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Asus", model: "ZenWiFi AX", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Ubiquiti", model: "EdgeRouter X", username: "ubnt", password: "ubnt", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Ubiquiti", model: "EdgeRouter Lite", username: "ubnt", password: "ubnt", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Ubiquiti", model: "EdgeRouter 4", username: "ubnt", password: "ubnt", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Ubiquiti", model: "USG", username: "ubnt", password: "ubnt", port: 22, protocol: "SSH", category: "Router" },
  { vendor: "MikroTik", model: "RouterBOARD hAP", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "MikroTik", model: "CCR1009", username: "admin", password: "", port: 8291, protocol: "Winbox", category: "Router" },
  { vendor: "MikroTik", model: "RB750Gr3", username: "admin", password: "", port: 22, protocol: "SSH", category: "Router" },
  { vendor: "MikroTik", model: "hAP ac2", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Cisco", model: "RV340", username: "cisco", password: "cisco", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Cisco", model: "RV160", username: "cisco", password: "cisco", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Cisco", model: "ISR 4321", username: "cisco", password: "cisco", port: 22, protocol: "SSH", category: "Router" },
  { vendor: "Cisco", model: "ASR 1001-X", username: "cisco", password: "cisco", port: 22, protocol: "SSH", category: "Router" },
  { vendor: "Juniper", model: "SRX300", username: "root", password: "", port: 22, protocol: "SSH", category: "Router" },
  { vendor: "Juniper", model: "MX204", username: "root", password: "", port: 22, protocol: "SSH", category: "Router" },
  { vendor: "Juniper", model: "EX2300", username: "root", password: "", port: 22, protocol: "SSH", category: "Router" },
  { vendor: "Aruba", model: "Instant On AP22", username: "admin", password: "admin", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Aruba", model: "7005 Controller", username: "admin", password: "admin", port: 4343, protocol: "HTTPS", category: "Router" },
  { vendor: "Ruckus", model: "R610", username: "super", password: "sp-admin", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Ruckus", model: "ZoneDirector 1200", username: "super", password: "sp-admin", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Zyxel", model: "USG FLEX 100", username: "admin", password: "1234", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Zyxel", model: "VMG3312", username: "admin", password: "1234", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Zyxel", model: "NBG6515", username: "admin", password: "1234", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Huawei", model: "AR1200", username: "admin", password: "admin@huawei.com", port: 22, protocol: "SSH", category: "Router" },
  { vendor: "Huawei", model: "NetEngine AR651", username: "admin", password: "admin@huawei.com", port: 443, protocol: "HTTPS", category: "Router" },
  { vendor: "Huawei", model: "HG8245H", username: "root", password: "admin", port: 80, protocol: "HTTP", category: "Router" },

  // ---- IP Cameras ----
  { vendor: "Hikvision", model: "DS-2CD2142FWD", username: "admin", password: "12345", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Hikvision", model: "DS-2CD2185FWD", username: "admin", password: "12345", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Hikvision", model: "DS-7608NI NVR", username: "admin", password: "12345", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Hikvision", model: "DS-2CD2043G2", username: "admin", password: "12345", port: 443, protocol: "HTTPS", category: "Camera" },
  { vendor: "Dahua", model: "IPC-HDW5231R-ZE", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Dahua", model: "DH-XVR5108HS", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Dahua", model: "IPC-HFW2431T", username: "admin", password: "admin", port: 37777, protocol: "Dahua TCP", category: "Camera" },
  { vendor: "Dahua", model: "NVR4216-16P", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Axis", model: "M3046-V", username: "root", password: "pass", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Axis", model: "P3245-V", username: "root", password: "pass", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Axis", model: "M1065-LW", username: "root", password: "pass", port: 443, protocol: "HTTPS", category: "Camera" },
  { vendor: "Reolink", model: "RLC-810A", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Reolink", model: "Argus 3 Pro", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Reolink", model: "NVR RLN8-410", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Amcrest", model: "IP2M-841", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Amcrest", model: "IP8M-T2599EW", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Amcrest", model: "NV4108E NVR", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Foscam", model: "FI9821P", username: "admin", password: "", port: 88, protocol: "HTTP", category: "Camera" },
  { vendor: "Foscam", model: "R2", username: "admin", password: "", port: 88, protocol: "HTTP", category: "Camera" },
  { vendor: "Foscam", model: "FI9928P", username: "admin", password: "", port: 443, protocol: "HTTPS", category: "Camera" },
  { vendor: "Wyze", model: "Cam v3", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Wyze", model: "Cam Pan v2", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Camera" },
  { vendor: "Ring", model: "Stick Up Cam", username: "admin", password: "", port: 443, protocol: "HTTPS", category: "Camera" },
  { vendor: "Ring", model: "Spotlight Cam", username: "admin", password: "", port: 443, protocol: "HTTPS", category: "Camera" },

  // ---- NAS Devices ----
  { vendor: "Synology", model: "DS220+", username: "admin", password: "", port: 5000, protocol: "HTTP", category: "NAS" },
  { vendor: "Synology", model: "DS920+", username: "admin", password: "", port: 5001, protocol: "HTTPS", category: "NAS" },
  { vendor: "Synology", model: "RS1221+", username: "admin", password: "", port: 5000, protocol: "HTTP", category: "NAS" },
  { vendor: "QNAP", model: "TS-251D", username: "admin", password: "admin", port: 8080, protocol: "HTTP", category: "NAS" },
  { vendor: "QNAP", model: "TS-453D", username: "admin", password: "admin", port: 8080, protocol: "HTTP", category: "NAS" },
  { vendor: "QNAP", model: "TVS-672XT", username: "admin", password: "admin", port: 443, protocol: "HTTPS", category: "NAS" },
  { vendor: "Western Digital", model: "My Cloud EX2 Ultra", username: "admin", password: "", port: 80, protocol: "HTTP", category: "NAS" },
  { vendor: "Western Digital", model: "My Cloud PR4100", username: "admin", password: "", port: 80, protocol: "HTTP", category: "NAS" },
  { vendor: "Western Digital", model: "My Cloud Home", username: "admin", password: "", port: 80, protocol: "HTTP", category: "NAS" },
  { vendor: "Buffalo", model: "TeraStation 3410", username: "admin", password: "password", port: 80, protocol: "HTTP", category: "NAS" },
  { vendor: "Buffalo", model: "LinkStation 510", username: "admin", password: "password", port: 80, protocol: "HTTP", category: "NAS" },
  { vendor: "Asustor", model: "AS5304T", username: "admin", password: "admin", port: 8000, protocol: "HTTP", category: "NAS" },
  { vendor: "Asustor", model: "Lockerstor 4", username: "admin", password: "admin", port: 8000, protocol: "HTTP", category: "NAS" },

  // ---- Printers ----
  { vendor: "HP", model: "LaserJet Pro M404", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "HP", model: "OfficeJet Pro 9015", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "HP", model: "Color LaserJet Pro M255", username: "admin", password: "", port: 443, protocol: "HTTPS", category: "Printer" },
  { vendor: "HP", model: "LaserJet Enterprise M607", username: "admin", password: "", port: 9100, protocol: "JetDirect", category: "Printer" },
  { vendor: "Brother", model: "HL-L2350DW", username: "admin", password: "access", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Brother", model: "MFC-L2710DW", username: "admin", password: "access", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Brother", model: "MFC-J995DW", username: "admin", password: "access", port: 443, protocol: "HTTPS", category: "Printer" },
  { vendor: "Canon", model: "PIXMA TR8520", username: "ADMIN", password: "canon", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Canon", model: "imageCLASS MF445dw", username: "ADMIN", password: "7654321", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Canon", model: "imageRUNNER C3025", username: "7654321", password: "7654321", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Epson", model: "WorkForce WF-2860", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Epson", model: "EcoTank ET-4760", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Xerox", model: "VersaLink C405", username: "admin", password: "1111", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Xerox", model: "WorkCentre 6515", username: "admin", password: "1111", port: 443, protocol: "HTTPS", category: "Printer" },
  { vendor: "Xerox", model: "Phaser 6510", username: "admin", password: "1111", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Ricoh", model: "SP C261SFNw", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Ricoh", model: "MP C3004", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Ricoh", model: "IM C3000", username: "admin", password: "", port: 443, protocol: "HTTPS", category: "Printer" },
  { vendor: "Lexmark", model: "MC3326adwe", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Printer" },
  { vendor: "Lexmark", model: "CX417de", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Printer" },

  // ---- Firewalls ----
  { vendor: "pfSense", model: "SG-3100", username: "admin", password: "pfsense", port: 443, protocol: "HTTPS", category: "Firewall" },
  { vendor: "pfSense", model: "Netgate 6100", username: "admin", password: "pfsense", port: 443, protocol: "HTTPS", category: "Firewall" },
  { vendor: "pfSense", model: "Community Edition", username: "admin", password: "pfsense", port: 443, protocol: "HTTPS", category: "Firewall" },
  { vendor: "OPNsense", model: "DEC850", username: "root", password: "opnsense", port: 443, protocol: "HTTPS", category: "Firewall" },
  { vendor: "OPNsense", model: "Community Edition", username: "root", password: "opnsense", port: 443, protocol: "HTTPS", category: "Firewall" },
  { vendor: "Sophos", model: "XG 135", username: "admin", password: "admin", port: 4444, protocol: "HTTPS", category: "Firewall" },
  { vendor: "Sophos", model: "XGS 2100", username: "admin", password: "admin", port: 4444, protocol: "HTTPS", category: "Firewall" },
  { vendor: "Fortinet", model: "FortiGate 60F", username: "admin", password: "", port: 443, protocol: "HTTPS", category: "Firewall" },
  { vendor: "Fortinet", model: "FortiGate 100F", username: "admin", password: "", port: 443, protocol: "HTTPS", category: "Firewall" },
  { vendor: "Fortinet", model: "FortiGate 40F", username: "admin", password: "", port: 22, protocol: "SSH", category: "Firewall" },
  { vendor: "SonicWall", model: "TZ370", username: "admin", password: "password", port: 443, protocol: "HTTPS", category: "Firewall" },
  { vendor: "SonicWall", model: "NSA 2700", username: "admin", password: "password", port: 443, protocol: "HTTPS", category: "Firewall" },
  { vendor: "WatchGuard", model: "Firebox T40", username: "admin", password: "readwrite", port: 8080, protocol: "HTTPS", category: "Firewall" },
  { vendor: "WatchGuard", model: "Firebox M290", username: "admin", password: "readwrite", port: 8080, protocol: "HTTPS", category: "Firewall" },
  { vendor: "Barracuda", model: "CloudGen F18", username: "admin", password: "admin", port: 443, protocol: "HTTPS", category: "Firewall" },
  { vendor: "Barracuda", model: "CloudGen F80", username: "admin", password: "admin", port: 443, protocol: "HTTPS", category: "Firewall" },

  // ---- Industrial Control Systems ----
  { vendor: "Siemens", model: "SIMATIC S7-1200", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Industrial" },
  { vendor: "Siemens", model: "SIMATIC S7-300", username: "admin", password: "admin", port: 102, protocol: "ISO-TSAP", category: "Industrial" },
  { vendor: "Siemens", model: "SCALANCE X208", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Industrial" },
  { vendor: "Siemens", model: "SIMATIC HMI", username: "admin", password: "admin", port: 443, protocol: "HTTPS", category: "Industrial" },
  { vendor: "Allen-Bradley", model: "CompactLogix 5380", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Industrial" },
  { vendor: "Allen-Bradley", model: "MicroLogix 1400", username: "admin", password: "1234", port: 80, protocol: "HTTP", category: "Industrial" },
  { vendor: "Allen-Bradley", model: "ControlLogix 5580", username: "admin", password: "admin", port: 44818, protocol: "EtherNet/IP", category: "Industrial" },
  { vendor: "Schneider Electric", model: "Modicon M340", username: "USER", password: "USER", port: 80, protocol: "HTTP", category: "Industrial" },
  { vendor: "Schneider Electric", model: "Modicon M580", username: "USER", password: "USER", port: 502, protocol: "Modbus TCP", category: "Industrial" },
  { vendor: "Schneider Electric", model: "ATV320 VFD", username: "USER", password: "USER", port: 80, protocol: "HTTP", category: "Industrial" },
  { vendor: "ABB", model: "AC500 PLC", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Industrial" },
  { vendor: "ABB", model: "IRC5 Robot Controller", username: "Default User", password: "robotics", port: 80, protocol: "HTTP", category: "Industrial" },
  { vendor: "Honeywell", model: "ControlEdge PLC", username: "admin", password: "admin", port: 443, protocol: "HTTPS", category: "Industrial" },
  { vendor: "Honeywell", model: "Experion PKS", username: "admin", password: "admin", port: 443, protocol: "HTTPS", category: "Industrial" },

  // ---- Switches and Access Points ----
  { vendor: "Cisco", model: "Catalyst 2960", username: "admin", password: "cisco", port: 22, protocol: "SSH", category: "Switch" },
  { vendor: "Cisco", model: "Catalyst 9200", username: "admin", password: "cisco", port: 22, protocol: "SSH", category: "Switch" },
  { vendor: "Cisco", model: "SG350-28", username: "cisco", password: "cisco", port: 443, protocol: "HTTPS", category: "Switch" },
  { vendor: "Cisco", model: "CBS250-24T", username: "cisco", password: "cisco", port: 443, protocol: "HTTPS", category: "Switch" },
  { vendor: "Cisco", model: "Aironet 2800", username: "Cisco", password: "Cisco", port: 22, protocol: "SSH", category: "Access Point" },
  { vendor: "HP/Aruba", model: "2530-24G", username: "admin", password: "", port: 22, protocol: "SSH", category: "Switch" },
  { vendor: "HP/Aruba", model: "2930F-24G", username: "admin", password: "", port: 443, protocol: "HTTPS", category: "Switch" },
  { vendor: "HP/Aruba", model: "Instant On 1930", username: "admin", password: "", port: 443, protocol: "HTTPS", category: "Switch" },
  { vendor: "Dell", model: "PowerSwitch N1124T", username: "admin", password: "admin", port: 22, protocol: "SSH", category: "Switch" },
  { vendor: "Dell", model: "PowerSwitch S4148F", username: "admin", password: "admin", port: 443, protocol: "HTTPS", category: "Switch" },
  { vendor: "Dell", model: "PowerConnect 2848", username: "admin", password: "", port: 80, protocol: "HTTP", category: "Switch" },
  { vendor: "Ubiquiti", model: "UniFi Switch 24", username: "ubnt", password: "ubnt", port: 22, protocol: "SSH", category: "Switch" },
  { vendor: "Ubiquiti", model: "UniFi AP AC Pro", username: "ubnt", password: "ubnt", port: 22, protocol: "SSH", category: "Access Point" },
  { vendor: "Ubiquiti", model: "UniFi AP U6 Pro", username: "ubnt", password: "ubnt", port: 22, protocol: "SSH", category: "Access Point" },
  { vendor: "Ubiquiti", model: "UniFi Switch Lite 16", username: "ubnt", password: "ubnt", port: 22, protocol: "SSH", category: "Switch" },

  // ---- Miscellaneous ----
  { vendor: "Raspberry Pi Foundation", model: "Raspberry Pi OS", username: "pi", password: "raspberry", port: 22, protocol: "SSH", category: "SBC" },
  { vendor: "Raspberry Pi Foundation", model: "Raspberry Pi (legacy)", username: "pi", password: "raspberry", port: 22, protocol: "SSH", category: "SBC" },
  { vendor: "Generic Linux", model: "Default SSH", username: "root", password: "toor", port: 22, protocol: "SSH", category: "Server" },
  { vendor: "Generic Linux", model: "Kali Linux", username: "kali", password: "kali", port: 22, protocol: "SSH", category: "Server" },
  { vendor: "Jenkins", model: "Jenkins CI", username: "admin", password: "admin", port: 8080, protocol: "HTTP", category: "Software" },
  { vendor: "Jenkins", model: "Jenkins (default)", username: "admin", password: "password", port: 8080, protocol: "HTTP", category: "Software" },
  { vendor: "Grafana", model: "Grafana OSS", username: "admin", password: "admin", port: 3000, protocol: "HTTP", category: "Software" },
  { vendor: "Portainer", model: "Portainer CE", username: "admin", password: "admin", port: 9000, protocol: "HTTP", category: "Software" },
  { vendor: "Apache", model: "Tomcat", username: "tomcat", password: "tomcat", port: 8080, protocol: "HTTP", category: "Software" },
  { vendor: "Apache", model: "Tomcat Manager", username: "admin", password: "admin", port: 8080, protocol: "HTTP", category: "Software" },
  { vendor: "MongoDB", model: "MongoDB Community", username: "", password: "", port: 27017, protocol: "MongoDB", category: "Database" },
  { vendor: "Redis", model: "Redis Server", username: "", password: "", port: 6379, protocol: "Redis", category: "Database" },
  { vendor: "MySQL", model: "MySQL Community", username: "root", password: "", port: 3306, protocol: "MySQL", category: "Database" },
  { vendor: "PostgreSQL", model: "PostgreSQL Server", username: "postgres", password: "postgres", port: 5432, protocol: "PostgreSQL", category: "Database" },
  { vendor: "Elasticsearch", model: "Elasticsearch", username: "elastic", password: "changeme", port: 9200, protocol: "HTTP", category: "Database" },
  { vendor: "RabbitMQ", model: "RabbitMQ Server", username: "guest", password: "guest", port: 15672, protocol: "HTTP", category: "Software" },
  { vendor: "Nagios", model: "Nagios Core", username: "nagiosadmin", password: "nagios", port: 80, protocol: "HTTP", category: "Software" },
  { vendor: "Zabbix", model: "Zabbix Server", username: "Admin", password: "zabbix", port: 80, protocol: "HTTP", category: "Software" },
  { vendor: "Webmin", model: "Webmin", username: "root", password: "root", port: 10000, protocol: "HTTPS", category: "Software" },
  { vendor: "OpenMediaVault", model: "OMV", username: "admin", password: "openmediavault", port: 80, protocol: "HTTP", category: "Software" },
  { vendor: "Proxmox", model: "Proxmox VE", username: "root", password: "proxmox", port: 8006, protocol: "HTTPS", category: "Software" },
  { vendor: "VMware", model: "ESXi", username: "root", password: "vmware", port: 443, protocol: "HTTPS", category: "Hypervisor" },
  { vendor: "VMware", model: "vCenter", username: "administrator@vsphere.local", password: "VMware1!", port: 443, protocol: "HTTPS", category: "Hypervisor" },
  { vendor: "Ubiquiti", model: "UniFi Controller", username: "ubnt", password: "ubnt", port: 8443, protocol: "HTTPS", category: "Software" },
  { vendor: "APC", model: "Smart-UPS", username: "apc", password: "apc", port: 80, protocol: "HTTP", category: "UPS" },
  { vendor: "APC", model: "Network Management Card", username: "apc", password: "apc", port: 443, protocol: "HTTPS", category: "UPS" },
  { vendor: "Dell", model: "iDRAC 9", username: "root", password: "calvin", port: 443, protocol: "HTTPS", category: "BMC" },
  { vendor: "HP", model: "iLO 5", username: "Administrator", password: "admin", port: 443, protocol: "HTTPS", category: "BMC" },
  { vendor: "Supermicro", model: "IPMI BMC", username: "ADMIN", password: "ADMIN", port: 80, protocol: "HTTP", category: "BMC" },
  { vendor: "Arris", model: "SB8200", username: "admin", password: "password", port: 80, protocol: "HTTP", category: "Modem" },
  { vendor: "Motorola", model: "MB8600", username: "admin", password: "motorola", port: 80, protocol: "HTTP", category: "Modem" },
  { vendor: "ZTE", model: "F670L", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "ZTE", model: "ZXHN H298A", username: "user", password: "user", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Tenda", model: "AC1200", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "TRENDnet", model: "TEW-827DRU", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" },
  { vendor: "Belkin", model: "RT3200", username: "admin", password: "admin", port: 80, protocol: "HTTP", category: "Router" }
];

// ----------------------------------------------------------------------------
// 4. WIRELESS_TOOLS -- Wireless security and penetration testing tools
// ----------------------------------------------------------------------------
const WIRELESS_TOOLS = [
  {
    name: "aircrack-ng",
    description: "The core tool of the aircrack-ng suite for cracking WEP and WPA/WPA2 pre-shared keys. It processes captured handshake files and performs dictionary attacks or brute-force key recovery using CPU-based computation. Supports multiple input formats including pcap, pcapng, and IVS files.",
    install: "sudo apt install aircrack-ng",
    usage: [
      "aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap",
      "aircrack-ng -a2 -b AA:BB:CC:DD:EE:FF -w wordlist.txt capture-01.cap",
      "aircrack-ng -a1 -b AA:BB:CC:DD:EE:FF wep_capture-01.ivs",
      "aircrack-ng -e TargetSSID -w passwords.txt capture*.cap"
    ]
  },
  {
    name: "airmon-ng",
    description: "Manages wireless adapter modes, specifically enabling and disabling monitor mode on wireless interfaces. Monitor mode allows the adapter to capture all wireless frames in range rather than only those addressed to it. Also handles killing processes that may interfere with monitor mode operation.",
    install: "sudo apt install aircrack-ng",
    usage: [
      "airmon-ng check kill",
      "airmon-ng start wlan0",
      "airmon-ng start wlan0 6",
      "airmon-ng stop wlan0mon"
    ]
  },
  {
    name: "airodump-ng",
    description: "Wireless packet capture tool that listens on a monitor-mode interface and displays information about detected access points and associated clients in real time. Captures raw 802.11 frames for later analysis, handshake extraction, and key cracking. Supports channel hopping across all 2.4GHz and 5GHz channels or fixed-channel monitoring.",
    install: "sudo apt install aircrack-ng",
    usage: [
      "airodump-ng wlan0mon",
      "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon",
      "airodump-ng --band abg wlan0mon",
      "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w output --output-format pcap wlan0mon",
      "airodump-ng wlan0mon --gpsd -w wardriving"
    ]
  },
  {
    name: "aireplay-ng",
    description: "Wireless frame injection tool used for generating traffic, performing deauthentication attacks, fake authentication, ARP request replay, and other injection-based attacks. Essential for forcing handshake captures and accelerating WEP cracking through traffic generation.",
    install: "sudo apt install aircrack-ng",
    usage: [
      "aireplay-ng -9 wlan0mon",
      "aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon",
      "aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon",
      "aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon",
      "aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon"
    ]
  },
  {
    name: "Kismet",
    description: "Wireless network detector, packet sniffer, and intrusion detection system supporting WiFi, Bluetooth, Software Defined Radio, and other wireless protocols. Features a web-based UI, supports distributed remote capture via lightweight capture agents, and stores data in a SQLite database for later analysis. Kismet operates passively and can detect hidden networks, war driving data, and rogue access points.",
    install: "sudo apt install kismet",
    usage: [
      "kismet -c wlan0mon",
      "kismet -c wlan0mon -c hci0:type=linuxbluetooth",
      "kismet -c wlan0mon --override wardrive",
      "kismet_cap_linux_wifi --connect localhost:3501 --source wlan0mon",
      "kismet --no-ncurses"
    ]
  },
  {
    name: "Bettercap",
    description: "Swiss army knife for WiFi, BLE, HID, and IP network reconnaissance, MITM, and attack operations. Provides an interactive session with modular caplets for WiFi deauthentication, handshake capture, ARP spoofing, DNS spoofing, HTTP/HTTPS proxy, BLE enumeration, and HID injection. Features a web UI and scripting engine for automation.",
    install: "sudo apt install bettercap",
    usage: [
      "bettercap -iface wlan0mon -eval 'wifi.recon on'",
      "bettercap -iface wlan0mon -eval 'wifi.recon on; wifi.deauth AA:BB:CC:DD:EE:FF'",
      "bettercap -iface wlan0mon -caplet wifi-pumpkin.cap",
      "bettercap -eval 'ble.recon on'",
      "bettercap -iface eth0 -eval 'net.probe on; net.recon on; arp.spoof on'"
    ]
  },
  {
    name: "Wifite2",
    description: "Automated wireless attack tool designed for simplicity and effectiveness. Wifite automatically scans for targets, captures handshakes, performs deauthentication attacks, attempts WPS PIN attacks, PMKID capture, and integrates with hashcat and aircrack-ng for password recovery. Designed to be run with minimal user interaction while supporting all major WiFi attack vectors.",
    install: "sudo apt install wifite",
    usage: [
      "wifite",
      "wifite --kill --wpa --dict /usr/share/wordlists/rockyou.txt",
      "wifite -i wlan0mon --wps --wpa",
      "wifite --skip-crack --no-wps",
      "wifite -mac --random-mac"
    ]
  },
  {
    name: "hcxdumptool",
    description: "Small tool for capturing PMKID hashes, EAPOL handshakes, and other WPA/WPA2 authentication material from WiFi networks. Designed to work with hcxpcapngtool for converting captures to hashcat-compatible format. Supports targeted and broad-spectrum capture operations and is the primary tool for clientless PMKID-based WPA attacks.",
    install: "sudo apt install hcxdumptool",
    usage: [
      "hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1",
      "hcxdumptool -i wlan0mon -o capture.pcapng --filterlist_ap=targets.txt --filtermode=2",
      "hcxdumptool -i wlan0mon -o capture.pcapng --active_beacon --tot=5",
      "hcxdumptool -i wlan0mon -o capture.pcapng --disable_deauthentication"
    ]
  },
  {
    name: "hcxpcapngtool",
    description: "Conversion tool for processing raw packet captures (pcapng format from hcxdumptool) into hashcat-compatible hash formats. Extracts PMKIDs and EAPOL handshakes and outputs them in hash mode 22000 format for efficient GPU-accelerated cracking with hashcat. Part of the hcxtools suite.",
    install: "sudo apt install hcxtools",
    usage: [
      "hcxpcapngtool -o hash.hc22000 capture.pcapng",
      "hcxpcapngtool -o hash.hc22000 -E essidlist -I identitylist capture.pcapng",
      "hcxpcapngtool -o hash.hc22000 capture1.pcapng capture2.pcapng",
      "hcxpcapngtool --all -o hash.hc22000 capture.pcapng"
    ]
  },
  {
    name: "hashcat (WiFi mode)",
    description: "High-performance GPU-accelerated password recovery tool. For WiFi cracking, hashcat uses mode 22000 (WPA-PBKDF2-PMKID+EAPOL) to crack captured handshakes and PMKIDs. Supports dictionary attacks, rule-based attacks, mask attacks (brute force with patterns), combination attacks, and hybrid attacks. GPU acceleration provides orders of magnitude faster cracking than CPU-based tools.",
    install: "sudo apt install hashcat",
    usage: [
      "hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt",
      "hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d",
      "hashcat -m 22000 hash.hc22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule",
      "hashcat -m 22000 hash.hc22000 -a 6 wordlist.txt ?d?d?d?d",
      "hashcat -m 22000 hash.hc22000 --show"
    ]
  },
  {
    name: "hostapd",
    description: "IEEE 802.11 access point and authentication server daemon. Used legitimately for creating software-based APs and in security testing for creating rogue/evil twin access points. Supports WPA/WPA2/WPA3-Personal and Enterprise modes, 802.1X authentication, multiple BSSIDs, and 802.11n/ac/ax features. The hostapd-mana fork adds Karma/MANA attack capabilities.",
    install: "sudo apt install hostapd",
    usage: [
      "hostapd /etc/hostapd/hostapd.conf",
      "hostapd -B rogue_ap.conf",
      "hostapd -dd /etc/hostapd/hostapd.conf",
      "hostapd_cli status"
    ]
  },
  {
    name: "dnsmasq",
    description: "Lightweight DHCP server and DNS forwarder commonly used alongside hostapd to provide network services to clients connecting to rogue or test access points. Provides DHCP address assignment, DNS resolution (and DNS spoofing for captive portal attacks), and TFTP services. Essential component of Evil Twin and captive portal attack setups.",
    install: "sudo apt install dnsmasq",
    usage: [
      "dnsmasq -C /etc/dnsmasq.conf --no-daemon",
      "dnsmasq --interface=wlan0 --dhcp-range=192.168.1.10,192.168.1.50,12h --no-daemon",
      "dnsmasq --address=/#/192.168.1.1 --interface=wlan0 --no-daemon",
      "dnsmasq --log-queries --log-facility=/var/log/dnsmasq.log --no-daemon"
    ]
  },
  {
    name: "mdk4",
    description: "Wireless attack tool for IEEE 802.11 protocol exploitation. Supports beacon flood attacks (creating hundreds of fake APs), authentication DoS, deauthentication/disassociation floods, EAPOL start/logoff floods, and various other WiFi denial-of-service techniques. Successor to mdk3 with improved attack modules and better hardware support.",
    install: "sudo apt install mdk4",
    usage: [
      "mdk4 wlan0mon b -c 1,6,11",
      "mdk4 wlan0mon b -f ssid_list.txt -c 6",
      "mdk4 wlan0mon d -b blacklist.txt",
      "mdk4 wlan0mon a -a AA:BB:CC:DD:EE:FF",
      "mdk4 wlan0mon d -c 1,6,11"
    ]
  },
  {
    name: "Reaver",
    description: "WPS (Wi-Fi Protected Setup) brute-force attack tool that exploits the WPS PIN design flaw to recover WPA/WPA2 passphrases. Systematically tries PIN combinations against the target AP, taking advantage of the split-PIN verification that reduces the keyspace. Includes Pixie Dust attack support (-K flag) for offline PIN recovery against vulnerable chipsets.",
    install: "sudo apt install reaver",
    usage: [
      "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv",
      "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1 -vv",
      "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -d 5 -N -vv",
      "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -p 12345670"
    ]
  },
  {
    name: "Bully",
    description: "Alternative WPS brute-force tool implementing the WPS protocol more efficiently than Reaver in some scenarios. Handles various WPS implementation quirks and edge cases that may cause Reaver to fail. Supports Pixie Dust attacks for offline PIN recovery and includes improved timeout and retry handling for stubborn access points.",
    install: "sudo apt install bully",
    usage: [
      "bully -b AA:BB:CC:DD:EE:FF -c 6 wlan0mon",
      "bully -b AA:BB:CC:DD:EE:FF -c 6 -d wlan0mon",
      "bully -b AA:BB:CC:DD:EE:FF -c 6 -S wlan0mon",
      "bully -b AA:BB:CC:DD:EE:FF -c 6 -F wlan0mon"
    ]
  },
  {
    name: "Pixiewps",
    description: "Offline WPS PIN recovery tool that exploits weak random number generation in certain WiFi chipset WPS implementations. Derives the WPS PIN from a single online WPS exchange by analyzing the E-S1/E-S2 nonces and E-Hash1/E-Hash2 values. When the target chipset uses predictable random numbers, the PIN can be recovered in seconds rather than hours of online brute force.",
    install: "sudo apt install pixiewps",
    usage: [
      "pixiewps -e <pke> -r <pkr> -s <e-hash1> -z <e-hash2> -a <authkey> -n <e-nonce>",
      "pixiewps -e <pke> -r <pkr> -s <e-hash1> -z <e-hash2> -a <authkey> -n <e-nonce> -S"
    ]
  },
  {
    name: "HackRF One",
    description: "Open-source Software Defined Radio (SDR) platform capable of transmitting and receiving on frequencies from 1 MHz to 6 GHz with up to 20 MHz bandwidth. Used for RF signal analysis, replay attacks, GPS spoofing research, wireless protocol reverse engineering, and custom signal generation. The companion tools (hackrf_transfer, hackrf_sweep) enable raw RF capture and transmission.",
    install: "sudo apt install hackrf",
    usage: [
      "hackrf_info",
      "hackrf_transfer -r capture.raw -f 433920000 -s 2000000 -a 1 -l 32 -g 32",
      "hackrf_transfer -t replay.raw -f 433920000 -s 2000000 -a 1 -x 47",
      "hackrf_sweep -f 2400:2500 -w 500000",
      "hackrf_transfer -r capture.raw -f 915000000 -s 8000000"
    ]
  },
  {
    name: "RTL-SDR",
    description: "Ultra-low-cost Software Defined Radio receiver based on Realtek RTL2832U DVB-T USB dongles. Receives RF signals from approximately 24 MHz to 1.766 GHz, making it suitable for monitoring ISM bands (433 MHz, 868 MHz, 915 MHz), aircraft ADS-B transponders, FM radio, pager systems, weather satellites, and various IoT wireless protocols. Receive-only (cannot transmit).",
    install: "sudo apt install rtl-sdr",
    usage: [
      "rtl_test -t",
      "rtl_sdr -f 433920000 -s 2000000 -g 40 capture.bin",
      "rtl_fm -f 162.550M -M wbfm -s 200000 -r 48000 - | aplay -r 48000 -f S16_LE",
      "rtl_433 -f 433920000 -R all",
      "rtl_adsb"
    ]
  },
  {
    name: "Ubertooth One",
    description: "Open-source 2.4 GHz wireless development platform designed specifically for Bluetooth monitoring and analysis. The only affordable tool capable of passively sniffing Bluetooth Classic (BR/EDR) and BLE traffic. Supports spectrum analysis of the 2.4 GHz band, Bluetooth packet capture, BLE advertisement sniffing, and Bluetooth connection following across frequency hops.",
    install: "sudo apt install ubertooth",
    usage: [
      "ubertooth-specan -d /dev/ubertooth0",
      "ubertooth-btle -f -c capture.pcapng",
      "ubertooth-btbb -l -t 30",
      "ubertooth-rx -l -t 60",
      "ubertooth-util -v"
    ]
  },
  {
    name: "Flipper Zero",
    description: "Portable multi-tool for pentesters and hardware security researchers. Integrates sub-GHz transceiver (300-928 MHz), 125 kHz RFID reader/writer, NFC (13.56 MHz) reader/emulator, infrared transceiver, Bluetooth LE, GPIO, USB, and iButton support in a pocket-sized device. Used for testing RF security of garage doors, car key fobs, access control systems, IoT sensors, and NFC cards.",
    install: "# Firmware updates via qFlipper desktop app or https://flipperzero.one",
    usage: [
      "# Sub-GHz: Read and replay 433MHz/315MHz signals",
      "# RFID: Read/Write/Emulate 125kHz EM4100/HID/Indala cards",
      "# NFC: Read/Emulate MIFARE Classic/Ultralight/NTAG cards",
      "# IR: Learn and replay infrared remote commands",
      "# BadUSB: Execute HID keystroke injection payloads via USB"
    ]
  },
  {
    name: "Proxmark3",
    description: "Advanced RFID/NFC research and penetration testing tool supporting both 125 kHz (LF) and 13.56 MHz (HF) frequencies. Capable of reading, writing, cloning, and emulating a wide range of RFID and NFC card types including EM4100, HID ProxCard, MIFARE Classic (including hardnested and darkside attacks for key recovery), MIFARE DESFire, iCLASS, and many others. The Proxmark3 RDV4 is the current recommended hardware revision.",
    install: "# Build from source: git clone https://github.com/RfidResearchGroup/proxmark3.git && cd proxmark3 && make clean && make all",
    usage: [
      "pm3 -- auto identifies connected cards",
      "pm3 -- lf em 410x read",
      "pm3 -- lf em 410x clone --id 0102030405",
      "pm3 -- hf mf autopwn",
      "pm3 -- hf mf rdbl --blk 0 -k FFFFFFFFFFFF",
      "pm3 -- hf 14a info"
    ]
  }
];

// ----------------------------------------------------------------------------
// 5. RF_ATTACKS -- Radio Frequency attack techniques
// ----------------------------------------------------------------------------
const RF_ATTACKS = [
  {
    name: "RF Replay Attack",
    frequency: "300 MHz - 928 MHz (ISM bands: 315 MHz, 433.92 MHz, 868 MHz, 915 MHz)",
    description: "An RF replay attack captures a legitimate radio transmission and retransmits it later to trigger the same action. Many simple RF devices such as garage door openers, gate controllers, wireless doorbells, and basic car alarm systems use fixed codes transmitted at common ISM band frequencies. The attacker uses an SDR receiver or dedicated hardware to record the signal, then replays it using a transmitter. Modern rolling-code systems (like KeeLoq and AUT64 used in automotive key fobs) were designed to prevent simple replay by changing the code with each transmission, but even these have been shown to be vulnerable through code-grabbing attacks where the attacker captures and jams a code to prevent the receiver from processing it while saving it for later use.",
    tools: [
      "HackRF One",
      "RTL-SDR (receive only)",
      "Flipper Zero",
      "GNU Radio",
      "YARD Stick One",
      "Universal Radio Hacker (URH)"
    ],
    prevention: [
      "Implement rolling codes or challenge-response protocols",
      "Use encrypted RF communications (AES-128 or better)",
      "Add timestamps or sequence numbers to transmitted messages",
      "Implement frequency hopping spread spectrum (FHSS)",
      "Use bidirectional authentication between transmitter and receiver",
      "Monitor for duplicate or out-of-sequence transmissions"
    ]
  },
  {
    name: "RF Jamming",
    frequency: "Any frequency band (commonly 315 MHz, 433 MHz, 868 MHz, 915 MHz, 2.4 GHz, 5 GHz)",
    description: "RF jamming involves transmitting high-power noise or interference on a target frequency to disrupt legitimate communications. Jamming can be broadband (covering a wide frequency range with noise) or narrowband (targeting a specific frequency or channel with precision). Reactive jamming detects when a legitimate signal is being transmitted and immediately overlays interference, making it more efficient and harder to detect than continuous jamming. RF jamming can disable wireless alarm systems, prevent panic button signals from reaching monitoring stations, disrupt cellular communications, and interfere with GPS navigation. Jamming equipment is illegal to sell, market, or operate in most countries, but inexpensive jammers are widely available online and pose a significant threat to wireless security systems.",
    tools: [
      "HackRF One",
      "YARD Stick One",
      "Custom transmitter circuits",
      "GNU Radio (for signal generation)",
      "Commercial RF signal generators"
    ],
    prevention: [
      "Deploy jamming detection sensors that monitor for elevated noise floors",
      "Use frequency-hopping or spread-spectrum modulation to resist narrowband jamming",
      "Implement wired backup communication paths for critical systems",
      "Design systems to fail secure (alarm on signal loss rather than fail open)",
      "Use anti-jamming protocols that detect and adapt to interference",
      "Report suspected jamming to regulatory authorities (FCC, Ofcom, etc.)"
    ]
  },
  {
    name: "SDR Signal Interception",
    frequency: "1 MHz - 6 GHz (depending on SDR hardware)",
    description: "Software Defined Radio enables passive interception and analysis of virtually any radio signal within its frequency range. Using affordable SDR hardware like RTL-SDR (receive-only, ~$25) or HackRF One (transmit/receive, ~$300), an attacker can monitor unencrypted wireless communications including ISM band IoT sensors, pager systems (POCSAG/FLEX), unencrypted radio communications, ADS-B aircraft transponder data, analog baby monitors, wireless microphones, and utility meter readings (AMR/AMI). The Universal Radio Hacker (URH) tool provides a complete workflow for recording, demodulating, analyzing, and decoding unknown RF protocols. GNU Radio provides a graphical signal processing framework for building custom demodulators and decoders. SDR interception is a critical first step in RF reverse engineering and protocol analysis.",
    tools: [
      "RTL-SDR",
      "HackRF One",
      "GNU Radio Companion",
      "Universal Radio Hacker (URH)",
      "GQRX",
      "SDR# (SDRSharp)",
      "Inspectrum"
    ],
    prevention: [
      "Encrypt all wireless communications using strong algorithms (AES-128/256)",
      "Use frequency-hopping spread spectrum to make interception more difficult",
      "Minimize transmission power to reduce interception range",
      "Implement secure key exchange for encrypted communications",
      "Avoid transmitting sensitive data over unencrypted RF links",
      "Use wired connections instead of wireless where feasible for sensitive data"
    ]
  },
  {
    name: "125 kHz RFID Cloning (EM4100/HID ProxCard)",
    frequency: "125 kHz (Low Frequency RFID)",
    description: "Low-frequency (125 kHz) RFID cards such as EM4100, HID ProxCard II, Indala, and AWID transmit their unique identifier in plaintext without any encryption or authentication. An attacker with an RFID reader (Proxmark3, handheld cloner, or even a smartphone with an external reader) can read the card's ID from a distance of several centimeters to a few inches and write it to a blank writable card (T5577 is the most common writable LF card). The entire cloning process takes under 5 seconds. Cloned cards are indistinguishable from originals to the access control system. Long-range readers with high-gain antennas can read LF cards from up to 1 meter, enabling covert cloning as a target walks past. This vulnerability affects millions of deployed physical access control systems worldwide.",
    tools: [
      "Proxmark3 RDV4",
      "Flipper Zero",
      "Handheld RFID cloner",
      "T5577 writable cards/fobs",
      "iCopy-X"
    ],
    prevention: [
      "Migrate from 125 kHz to 13.56 MHz encrypted card technologies (MIFARE DESFire EV2/EV3, SEOS)",
      "Implement multi-factor access control (card + PIN, card + biometric)",
      "Use card shielding sleeves/wallets to prevent covert reading",
      "Deploy tamper-evident card designs that deter cloning",
      "Implement access logging and anomaly detection for duplicate card use",
      "Consider mobile credentials (BLE/NFC smartphone-based) with mutual authentication"
    ]
  },
  {
    name: "13.56 MHz MIFARE Classic Cloning",
    frequency: "13.56 MHz (High Frequency RFID/NFC)",
    description: "MIFARE Classic cards use the proprietary Crypto-1 cipher for authentication, which was reverse-engineered and publicly broken in 2008. Multiple attacks exist for recovering the encryption keys: the darkside attack recovers a key from a card with at least one default key, the nested attack uses a known key in one sector to recover keys for all other sectors, and the hardnested attack can recover keys even without any known keys. Once all sector keys are recovered, the full card data can be read and cloned to a Chinese 'magic' MIFARE card (Gen1a/Gen2/Gen4 variants that allow writing to normally read-only Block 0 containing the UID). Despite being cryptographically broken for over 15 years, MIFARE Classic remains in widespread use for transit systems, access control, hotel room keys, and payment systems worldwide due to the enormous deployed base and upgrade costs.",
    tools: [
      "Proxmark3 RDV4",
      "Flipper Zero",
      "ACR122U NFC reader",
      "libnfc",
      "MFOC (MIFARE Classic Offline Cracker)",
      "MFCUK (MIFARE Classic Universal Toolkit)"
    ],
    prevention: [
      "Migrate to MIFARE DESFire EV2/EV3 with AES-128 encryption",
      "Implement server-side validation of card data (not just UID checks)",
      "Use diversified keys (unique keys per card derived from a master key)",
      "Implement rolling counters or transaction logs to detect cloned cards",
      "Deploy card blacklisting for known compromised UIDs",
      "Consider transitioning to mobile credentials with asymmetric cryptography"
    ]
  },
  {
    name: "NFC Relay Attack",
    frequency: "13.56 MHz (NFC)",
    description: "An NFC relay attack extends the effective range of NFC communication (normally limited to approximately 4 cm) by using two devices to relay the NFC transaction between a victim's card and a legitimate reader over a long-distance data link (WiFi, cellular, or Bluetooth). One device (the 'mole') is held near the victim's contactless card or smartphone, while another device (the 'proxy') is placed against the target reader. The relay transparently forwards all NFC communication between card and reader, making the reader believe the card is physically present. This attack is effective against contactless payment systems (EMV contactless), NFC-based access control, and any protocol that relies on physical proximity as a security measure. The relay latency is typically fast enough (under 100ms) to not trigger protocol timeouts.",
    tools: [
      "NFCGate (Android app)",
      "Proxmark3 with relay firmware",
      "Two NFC-capable Android phones",
      "libnfc with custom relay scripts",
      "Custom Arduino/ESP32 NFC relay hardware"
    ],
    prevention: [
      "Implement distance bounding protocols that measure round-trip time to detect relaying",
      "Use transaction confirmation on the card/device (e.g., fingerprint or PIN for mobile wallets)",
      "Require additional authentication factors beyond card presence",
      "Enable location-based transaction verification",
      "Implement velocity checks to flag geographically impossible transactions",
      "Use RF shielding (Faraday sleeve) to prevent unauthorized NFC communication"
    ]
  },
  {
    name: "GPS Spoofing",
    frequency: "L1: 1575.42 MHz, L2: 1227.60 MHz, L5: 1176.45 MHz",
    description: "GPS spoofing involves broadcasting counterfeit GPS signals that override the legitimate satellite signals received by a target GPS receiver, causing it to compute an incorrect position, velocity, or time. Civilian GPS signals are unencrypted and unauthenticated, making them inherently vulnerable to spoofing. A sufficiently powerful spoofing signal will be accepted by the receiver in preference to the weaker genuine satellite signals. GPS spoofing can redirect navigation systems, manipulate timestamps in financial and telecommunications systems, affect drone flight paths, falsify vehicle tracking and fleet management data, and disrupt precision agriculture and surveying. The availability of open-source GPS signal simulators (gps-sdr-sim) and affordable SDR transmitters (HackRF One) has lowered the barrier to entry for GPS spoofing attacks significantly.",
    tools: [
      "HackRF One with gps-sdr-sim",
      "gps-sdr-sim",
      "GNU Radio",
      "USRP (Ettus Research)",
      "GPS signal simulator hardware"
    ],
    prevention: [
      "Use multi-constellation receivers (GPS + GLONASS + Galileo + BeiDou) to make spoofing harder",
      "Implement signal authentication when available (Galileo OS-NMA)",
      "Cross-reference GPS with inertial navigation systems (INS) to detect sudden position jumps",
      "Monitor for anomalous GPS signal characteristics (excessive signal strength, doppler inconsistencies)",
      "Use GPS receivers with anti-spoofing capabilities",
      "Implement cryptographic time synchronization (NTS) as a backup to GPS timing"
    ]
  },
  {
    name: "Car Key Fob Relay Attack",
    frequency: "125 kHz (LF wake-up) and 315 MHz / 433.92 MHz (UHF response)",
    description: "A relay attack against passive keyless entry (PKE) and push-button start automotive systems works by extending the short-range LF challenge signal from the car to the key fob using two relay devices. The car continuously broadcasts a low-frequency (125 kHz) challenge signal within a range of approximately 1-2 meters. An attacker positions one relay device near the car and another near the key fob (which could be inside the owner's house, office, or pocket). The relay transparently forwards the LF challenge to the fob and relays the fob's UHF response back to the car, tricking the car into believing the fob is within range. This allows the attacker to unlock the car and start the engine. The entire attack can be performed in under 60 seconds using commercially available relay equipment costing a few hundred dollars. This attack vector is responsible for a significant percentage of modern vehicle thefts.",
    tools: [
      "Commercial relay attack kits",
      "HackRF One (for signal analysis)",
      "Yard Stick One",
      "Custom LF/UHF relay hardware",
      "RTL-SDR (for reconnaissance)"
    ],
    prevention: [
      "Store key fobs in Faraday bags/pouches when not in use",
      "Enable motion-sensor fob features that deactivate the fob when stationary (available on some modern fobs)",
      "Use steering wheel locks or OBD port locks as physical deterrents",
      "Disable passive keyless entry in vehicle settings if possible",
      "Use UWB (Ultra-Wideband) based keyless systems that provide accurate ranging (newer vehicles)",
      "Consider aftermarket CAN bus security systems that detect unauthorized engine start"
    ]
  },
  {
    name: "Garage Door Replay Attack",
    frequency: "300 MHz - 400 MHz (commonly 315 MHz in US, 433.92 MHz in EU)",
    description: "Older garage door openers use fixed codes transmitted on common ISM frequencies, making them trivially vulnerable to replay attacks. The attacker records the transmission from a legitimate remote using an SDR or Flipper Zero and replays it to open the garage door at any later time. While most modern garage door openers use rolling codes (Chamberlain/LiftMaster Security+ 2.0, Genie Intellicode), many older units and some current budget models still use fixed codes. Even rolling-code systems can be attacked through code-grabbing: the attacker jams the receiver while capturing the transmitted code, then captures a second code while replaying the first (so the user sees the door open on the 'second' press). The attacker now possesses one unused valid rolling code. The RollJam attack demonstrated by Samy Kamkar automates this process.",
    tools: [
      "Flipper Zero",
      "HackRF One",
      "YARD Stick One",
      "RTL-SDR (receive/analysis)",
      "RollJam device (custom hardware)",
      "Universal Radio Hacker (URH)"
    ],
    prevention: [
      "Upgrade to a garage door opener with rolling code technology",
      "Use openers with AES-encrypted communications",
      "Implement internet-connected smart openers with app-based authentication",
      "Add a secondary security measure (contact sensor alerting, camera monitoring)",
      "Disable the remote and use smartphone-based control exclusively",
      "Regularly test that the opener rejects replayed codes"
    ]
  },
  {
    name: "MouseJack (Wireless Keyboard/Mouse Injection)",
    frequency: "2.4 GHz (proprietary protocols, not Bluetooth)",
    description: "MouseJack, discovered by Bastille Networks in 2016, is a collection of vulnerabilities affecting non-Bluetooth 2.4 GHz wireless keyboards and mice from major manufacturers including Logitech, Dell, HP, Microsoft, Lenovo, and Amazon. The vulnerabilities allow an attacker within radio range (up to 100 meters with a directional antenna) to inject keystrokes into the victim's computer through the wireless dongle. Many affected devices either transmit keystrokes unencrypted (mice) or have flawed encryption implementations that can be bypassed. The attacker uses a compatible 2.4 GHz transceiver (such as CrazyRadio PA with custom firmware) to identify vulnerable dongles, then injects keystroke packets that the dongle passes to the operating system as if typed on the legitimate keyboard. This enables arbitrary command execution, malware installation, and data exfiltration at typing speeds of hundreds of characters per second.",
    tools: [
      "CrazyRadio PA with nrf-research-firmware",
      "Logitech Unifying receiver research tools",
      "JackIt (injection framework)",
      "MouseJack tools (Bastille Networks)",
      "nRF24LU1+ based hardware"
    ],
    prevention: [
      "Use wired keyboards and mice for sensitive work",
      "Switch to Bluetooth keyboards/mice which are not affected by MouseJack",
      "Apply firmware updates to wireless dongles (Logitech Unifying receiver updates)",
      "Replace vulnerable dongles that have no available firmware fix",
      "Use USB port blockers to prevent unauthorized dongle insertion",
      "Monitor for rapid keystroke injection patterns in endpoint detection systems"
    ]
  },
  {
    name: "Sub-GHz Replay (Flipper Zero / SDR)",
    frequency: "300 MHz - 928 MHz (sub-GHz ISM bands)",
    description: "Sub-GHz replay attacks target the wide variety of consumer, commercial, and industrial devices that communicate on ISM band frequencies below 1 GHz. These include garage doors, gate openers, wireless doorbells, weather stations, tire pressure monitoring systems (TPMS), home automation devices, wireless power outlets, industrial telemetry, and remote-controlled equipment. The Flipper Zero has made sub-GHz replay attacks accessible by providing an integrated transceiver covering 300-928 MHz with built-in protocol decoders for common modulation schemes (AM/OOK, FM/FSK) and encoding formats (fixed code, rolling code identification). For devices using fixed codes, the attack is straightforward: record the signal and replay it. For devices with basic obfuscation but no true rolling codes, the Flipper Zero community has developed protocol-specific decoders that can analyze and regenerate valid signals. True rolling-code systems require more sophisticated attacks but are not immune to code-grabbing techniques.",
    tools: [
      "Flipper Zero",
      "HackRF One",
      "YARD Stick One",
      "RTL-SDR (receive only)",
      "Universal Radio Hacker (URH)",
      "GNU Radio",
      "rfcat"
    ],
    prevention: [
      "Use devices with encrypted rolling code implementations (AES-based)",
      "Avoid fixed-code systems for any security-relevant application",
      "Implement bidirectional authentication in custom RF protocols",
      "Minimize transmission range to reduce the interception window",
      "Add tamper detection and alerting to RF-controlled systems",
      "Transition to IP-based (WiFi/Ethernet) or encrypted Zigbee/Z-Wave control where possible"
    ]
  }
];
