// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// IoT & Embedded Device Security Reference Database
// Protocols, firmware analysis, hardware interfaces, ICS/SCADA, default credentials

// ============================================================================
// IoT PROTOCOLS REFERENCE
// ============================================================================
export const IOT_PROTOCOLS = [
  {
    name: "MQTT",
    full_name: "Message Queuing Telemetry Transport",
    port: 1883,
    tls_port: 8883,
    layer: "Application (TCP)",
    description: "Lightweight publish/subscribe messaging protocol for IoT; designed for constrained devices and low-bandwidth networks",
    packet_format: {
      header: "Fixed header (2+ bytes): packet type (4 bits) + flags (4 bits) + remaining length (1-4 bytes)",
      types: ["CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT"]
    },
    vulnerabilities: [
      { name: "No authentication by default", description: "Many MQTT brokers allow anonymous connections", impact: "Unauthorized access to all published messages" },
      { name: "Plaintext communication", description: "Default port 1883 uses no encryption", impact: "Credential and data interception" },
      { name: "Topic enumeration", description: "Subscribe to '#' wildcard to receive ALL messages", impact: "Full data exfiltration" },
      { name: "Injection via publish", description: "Publish malicious payloads to control topics", impact: "Device manipulation, false sensor data" },
      { name: "Retained message poisoning", description: "Publish retained messages that persist for new subscribers", impact: "Persistent manipulation" },
      { name: "Will message abuse", description: "Set last-will message to broadcast on disconnect", impact: "Spam, misinformation" },
      { name: "Denial of service", description: "Subscribe to all topics, flood with publishes", impact: "Broker overload" },
    ],
    attack_tools: ["mosquitto_pub/sub", "MQTT Explorer", "mqtt-pwn", "Wireshark (MQTT dissector)"],
    pentest_steps: [
      "nmap -sV -p 1883,8883 TARGET",
      "mosquitto_sub -h TARGET -t '#' -v  (subscribe to all topics)",
      "Test anonymous connection: mosquitto_pub -h TARGET -t test -m hello",
      "Enumerate topics by listening on '#' and '$SYS/#'",
      "Check for authentication: try connecting without credentials",
      "Test TLS: mosquitto_sub -h TARGET -p 8883 --cafile ca.crt",
      "Publish to control topics to test write access",
    ]
  },
  {
    name: "CoAP",
    full_name: "Constrained Application Protocol",
    port: 5683,
    dtls_port: 5684,
    layer: "Application (UDP)",
    description: "RESTful protocol for constrained IoT devices; like HTTP but over UDP with low overhead",
    packet_format: {
      header: "4 bytes: version (2 bits) + type (2 bits) + token length (4 bits) + code (8 bits) + message ID (16 bits)",
      types: ["CON (Confirmable)", "NON (Non-confirmable)", "ACK", "RST"],
      methods: ["GET (0.01)", "POST (0.02)", "PUT (0.03)", "DELETE (0.04)"]
    },
    vulnerabilities: [
      { name: "No default security", description: "DTLS is optional; many deployments skip it", impact: "Plaintext communication" },
      { name: "UDP amplification", description: "Spoofed source + large response = DDoS amplification", impact: "Reflected DDoS attacks" },
      { name: "Resource discovery", description: "GET /.well-known/core reveals all resources", impact: "Attack surface enumeration" },
      { name: "No authentication", description: "Many CoAP servers have no access control", impact: "Unauthorized resource access" },
    ],
    attack_tools: ["coap-client (libcoap)", "Copper (Firefox addon)", "Wireshark (CoAP dissector)", "aiocoap (Python)"]
  },
  {
    name: "Zigbee",
    full_name: "IEEE 802.15.4 / Zigbee",
    frequency: "2.4 GHz (16 channels), 868 MHz (1 channel), 915 MHz (10 channels)",
    range: "10-100 meters",
    layer: "Physical + Network + Application",
    description: "Low-power mesh networking protocol for home automation, industrial monitoring, and smart lighting",
    vulnerabilities: [
      { name: "Default trust center key", description: "Well-known default key (5A 69 67 42 65 65 41 6C 6C 69 61 6E 63 65 30 39) used during joining", impact: "Network key interception during device pairing" },
      { name: "Key sniffing during join", description: "Network key is encrypted with trust center key during device join", impact: "If trust center key is known (default), network key is recoverable" },
      { name: "Replay attacks", description: "Captured packets can be replayed (frame counter bypass in some implementations)", impact: "Unauthorized device commands" },
      { name: "Touchlink commissioning exploit", description: "Zigbee Light Link touchlink allows factory reset from proximity", impact: "Steal devices from existing network" },
    ],
    attack_tools: ["KillerBee (ApiMote/RzRaven)", "Attify Zigbee Framework", "Wireshark (Zigbee dissector)", "TI CC2531 USB dongle + zbdump"]
  },
  {
    name: "Z-Wave",
    frequency: "908.42 MHz (US), 868.42 MHz (EU)",
    range: "30-100 meters",
    layer: "Full stack (Physical to Application)",
    description: "Low-power mesh protocol for home automation; proprietary (Silicon Labs)",
    vulnerabilities: [
      { name: "S0 security downgrade", description: "S0 uses known key exchange (all zeros key); S2 is secure but devices may fall back to S0", impact: "Network key recovery via known-plaintext attack on S0 pairing" },
      { name: "No encryption (legacy)", description: "Pre-S0 devices use no encryption at all", impact: "Full packet interception and injection" },
      { name: "Signal jamming", description: "Sub-GHz frequencies can be jammed with SDR", impact: "Denial of service, prevent alarm signals" },
    ],
    attack_tools: ["Z-Wave Sniffer (Silicon Labs UZB stick)", "Scapy-radio", "EZ-Wave", "HackRF One / RTL-SDR"]
  },
  {
    name: "BLE",
    full_name: "Bluetooth Low Energy (4.0+)",
    frequency: "2.4 GHz ISM band (40 channels)",
    range: "Up to 100 meters (typically 10-30m)",
    layer: "Physical + Link + Application (GATT/ATT)",
    description: "Low-power wireless protocol for fitness trackers, smart locks, beacons, medical devices",
    vulnerabilities: [
      { name: "Just Works pairing", description: "No authentication during pairing; MITM possible", impact: "Eavesdropping and device impersonation" },
      { name: "Fixed passkey", description: "Devices with hardcoded passkey (often 000000)", impact: "Trivial pairing bypass" },
      { name: "GATT enumeration", description: "Services and characteristics are readable without pairing", impact: "Device fingerprinting, data leakage" },
      { name: "KNOB attack", description: "Key Negotiation of Bluetooth forces minimum encryption key length", impact: "Brute-force the encryption key" },
      { name: "BLURtooth", description: "Cross-transport key derivation allows overwrite of stronger keys", impact: "MITM on Classic BT using BLE key" },
      { name: "SweynTooth", description: "Family of vulnerabilities in BLE SoC implementations", impact: "Crashes, deadlocks, security bypass in medical/IoT devices" },
      { name: "Replay attacks", description: "Captured BLE commands replayed to device", impact: "Unauthorized lock unlock, device control" },
    ],
    attack_tools: ["nRF Connect (mobile/desktop)", "GATTacker", "BtleJuice", "Ubertooth One", "bettercap (BLE module)", "BlueZ (gatttool, hcitool)"]
  },
  {
    name: "LoRaWAN",
    full_name: "Long Range Wide Area Network",
    frequency: "868 MHz (EU), 915 MHz (US), 923 MHz (Asia)",
    range: "2-15 km urban, up to 50 km rural",
    layer: "Physical (LoRa) + MAC + Application",
    description: "Long-range, low-power protocol for IoT sensors, smart cities, agriculture, utilities",
    vulnerabilities: [
      { name: "ABP replay attacks", description: "Activation By Personalization uses static keys and frame counters that reset on reboot", impact: "Frame counter reset allows packet replay" },
      { name: "Join-accept replay (OTAA)", description: "Captured join-accept can be replayed if DevNonce is reused", impact: "Session key recovery" },
      { name: "Bit-flipping (LoRaWAN 1.0)", description: "No payload integrity for port field; CTR mode allows bit flipping", impact: "Payload manipulation" },
      { name: "Gateway spoofing", description: "Gateways forward to network server; rogue gateway can intercept", impact: "Traffic interception" },
    ],
    attack_tools: ["LoRa SDR (HackRF + gr-lora)", "ChirpStack (for testing)", "LoRaWAN Auditing Framework"]
  },
  {
    name: "Thread",
    full_name: "Thread (IEEE 802.15.4 / 6LoWPAN)",
    frequency: "2.4 GHz",
    range: "10-30 meters (mesh extends range)",
    layer: "IPv6-based mesh networking",
    description: "IP-based mesh protocol for smart home; designed for Matter ecosystem",
    vulnerabilities: [
      { name: "Commissioning window", description: "During device joining, credentials are transmitted (encrypted with commissioning credential)", impact: "If commissioning credential is weak or intercepted, network keys exposed" },
      { name: "Border router attacks", description: "Thread border router bridges Thread to WiFi/Ethernet", impact: "Compromised border router exposes entire Thread network" },
    ],
    attack_tools: ["OpenThread (for research)", "Wireshark (6LoWPAN dissector)", "nRF52840 dongle (packet sniffing)"]
  },
  {
    name: "Matter",
    full_name: "Matter (formerly Project CHIP)",
    transport: "Over WiFi, Thread, or Ethernet",
    layer: "Application layer (runs over IP)",
    description: "Unified smart home standard by CSA (Apple, Google, Amazon, Samsung); aims to replace proprietary protocols",
    vulnerabilities: [
      { name: "New protocol, evolving security", description: "As of 2024, security research is ongoing; implementation bugs likely in early devices", impact: "Unknown until widespread adoption reveals flaws" },
      { name: "Commissioning security", description: "Device onboarding uses QR code or manual pairing code", impact: "Physical access to QR code enables unauthorized pairing" },
      { name: "Multi-admin", description: "Devices can be shared across ecosystems (multi-fabric)", impact: "Complex trust model; one compromised ecosystem affects shared devices" },
    ]
  }
];

// ============================================================================
// FIRMWARE ANALYSIS METHODOLOGY
// ============================================================================
export const FIRMWARE_ANALYSIS = {
  acquisition: [
    { method: "Vendor download", description: "Download firmware update files from manufacturer's website", tools: ["wget", "browser"] },
    { method: "UART/serial dump", description: "Connect to UART port and dump flash via bootloader (U-Boot)", tools: ["USB-TTL adapter", "minicom/screen", "U-Boot md/cp commands"] },
    { method: "SPI flash dump", description: "Desolder or clip SPI flash chip and read contents", tools: ["Flashrom", "CH341A programmer", "SOIC8 clip"] },
    { method: "JTAG/SWD dump", description: "Use debug interface to dump flash memory", tools: ["OpenOCD", "J-Link", "Bus Pirate"] },
    { method: "Network capture", description: "Intercept firmware update download (MITM)", tools: ["mitmproxy", "Burp Suite", "tcpdump"] },
    { method: "Mobile app extraction", description: "Firmware may be embedded in companion mobile app", tools: ["apktool", "jadx (Android)", "Hopper (iOS)"] },
  ],
  extraction: [
    { step: "Identify format", command: "file firmware.bin", description: "Determine file type (ELF, raw, compressed)" },
    { step: "Entropy analysis", command: "binwalk -E firmware.bin", description: "High entropy = encrypted or compressed" },
    { step: "Signature scan", command: "binwalk firmware.bin", description: "Find embedded filesystems, compressed data, certificates" },
    { step: "Extract filesystem", command: "binwalk -e firmware.bin", description: "Extract all identified components" },
    { step: "Mount filesystem", command: "sudo mount -o loop rootfs.squashfs /mnt/fw", description: "Mount extracted filesystem image" },
    { step: "Identify filesystem type", command: "file rootfs.img", description: "SquashFS, JFFS2, YAFFS2, ext4, cramfs, UBI" },
    { step: "unsquashfs", command: "unsquashfs rootfs.squashfs", description: "Extract SquashFS filesystem (most common in IoT)" },
    { step: "jefferson (JFFS2)", command: "jefferson firmware.jffs2 -d output/", description: "Extract JFFS2 filesystem" },
    { step: "ubi_reader", command: "ubireader_extract_images firmware.ubi", description: "Extract UBI/UBIFS images" },
  ],
  analysis: [
    { target: "Password hashes", command: "cat etc/shadow", description: "Check for default/weak passwords" },
    { target: "SSH keys", command: "find . -name 'id_rsa' -o -name '*.pem'", description: "Hardcoded private keys" },
    { target: "Certificates", command: "find . -name '*.crt' -o -name '*.pem' -o -name '*.key'", description: "TLS certificates and keys" },
    { target: "Config files", command: "find . -name '*.conf' -o -name '*.cfg' -o -name '*.ini'", description: "Service configurations" },
    { target: "Credentials in code", command: "grep -r 'password\\|passwd\\|secret\\|api_key' .", description: "Hardcoded secrets" },
    { target: "URLs/IPs", command: "grep -rEo 'https?://[^ ]+' . | sort -u", description: "Backend servers, update URLs, C2" },
    { target: "Binary analysis", command: "file usr/bin/* | grep ELF", description: "Identify architecture for further analysis" },
    { target: "Web server config", command: "cat etc/lighttpd/* etc/nginx/* etc/httpd/*", description: "Web interface configuration" },
    { target: "Startup scripts", command: "cat etc/init.d/* etc/rc.local", description: "Services started at boot" },
    { target: "Cron jobs", command: "cat etc/crontab var/spool/cron/*", description: "Scheduled tasks" },
  ],
  emulation: [
    { tool: "QEMU user mode", command: "qemu-arm-static -L . ./usr/bin/httpd", description: "Emulate single binary with host kernel" },
    { tool: "QEMU system mode", command: "qemu-system-mipsel -M malta -kernel vmlinux -hda rootfs.ext2 -append 'root=/dev/sda console=ttyS0'", description: "Full system emulation" },
    { tool: "Firmadyne", description: "Automated IoT firmware emulation and analysis platform", url: "github.com/firmadyne/firmadyne" },
    { tool: "FirmAE", description: "Improved firmware analysis and emulation", url: "github.com/pr0v3rbs/FirmAE" },
    { tool: "ARM-X", description: "ARM firmware emulation framework", url: "github.com/therealsaumil/armx" },
    { tool: "Unicorn Engine", description: "Emulate specific functions without full OS", url: "unicorn-engine.org" },
  ],
  tools_summary: [
    { name: "Binwalk", description: "Firmware extraction and analysis", category: "extraction" },
    { name: "Firmware Mod Kit", description: "Extract, modify, and rebuild firmware images", category: "extraction" },
    { name: "Ghidra", description: "Disassemble and decompile firmware binaries", category: "analysis" },
    { name: "radare2/rizin", description: "CLI reverse engineering framework", category: "analysis" },
    { name: "firmwalker", description: "Search extracted firmware for interesting files", category: "analysis" },
    { name: "EMBA", description: "Embedded firmware analyzer (automated)", category: "analysis" },
    { name: "ByteSweep", description: "IoT firmware security analysis", category: "analysis" },
  ]
};

// ============================================================================
// HARDWARE INTERFACES
// ============================================================================
export const HARDWARE_INTERFACES = [
  {
    name: "UART",
    full_name: "Universal Asynchronous Receiver-Transmitter",
    pins: ["TX (Transmit)", "RX (Receive)", "GND (Ground)", "VCC (optional, do NOT connect to adapter)"],
    description: "Serial debug console; most IoT devices have UART pads on PCB for development/debug access",
    common_baud_rates: [9600, 19200, 38400, 57600, 115200, 460800, 921600],
    identification: [
      "Look for 4 pads/pins in a row on PCB (often near processor or edge)",
      "Use multimeter: GND = 0V, VCC = 3.3V/5V, TX = fluctuating voltage (data being sent), RX = steady high",
      "Use logic analyzer or JTAGulator to auto-detect baud rate",
      "Labels on PCB: TP1, TP2, J1 (test points)",
    ],
    connection: [
      "Connect GND to GND",
      "Connect device TX to adapter RX",
      "Connect device RX to adapter TX",
      "NEVER connect VCC (adapter provides its own power)",
      "Match voltage levels (3.3V vs 5V) — use level shifter if needed",
    ],
    tools: [
      { name: "USB-TTL adapter (CP2102/FT232/CH340)", description: "USB to UART converter; ~$3-5", connection: "TX/RX/GND" },
      { name: "Bus Pirate", description: "Multi-protocol tool; UART + SPI + I2C + JTAG", connection: "Any protocol" },
      { name: "minicom", command: "minicom -D /dev/ttyUSB0 -b 115200", description: "Linux serial terminal" },
      { name: "screen", command: "screen /dev/ttyUSB0 115200", description: "Simple serial terminal" },
      { name: "PuTTY", description: "Windows serial terminal", connection: "COM port" },
      { name: "JTAGulator", description: "Auto-detect UART/JTAG pinouts", url: "grandideastudio.com" },
    ],
    attacks: [
      "Get root shell via serial console (many devices drop to root without password)",
      "Interrupt U-Boot bootloader (press key during boot countdown) to modify boot args",
      "Dump flash memory via U-Boot commands (md, cp)",
      "Change root password by modifying /etc/shadow in U-Boot",
      "Boot from TFTP/NFS to bypass filesystem protections",
    ]
  },
  {
    name: "JTAG",
    full_name: "Joint Test Action Group (IEEE 1149.1)",
    pins: ["TDI (Test Data In)", "TDO (Test Data Out)", "TCK (Test Clock)", "TMS (Test Mode Select)", "TRST (Test Reset, optional)", "GND"],
    description: "Debug and test interface for ICs; provides full CPU control, memory access, and flash programming",
    identification: [
      "Look for 10-pin or 20-pin header on PCB (standard ARM JTAG headers)",
      "Unpopulated pads in a grid pattern near processor",
      "Use JTAGulator or manual probing to identify pins",
      "Check processor datasheet for JTAG pin assignments",
    ],
    capabilities: [
      "Full CPU control (halt, step, run, set breakpoints)",
      "Read/write all memory (RAM, flash, registers)",
      "Dump entire firmware from flash",
      "Bypass boot security (read-protect bits may prevent this on some MCUs)",
      "Debug running firmware in real-time",
      "Program new firmware",
      "Boundary scan (test PCB connections between ICs)",
    ],
    tools: [
      { name: "OpenOCD", description: "Open-source JTAG debugger", command: "openocd -f interface/jlink.cfg -f target/stm32f1x.cfg" },
      { name: "J-Link (Segger)", description: "Professional JTAG/SWD debugger; fast, reliable", price: "$60 (EDU) - $1000+" },
      { name: "Bus Pirate", description: "Budget multi-protocol tool with JTAG support", price: "~$30" },
      { name: "ST-Link", description: "STM32 programmer/debugger", price: "~$5 (clone)" },
      { name: "JTAGulator", description: "Auto-identify JTAG/UART pinouts (20-channel)", price: "~$150" },
      { name: "GDB (with OpenOCD)", command: "arm-none-eabi-gdb -ex 'target remote :3333'", description: "Debug firmware via JTAG" },
    ]
  },
  {
    name: "SPI",
    full_name: "Serial Peripheral Interface",
    pins: ["MOSI (Master Out Slave In)", "MISO (Master In Slave Out)", "SCLK (Serial Clock)", "CS/SS (Chip Select)", "GND"],
    description: "Synchronous serial bus for flash memory chips, sensors, and displays; IoT devices often use SPI flash for firmware storage",
    common_chips: [
      { part: "W25Q32/64/128", description: "Winbond SPI NOR flash; most common in IoT routers", package: "SOIC-8" },
      { part: "MX25L64/128", description: "Macronix SPI flash", package: "SOIC-8" },
      { part: "AT25SF/DF", description: "Adesto (Microchip) SPI flash", package: "SOIC-8" },
      { part: "EN25Q/QH", description: "EON/Eon Silicon SPI flash", package: "SOIC-8" },
    ],
    tools: [
      { name: "CH341A USB programmer", description: "Cheapest SPI flash programmer (~$3)", connection: "SOIC-8 clip or socket" },
      { name: "Flashrom", command: "flashrom -p ch341a_spi -r firmware.bin", description: "Read/write SPI flash" },
      { name: "Bus Pirate", description: "Multi-protocol; can read SPI flash", connection: "MOSI/MISO/SCLK/CS" },
      { name: "SOIC-8 clip", description: "Clip onto flash chip without desoldering", price: "~$5" },
      { name: "Saleae Logic Analyzer", description: "Capture and decode SPI traffic", price: "$10 (clone) - $500 (genuine)" },
    ],
    attacks: [
      "Read firmware directly from SPI flash chip (bypass all software protections)",
      "Modify firmware and write back (backdoor, remove auth)",
      "Clone device by reading and duplicating flash contents",
      "Analyze SPI communication between processor and external devices",
    ]
  },
  {
    name: "I2C",
    full_name: "Inter-Integrated Circuit",
    pins: ["SDA (Serial Data)", "SCL (Serial Clock)", "GND"],
    description: "Two-wire bus for connecting low-speed peripherals; used for EEPROMs, sensors, RTCs, displays",
    address_range: "7-bit (0x00-0x7F) or 10-bit addressing",
    tools: [
      { name: "Bus Pirate", description: "I2C bus scanning and communication", command: "(1) → scan for devices" },
      { name: "i2cdetect (Linux)", command: "i2cdetect -y 1", description: "Scan I2C bus for devices" },
      { name: "i2cdump", command: "i2cdump -y 1 0x50", description: "Dump EEPROM contents at address 0x50" },
      { name: "Saleae Logic Analyzer", description: "Capture and decode I2C traffic" },
    ],
    attacks: [
      "Read EEPROM contents (may contain credentials, config, serial numbers)",
      "Write EEPROM to modify device configuration",
      "Impersonate I2C slave device (inject false sensor data)",
      "Sniff I2C bus traffic between components",
    ]
  },
  {
    name: "SWD",
    full_name: "Serial Wire Debug",
    pins: ["SWDIO (Data I/O)", "SWCLK (Clock)", "GND", "RESET (optional)"],
    description: "ARM-specific two-wire debug interface; alternative to JTAG with fewer pins; used on most ARM Cortex-M microcontrollers",
    tools: [
      { name: "ST-Link V2", description: "Most common SWD debugger for STM32", price: "~$5 (clone)" },
      { name: "J-Link", description: "Professional SWD/JTAG debugger", price: "$60 (EDU)" },
      { name: "DAPLink", description: "Open-source CMSIS-DAP debugger", price: "~$10" },
      { name: "OpenOCD", command: "openocd -f interface/stlink.cfg -f target/stm32f4x.cfg", description: "Open-source debug server" },
      { name: "pyOCD", command: "pyocd gdb -t stm32f407vg", description: "Python-based ARM debugger" },
    ],
    capabilities: [
      "Same as JTAG: full CPU control, memory access, flash dump/program",
      "Only 2 pins needed (vs 4-5 for JTAG)",
      "Supported on all ARM Cortex-M, most Cortex-A",
      "Can read/write all memory including flash and peripherals",
    ]
  }
];

// ============================================================================
// OWASP IoT TOP 10
// ============================================================================
export const OWASP_IOT_TOP_10 = [
  {
    id: "I1",
    name: "Weak, Guessable, or Hardcoded Passwords",
    description: "Use of easily brute forced, publicly available, or unchangeable credentials including backdoors in firmware or client software that grants unauthorized access",
    examples: [
      "Default admin/admin or admin/password credentials",
      "Hardcoded backdoor accounts in firmware",
      "No password change required on first use",
      "No account lockout after failed attempts",
      "Weak password policy allowing short or simple passwords",
    ],
    mitigations: [
      "Require password change on first use",
      "Enforce strong password policy",
      "Implement account lockout",
      "No hardcoded credentials in firmware",
      "Support two-factor authentication where possible",
    ]
  },
  {
    id: "I2",
    name: "Insecure Network Services",
    description: "Unneeded or insecure network services running on the device, especially those exposed to the internet, that compromise confidentiality, integrity, or availability",
    examples: [
      "Telnet service running with default credentials",
      "UPnP exposing internal services to the internet",
      "Debug ports (JTAG over network) left open",
      "Unnecessary services running (FTP, TFTP, SSH with weak config)",
      "Buffer overflow in network service daemon",
    ],
    mitigations: [
      "Disable unnecessary services",
      "Use secure protocols (SSH instead of Telnet, HTTPS instead of HTTP)",
      "Implement firewall rules on device",
      "Regular security testing of exposed services",
    ]
  },
  {
    id: "I3",
    name: "Insecure Ecosystem Interfaces",
    description: "Insecure web, backend API, cloud, or mobile interfaces in the ecosystem outside the device that allow compromise",
    examples: [
      "Web interface with XSS, CSRF, SQL injection",
      "API with no authentication or broken auth",
      "Cloud backend with IDOR vulnerabilities",
      "Mobile app storing credentials in plaintext",
      "Lack of TLS on API communications",
    ],
    mitigations: [
      "Apply standard web security practices to all interfaces",
      "Use OAuth 2.0 / API keys with rate limiting",
      "Implement input validation everywhere",
      "Encrypt all communications with TLS 1.2+",
    ]
  },
  {
    id: "I4",
    name: "Lack of Secure Update Mechanism",
    description: "Lack of ability to securely update the device including lack of firmware validation, lack of encrypted delivery, lack of anti-rollback, and lack of notifications",
    examples: [
      "Firmware updates over HTTP (no TLS)",
      "No signature verification on firmware images",
      "Update file can be tampered with in transit",
      "No rollback protection (downgrade to vulnerable version)",
      "No automatic update capability",
    ],
    mitigations: [
      "Cryptographically sign firmware images",
      "Verify signatures before applying updates",
      "Deliver updates over encrypted channel (TLS)",
      "Implement anti-rollback with version counters",
      "Support automatic update with user notification",
    ]
  },
  {
    id: "I5",
    name: "Use of Insecure or Outdated Components",
    description: "Use of deprecated or insecure software components or libraries including insecure customization of OS platform, and use of third-party software or hardware from a compromised supply chain",
    examples: [
      "Outdated Linux kernel with known CVEs",
      "Old version of OpenSSL with Heartbleed",
      "Busybox with known vulnerabilities",
      "Deprecated cryptographic libraries",
      "Unpatched web server (lighttpd, GoAhead, Boa)",
    ],
    mitigations: [
      "Maintain software bill of materials (SBOM)",
      "Regular vulnerability scanning of components",
      "Timely patching process",
      "Use supported, maintained software versions",
    ]
  },
  {
    id: "I6",
    name: "Insufficient Privacy Protections",
    description: "User personal information stored on the device or in the ecosystem that is used insecurely, improperly, or without permission",
    examples: [
      "Collecting more data than necessary",
      "Sharing data with third parties without consent",
      "Insecure storage of personal data on device",
      "No data anonymization",
      "No privacy policy or user consent mechanism",
    ],
    mitigations: [
      "Collect only necessary data (data minimization)",
      "Encrypt personal data at rest and in transit",
      "Provide clear privacy policy",
      "Allow users to delete their data",
    ]
  },
  {
    id: "I7",
    name: "Insecure Data Transfer and Storage",
    description: "Lack of encryption or access control of sensitive data anywhere within the ecosystem including at rest, in transit, or during processing",
    examples: [
      "Plaintext transmission of credentials",
      "Unencrypted storage of sensitive data in flash",
      "API keys stored in plaintext on device",
      "No TLS on cloud communication",
      "Sensitive data in debug logs",
    ],
    mitigations: [
      "Encrypt all sensitive data at rest (AES-256)",
      "Use TLS 1.2+ for all network communication",
      "Secure key storage (hardware security module if available)",
      "Minimize logging of sensitive data",
    ]
  },
  {
    id: "I8",
    name: "Lack of Device Management",
    description: "Lack of security support on devices deployed in production including asset management, update management, secure decommissioning, systems monitoring, and response capabilities",
    examples: [
      "No way to remotely manage or update deployed devices",
      "No inventory of deployed devices",
      "No monitoring for anomalous behavior",
      "No secure factory reset / decommission process",
      "No logging or audit trail",
    ],
    mitigations: [
      "Implement device management platform",
      "Support remote configuration and updates",
      "Monitor device health and behavior",
      "Secure decommissioning process (data wipe)",
    ]
  },
  {
    id: "I9",
    name: "Insecure Default Settings",
    description: "Devices or systems shipped with insecure default settings or lack the ability to restrict settings from being made more secure",
    examples: [
      "All ports open by default",
      "Default WiFi with no password",
      "Debug mode enabled by default",
      "Permissive firewall rules",
      "UPnP enabled by default",
    ],
    mitigations: [
      "Ship with minimum necessary services enabled",
      "Require configuration on first use",
      "Disable debug interfaces in production",
      "Default to most secure settings",
    ]
  },
  {
    id: "I10",
    name: "Lack of Physical Hardening",
    description: "Lack of physical hardening measures allowing potential attackers to gain sensitive information that can facilitate a future remote attack or take local control of the device",
    examples: [
      "Exposed UART/JTAG/SPI debug ports",
      "Removable storage with unencrypted data",
      "No tamper detection",
      "Readable PCB markings revealing chip models",
      "External flash chip easily accessible",
    ],
    mitigations: [
      "Disable or remove debug ports in production",
      "Use read-protect on microcontrollers",
      "Encrypt external storage",
      "Implement tamper detection and response",
      "Use epoxy or conformal coating over debug pads",
    ]
  }
];

// ============================================================================
// ICS / SCADA PROTOCOLS
// ============================================================================
export const ICS_PROTOCOLS = [
  {
    name: "Modbus",
    port: 502,
    description: "Serial/TCP protocol for industrial PLCs; no authentication, no encryption",
    variants: ["Modbus RTU (serial RS-485)", "Modbus ASCII (serial)", "Modbus TCP (Ethernet)"],
    vulnerabilities: [
      "No authentication (any client can read/write registers)",
      "No encryption (all data in plaintext)",
      "No integrity checking beyond CRC (TCP has none)",
      "Device ID enumeration",
      "Register read/write without authorization",
      "Function code scanning reveals device capabilities",
    ],
    attack_tools: ["mbtget", "Metasploit (modbusclient)", "modbus-cli", "PyModbus", "Wireshark (Modbus dissector)"],
    common_function_codes: [
      { code: 1, name: "Read Coils", description: "Read discrete outputs (ON/OFF)" },
      { code: 2, name: "Read Discrete Inputs", description: "Read discrete inputs" },
      { code: 3, name: "Read Holding Registers", description: "Read analog output registers" },
      { code: 4, name: "Read Input Registers", description: "Read analog input registers" },
      { code: 5, name: "Write Single Coil", description: "Write single discrete output" },
      { code: 6, name: "Write Single Register", description: "Write single analog output" },
      { code: 15, name: "Write Multiple Coils", description: "Write multiple discrete outputs" },
      { code: 16, name: "Write Multiple Registers", description: "Write multiple analog outputs" },
    ]
  },
  {
    name: "DNP3",
    full_name: "Distributed Network Protocol 3",
    port: 20000,
    description: "Protocol for electric/water utility SCADA; supports authentication (Secure Authentication v5)",
    vulnerabilities: [
      "Legacy deployments have no authentication",
      "Sequence number prediction",
      "Man-in-the-middle (no TLS by default)",
      "Unsolicited response spoofing",
    ]
  },
  {
    name: "OPC UA",
    full_name: "Open Platform Communications Unified Architecture",
    port: 4840,
    description: "Modern industrial protocol; supports encryption and authentication (better than legacy OPC DA)",
    vulnerabilities: [
      "Implementation bugs in OPC UA stacks",
      "Anonymous authentication often enabled",
      "Self-signed certificates accepted by default",
      "Discovery endpoint information disclosure",
    ]
  },
  {
    name: "EtherNet/IP",
    port: 44818,
    description: "Industrial Ethernet protocol by ODVA; used by Allen-Bradley/Rockwell PLCs",
    vulnerabilities: [
      "No authentication in CIP (Common Industrial Protocol)",
      "Device enumeration via ListIdentity",
      "Program upload/download without authorization",
    ]
  },
  {
    name: "BACnet",
    port: 47808,
    description: "Building Automation and Control Networks; used in HVAC, lighting, access control",
    vulnerabilities: [
      "No authentication by default",
      "Device discovery via Who-Is broadcast",
      "Read/write building control parameters without auth",
      "Can affect physical safety (HVAC, fire systems)",
    ]
  },
  {
    name: "S7comm",
    port: 102,
    description: "Siemens S7 PLC communication protocol; proprietary",
    vulnerabilities: [
      "No authentication in S7comm (legacy)",
      "S7comm+ adds TLS but many old PLCs don't support it",
      "PLC start/stop commands without authorization",
      "Program upload/download",
    ],
    attack_tools: ["Metasploit (S7 modules)", "Snap7 library", "PLCScan", "Wireshark (S7comm dissector)"]
  }
];

// ============================================================================
// DEFAULT CREDENTIALS DATABASE
// ============================================================================
export const DEFAULT_CREDENTIALS = [
  // Routers
  { vendor: "Cisco", device: "IOS Router", username: "cisco", password: "cisco", category: "router" },
  { vendor: "Cisco", device: "IOS Router (enable)", username: "", password: "cisco", category: "router" },
  { vendor: "MikroTik", device: "RouterOS", username: "admin", password: "(blank)", category: "router" },
  { vendor: "Ubiquiti", device: "EdgeRouter/UniFi", username: "ubnt", password: "ubnt", category: "router" },
  { vendor: "TP-Link", device: "Home Router", username: "admin", password: "admin", category: "router" },
  { vendor: "Netgear", device: "Home Router", username: "admin", password: "password", category: "router" },
  { vendor: "D-Link", device: "Home Router", username: "admin", password: "(blank)", category: "router" },
  { vendor: "Linksys", device: "Home Router", username: "admin", password: "admin", category: "router" },
  { vendor: "ASUS", device: "Home Router", username: "admin", password: "admin", category: "router" },
  { vendor: "Huawei", device: "Home Router", username: "admin", password: "admin", category: "router" },
  { vendor: "ZTE", device: "Home Router", username: "admin", password: "admin", category: "router" },
  { vendor: "Zyxel", device: "Router/Firewall", username: "admin", password: "1234", category: "router" },
  { vendor: "Juniper", device: "Junos", username: "root", password: "(blank)", category: "router" },
  { vendor: "Aruba", device: "Controller", username: "admin", password: "admin", category: "router" },
  { vendor: "Fortinet", device: "FortiGate", username: "admin", password: "(blank)", category: "router" },
  { vendor: "Palo Alto", device: "PAN-OS", username: "admin", password: "admin", category: "router" },
  { vendor: "SonicWall", device: "Firewall", username: "admin", password: "password", category: "router" },
  { vendor: "pfSense", device: "Firewall", username: "admin", password: "pfsense", category: "router" },
  { vendor: "OPNsense", device: "Firewall", username: "root", password: "opnsense", category: "router" },

  // Cameras
  { vendor: "Hikvision", device: "IP Camera/NVR", username: "admin", password: "12345", category: "camera" },
  { vendor: "Dahua", device: "IP Camera/NVR", username: "admin", password: "admin", category: "camera" },
  { vendor: "Axis", device: "Network Camera", username: "root", password: "pass", category: "camera" },
  { vendor: "Samsung", device: "IP Camera", username: "admin", password: "4321", category: "camera" },
  { vendor: "Foscam", device: "IP Camera", username: "admin", password: "(blank)", category: "camera" },
  { vendor: "Amcrest", device: "IP Camera", username: "admin", password: "admin", category: "camera" },
  { vendor: "Reolink", device: "IP Camera", username: "admin", password: "(blank)", category: "camera" },
  { vendor: "Vivotek", device: "IP Camera", username: "root", password: "(blank)", category: "camera" },
  { vendor: "Bosch", device: "IP Camera", username: "service", password: "(blank)", category: "camera" },
  { vendor: "Uniview", device: "IP Camera", username: "admin", password: "123456", category: "camera" },

  // NAS/Storage
  { vendor: "Synology", device: "DiskStation", username: "admin", password: "(blank)", category: "nas" },
  { vendor: "QNAP", device: "NAS", username: "admin", password: "admin", category: "nas" },
  { vendor: "Western Digital", device: "My Cloud", username: "admin", password: "(blank)", category: "nas" },
  { vendor: "Drobo", device: "NAS", username: "admin", password: "(blank)", category: "nas" },
  { vendor: "Buffalo", device: "LinkStation", username: "admin", password: "password", category: "nas" },

  // Printers
  { vendor: "HP", device: "Printer EWS", username: "admin", password: "(blank)", category: "printer" },
  { vendor: "Xerox", device: "Printer", username: "admin", password: "1111", category: "printer" },
  { vendor: "Canon", device: "Printer", username: "ADMIN", password: "canon", category: "printer" },
  { vendor: "Brother", device: "Printer", username: "admin", password: "access", category: "printer" },
  { vendor: "Epson", device: "Printer", username: "admin", password: "(blank)", category: "printer" },
  { vendor: "Konica Minolta", device: "Printer", username: "admin", password: "administrator", category: "printer" },
  { vendor: "Ricoh", device: "Printer", username: "admin", password: "(blank)", category: "printer" },
  { vendor: "Lexmark", device: "Printer", username: "(none)", password: "(blank)", category: "printer" },

  // Smart Home
  { vendor: "Ring", device: "Doorbell/Camera", username: "(email)", password: "(user-set)", category: "smarthome", note: "No default; uses Amazon account" },
  { vendor: "Nest", device: "Thermostat/Camera", username: "(email)", password: "(user-set)", category: "smarthome", note: "No default; uses Google account" },
  { vendor: "Philips Hue", device: "Bridge", username: "", password: "(button press auth)", category: "smarthome" },
  { vendor: "SmartThings", device: "Hub", username: "(email)", password: "(user-set)", category: "smarthome" },
  { vendor: "Wyze", device: "Camera", username: "(email)", password: "(user-set)", category: "smarthome" },

  // Industrial / SCADA
  { vendor: "Siemens", device: "S7-300/400 PLC", username: "", password: "(no auth)", category: "ics" },
  { vendor: "Allen-Bradley", device: "ControlLogix", username: "", password: "(no auth)", category: "ics" },
  { vendor: "Schneider Electric", device: "Modicon M340", username: "USER", password: "USER", category: "ics" },
  { vendor: "GE", device: "PACSystemsRX3i", username: "", password: "(no auth)", category: "ics" },
  { vendor: "ABB", device: "AC500 PLC", username: "admin", password: "admin", category: "ics" },
  { vendor: "Honeywell", device: "Experion PKS", username: "ADMIN", password: "ADMIN", category: "ics" },
  { vendor: "Yokogawa", device: "CENTUM VP", username: "", password: "(no auth)", category: "ics" },

  // Network Management
  { vendor: "Dell iDRAC", device: "Server BMC", username: "root", password: "calvin", category: "management" },
  { vendor: "HP iLO", device: "Server BMC", username: "Administrator", password: "(on label)", category: "management" },
  { vendor: "Supermicro", device: "IPMI/BMC", username: "ADMIN", password: "ADMIN", category: "management" },
  { vendor: "APC", device: "UPS NMC", username: "apc", password: "apc", category: "management" },
  { vendor: "Raritan", device: "PDU", username: "admin", password: "raritan", category: "management" },
  { vendor: "Avocent", device: "KVM", username: "Admin", password: "admin", category: "management" },

  // VoIP
  { vendor: "Polycom", device: "VoIP Phone", username: "Polycom", password: "456", category: "voip" },
  { vendor: "Cisco", device: "IP Phone", username: "admin", password: "admin", category: "voip" },
  { vendor: "Yealink", device: "IP Phone", username: "admin", password: "admin", category: "voip" },
  { vendor: "Grandstream", device: "IP Phone", username: "admin", password: "admin", category: "voip" },
  { vendor: "Avaya", device: "IP Phone", username: "admin", password: "admin", category: "voip" },
  { vendor: "Asterisk", device: "PBX", username: "admin", password: "amp111", category: "voip" },
  { vendor: "FreePBX", device: "PBX", username: "admin", password: "admin", category: "voip" },

  // Embedded Linux / SBCs
  { vendor: "Raspberry Pi", device: "Raspberry Pi OS", username: "pi", password: "raspberry", category: "embedded" },
  { vendor: "BeagleBone", device: "Debian", username: "debian", password: "temppwd", category: "embedded" },
  { vendor: "Orange Pi", device: "Armbian", username: "root", password: "1234", category: "embedded" },
  { vendor: "OpenWrt", device: "Router Firmware", username: "root", password: "(blank)", category: "embedded" },
  { vendor: "DD-WRT", device: "Router Firmware", username: "root", password: "admin", category: "embedded" },
  { vendor: "Tomato", device: "Router Firmware", username: "admin", password: "admin", category: "embedded" },

  // Access Points / WiFi
  { vendor: "Ruckus", device: "Access Point", username: "super", password: "sp-admin", category: "wifi" },
  { vendor: "Aruba", device: "Instant AP", username: "admin", password: "admin", category: "wifi" },
  { vendor: "Ubiquiti", device: "UniFi AP", username: "ubnt", password: "ubnt", category: "wifi" },
  { vendor: "Meraki", device: "Cloud AP", username: "(cloud)", password: "(cloud managed)", category: "wifi" },
  { vendor: "EnGenius", device: "Access Point", username: "admin", password: "admin", category: "wifi" },
  { vendor: "Cambium", device: "ePMP", username: "admin", password: "admin", category: "wifi" },

  // Databases (commonly on IoT backends)
  { vendor: "MongoDB", device: "Database", username: "(none)", password: "(no auth)", category: "database", note: "No auth by default; binds 0.0.0.0" },
  { vendor: "Redis", device: "Cache/DB", username: "(none)", password: "(no auth)", category: "database", note: "No auth by default" },
  { vendor: "CouchDB", device: "Database", username: "admin", password: "admin", category: "database" },
  { vendor: "Elasticsearch", device: "Search Engine", username: "(none)", password: "(no auth)", category: "database", note: "No auth before v8" },
  { vendor: "InfluxDB", device: "Time Series DB", username: "admin", password: "admin", category: "database" },
  { vendor: "Mosquitto", device: "MQTT Broker", username: "(none)", password: "(no auth)", category: "database", note: "Anonymous by default" },
];

// ============================================================================
// AUTOMOTIVE SECURITY
// ============================================================================
export const AUTOMOTIVE_SECURITY = {
  can_bus: {
    description: "Controller Area Network — primary vehicle communication bus",
    speed: "Up to 1 Mbps (CAN 2.0) / 8 Mbps (CAN FD)",
    frame_format: {
      fields: ["Arbitration ID (11 or 29 bits)", "Control/DLC (4 bits = data length)", "Data (0-8 bytes)", "CRC (15 bits)"],
      note: "No source address, no authentication — any ECU can send any message"
    },
    attack_vectors: [
      { attack: "Passive sniffing", description: "Read all CAN traffic via OBD-II port or direct bus connection", tools: ["candump", "SavvyCAN", "CANalyst-II"] },
      { attack: "Message injection", description: "Send crafted CAN frames to control vehicle functions", tools: ["cansend", "CANtact", "ValueCAN"] },
      { attack: "Replay attack", description: "Capture and replay CAN messages to trigger actions", tools: ["canplayer", "SavvyCAN"] },
      { attack: "Fuzzing", description: "Send random CAN IDs/data to discover undocumented functions", tools: ["caringcaribou", "cangen"] },
      { attack: "Bus-off attack", description: "Force ECU into error state by manipulating error counters", impact: "Disable specific ECU (e.g., ABS, airbags)" },
      { attack: "Diagnostic commands", description: "Use UDS/OBD-II diagnostic services for privileged operations", tools: ["UDS scanner", "python-can"] },
    ],
    tools: [
      { name: "SocketCAN (Linux)", description: "Linux kernel CAN support", commands: ["candump can0", "cansend can0 123#DEADBEEF", "cangen can0"] },
      { name: "SavvyCAN", description: "Cross-platform CAN bus analyzer GUI" },
      { name: "CANtact", description: "Open-source USB CAN adapter (~$60)" },
      { name: "Caringcaribou", description: "Vehicle security analysis tool" },
      { name: "ICSim", description: "Instrument Cluster Simulator for practice" },
    ]
  },
  key_fob_attacks: [
    { attack: "Relay attack", description: "Amplify key fob signal to trick car into thinking fob is nearby", tools: ["Proxmark3", "HackRF One", "Yard Stick One"], prevention: "Faraday bag for keys, UWB ranging in newer cars" },
    { attack: "Rolljam", description: "Jam + capture rolling code; replay when owner tries again", tools: ["HackRF One", "Yard Stick One", "custom firmware"], prevention: "Dual-code systems, UWB" },
    { attack: "Signal cloning (fixed code)", description: "Copy fixed code remotes (older vehicles, garage doors)", tools: ["RTL-SDR", "HackRF One", "Flipper Zero"], prevention: "Use rolling codes" },
    { attack: "Keyless entry brute force", description: "Brute-force rolling code (some implementations have small keyspace)", prevention: "Large keyspace, lockout after failures" },
  ]
};

// ============================================================================
// DRONE / UAV SECURITY
// ============================================================================
export const DRONE_SECURITY = {
  attack_vectors: [
    { vector: "WiFi deauth", description: "Deauthenticate drone from controller (WiFi-based drones)", tools: ["aireplay-ng", "mdk4"] },
    { vector: "GPS spoofing", description: "Send fake GPS signals to misdirect drone", tools: ["HackRF + GPS-SDR-SIM"] },
    { vector: "RF jamming", description: "Jam control frequency to trigger RTH or land", tools: ["HackRF One", "Yard Stick One"] },
    { vector: "Firmware exploitation", description: "Extract and modify drone firmware for persistent access", tools: ["Binwalk", "IDA Pro/Ghidra"] },
    { vector: "MAVLink injection", description: "Send crafted MAVLink commands to ArduPilot/PX4 drones", tools: ["MAVProxy", "QGroundControl"] },
    { vector: "Video feed interception", description: "Capture unencrypted FPV video downlink", tools: ["SDR receiver", "analog/digital video decoder"] },
    { vector: "App exploitation", description: "Exploit companion mobile app for credentials or control", tools: ["Frida", "Burp Suite"] },
  ],
  common_frequencies: [
    { frequency: "2.4 GHz", usage: "WiFi-based control, some proprietary RC links" },
    { frequency: "5.8 GHz", usage: "FPV video, WiFi control" },
    { frequency: "900 MHz", usage: "Long-range control (ExpressLRS, Crossfire)" },
    { frequency: "1.2 GHz", usage: "Analog FPV video (long range)" },
    { frequency: "433 MHz", usage: "Telemetry, some control links" },
  ]
};

// ============================================================================
// MEDICAL DEVICE SECURITY
// ============================================================================
export const MEDICAL_DEVICE_SECURITY = {
  protocols: [
    { name: "DICOM", port: 104, description: "Digital Imaging and Communications in Medicine — medical imaging transfer", vulnerabilities: ["No encryption by default", "Patient data in cleartext", "DICOM service discovery", "Image manipulation"] },
    { name: "HL7 v2", port: 2575, description: "Health Level Seven — clinical data exchange between systems", vulnerabilities: ["Plaintext protocol", "No authentication", "Message injection", "Patient record manipulation"] },
    { name: "FHIR", port: 443, description: "Fast Healthcare Interoperability Resources — modern REST API for health data", vulnerabilities: ["OAuth misconfiguration", "Excessive data exposure", "IDOR on patient records"] },
  ],
  notable_research: [
    { device: "Insulin pumps", researcher: "Billy Rios, Jay Radcliffe", finding: "Remote insulin dose manipulation via wireless" },
    { device: "Pacemakers (St. Jude/Abbott)", researcher: "MedSec/Muddy Waters", finding: "RF protocol vulnerabilities allowing remote shock delivery" },
    { device: "Infusion pumps (BD Alaris)", researcher: "CyberMDX", finding: "Firmware modification to alter drug dosing" },
    { device: "MRI machines", researcher: "Various", finding: "Unpatched Windows XP/7 running on MRI workstations" },
    { device: "Hospital networks", researcher: "TrapX Security", finding: "MEDJACK — medical device hijacking for lateral movement" },
  ],
  regulations: [
    { name: "FDA Pre-market Guidance", description: "Cybersecurity requirements for medical device submissions" },
    { name: "FDA Post-market Guidance", description: "Vulnerability management after device is on market" },
    { name: "IEC 62443", description: "Industrial communication networks security (applies to medical devices)" },
    { name: "HIPAA", description: "Patient data protection requirements" },
    { name: "MDR (EU)", description: "European Medical Device Regulation with cybersecurity requirements" },
  ]
};
