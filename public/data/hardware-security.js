// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Hardware Security & Physical Attack Reference Database

export const SIDE_CHANNEL_ATTACKS = [
  {
    id: "SCA-001",
    name: "Timing Attack",
    category: "Side Channel",
    description: "Measuring the time a cryptographic operation takes to infer secret values. Different execution paths (branch misprediction, cache hits/misses) reveal information about the key or data being processed.",
    targets: ["Password comparison", "RSA modular exponentiation", "AES table lookups", "ECDSA nonce generation"],
    examples: [
      { name: "Kocher's Timing Attack on RSA", year: 1996, description: "First practical timing attack — measured time of RSA private key operations to extract the key bit by bit." },
      { name: "Lucky Thirteen", year: 2013, cve: "CVE-2013-0169", description: "Timing attack on TLS CBC mode MAC verification — padding validation timing revealed plaintext bytes." },
      { name: "Minerva", year: 2019, description: "ECDSA nonce bit-length leakage via timing — extracted private keys from smart cards and TPMs." }
    ],
    defense: [
      "Constant-time implementations for all cryptographic operations",
      "Avoid secret-dependent branching (use conditional moves: CMOV)",
      "Avoid secret-dependent memory access patterns (use constant-time table lookups)",
      "Add random delays (weak defense — statistical analysis can filter noise)",
      "Use cryptographic libraries audited for constant-time behavior (libsodium, BearSSL)"
    ]
  },
  {
    id: "SCA-002",
    name: "Power Analysis (SPA/DPA)",
    category: "Side Channel",
    description: "Measuring the power consumption of a device during cryptographic operations to extract secret keys.",
    types: [
      { name: "Simple Power Analysis (SPA)", description: "Visual inspection of a single power trace to identify operations. Different instructions (multiply vs square in RSA) consume different power." },
      { name: "Differential Power Analysis (DPA)", description: "Statistical analysis of many power traces to correlate power consumption with intermediate values of the cryptographic algorithm. Extremely powerful — works against most unprotected implementations." },
      { name: "Correlation Power Analysis (CPA)", description: "Improved DPA using Pearson correlation coefficient between predicted and actual power consumption. Requires fewer traces than DPA." }
    ],
    equipment: [
      { name: "Oscilloscope", cost: "$500-$50K", description: "Measure power consumption waveforms at high sample rates (>1 GSa/s for modern targets)" },
      { name: "Current probe / shunt resistor", cost: "$10-$500", description: "Convert current flow to measurable voltage" },
      { name: "ChipWhisperer", cost: "$250-$2000", description: "Open-source power analysis and fault injection platform (Lite/Pro/Husky)" },
      { name: "Riscure Inspector", cost: "$50K+", description: "Professional SCA/FI workstation" }
    ],
    defense: [
      "Masking — randomize intermediate values so power consumption is uncorrelated with secrets",
      "Shuffling — randomize the order of operations",
      "Constant-power implementations (dummy operations to equalize power)",
      "Noise generation — add random power consumption",
      "Amplitude/frequency domain filtering in hardware",
      "Dual-rail logic — complementary circuits that consume constant power"
    ]
  },
  {
    id: "SCA-003",
    name: "Electromagnetic Emanation (EM Analysis)",
    category: "Side Channel",
    description: "Similar to power analysis but measuring electromagnetic emissions from a chip instead of power consumption. Can be performed at a distance and doesn't require physical contact.",
    advantage: "Can target specific circuit areas using near-field EM probes. Works even when power supply is filtered/noisy.",
    equipment: [
      { name: "Near-field EM probe", cost: "$200-$5K", description: "Small loop antenna for localized EM measurements" },
      { name: "Low-noise amplifier", cost: "$100-$1K", description: "Amplify weak EM signals from chip" },
      { name: "Software-defined radio (SDR)", cost: "$20-$2K", description: "HackRF, RTL-SDR for EM signal capture" }
    ],
    realWorld: [
      { name: "TEMPEST", description: "NSA specification for EM emanation security. Classified standard for shielding sensitive equipment." },
      { name: "Van Eck phreaking", year: 1985, description: "Eavesdropping on CRT monitors from their EM emissions at distance. Demonstrated rebuilding screen content from 100+ meters." },
      { name: "RSA key extraction via EM", year: 2014, description: "Extracted 4096-bit RSA keys from a laptop by measuring EM emissions with a probe near the chassis." }
    ]
  },
  {
    id: "SCA-004",
    name: "Cache Timing Attacks (Spectre/Meltdown)",
    category: "Microarchitectural Side Channel",
    description: "Exploit CPU cache behavior to leak data from other processes or the kernel.",
    variants: [
      { name: "Spectre v1 (Bounds Check Bypass)", cve: "CVE-2017-5753", description: "Exploit speculative execution past array bounds checks to leak arbitrary memory via cache timing." },
      { name: "Spectre v2 (Branch Target Injection)", cve: "CVE-2017-5715", description: "Poison the branch target buffer to redirect speculative execution to attacker-controlled code (gadgets)." },
      { name: "Meltdown", cve: "CVE-2017-5754", description: "Read kernel memory from user space by exploiting out-of-order execution — CPU accesses kernel data before permission check completes." },
      { name: "Flush+Reload", description: "Evict a shared memory line from cache (CLFLUSH), let victim execute, then measure reload time to determine if victim accessed that line." },
      { name: "Prime+Probe", description: "Fill cache set with attacker's data, let victim execute, then probe cache set — evicted lines indicate victim's memory access pattern." },
      { name: "Spectre-BHB (Branch History Buffer)", cve: "CVE-2022-23960", description: "Bypass Spectre v2 mitigations by injecting history into the Branch History Buffer." }
    ],
    impact: "Read arbitrary memory from any process or the kernel at ~500 KB/s. Affects virtually all modern CPUs (Intel, AMD, ARM).",
    defense: [
      "Microcode updates from CPU vendor",
      "Kernel Page Table Isolation (KPTI) — separate kernel and user page tables",
      "Retpoline — replace indirect branches with return trampolines",
      "Array index masking — mask array indices to prevent speculative out-of-bounds access",
      "Process isolation improvements (site isolation in browsers)",
      "Disable SMT/HyperThreading for highest security (significant performance impact)"
    ]
  }
];

export const FAULT_INJECTION = [
  {
    id: "FI-001",
    name: "Voltage Glitching",
    description: "Briefly dropping or spiking the supply voltage of a microcontroller/processor to cause instruction skipping, data corruption, or security check bypass.",
    mechanism: "A brief voltage drop (5-50ns) causes the CPU to misread a register value or skip an instruction. By precisely timing the glitch during a security check (e.g., 'if(password_valid)'), the check can be bypassed.",
    equipment: [
      { name: "ChipWhisperer", cost: "$250-$2000", description: "Open-source glitching platform with precise timing control" },
      { name: "Custom MOSFET circuit", cost: "$20-$100", description: "Simple crowbar circuit to short VCC to GND briefly" },
      { name: "FPGA-based glitcher", cost: "$100-$5000", description: "Custom FPGA design for sub-nanosecond timing precision" }
    ],
    targets: [
      "Secure boot bypass (skip signature verification)",
      "Password/PIN check bypass (skip comparison instruction)",
      "Firmware readout protection bypass (STM32, nRF52, etc.)",
      "Privilege escalation (corrupt permission register)",
      "Cryptographic key extraction (DFA — Differential Fault Analysis on AES)"
    ],
    defense: [
      "Voltage glitch detectors (brownout detection with fast reset)",
      "Double-checking security decisions (check twice, fail if different)",
      "Software-level integrity checks (checksums on critical data)",
      "Hardware security modules with tamper detection",
      "Instruction flow monitoring (detect skipped instructions)"
    ]
  },
  {
    id: "FI-002",
    name: "Clock Glitching",
    description: "Inserting extra clock edges or stretching/compressing clock cycles to cause instruction execution errors.",
    mechanism: "By adding a short extra clock pulse, the CPU attempts to execute an instruction in less time than needed, causing setup/hold time violations that corrupt the result. Similar effect to voltage glitching but through clock manipulation.",
    equipment: [
      { name: "ChipWhisperer", description: "Supports clock glitching with adjustable pulse width and offset" },
      { name: "PLL manipulation", description: "On some targets, the clock PLL can be manipulated via debug interfaces" }
    ]
  },
  {
    id: "FI-003",
    name: "Laser Fault Injection (LFI)",
    description: "Using focused laser pulses on decapped IC die to induce targeted faults in specific transistors or memory cells.",
    mechanism: "Photons from a laser generate electron-hole pairs in silicon, causing transient current that flips bits in SRAM, registers, or logic gates. Unlike voltage/clock glitching, LFI can target specific gates with micrometer precision.",
    equipment: [
      { name: "Riscure Laser Station", cost: "$100K+", description: "Professional laser fault injection workstation with XYZ stage and microscope" },
      { name: "Custom setup", cost: "$5K-$50K", description: "Laser diode + microscope + XYZ stage + timing electronics" }
    ],
    applications: [
      "Targeted bit flips in security registers",
      "Bypass specific comparison instructions",
      "Differential Fault Analysis on AES (2 faulted ciphertexts can reveal the full key)",
      "Bypass fuse-based configuration bits",
      "Attack specific memory cells (e.g., key storage)"
    ],
    defense: [
      "Light sensors on die surface (detect laser illumination)",
      "Active mesh/shield layers over sensitive circuits",
      "Redundant computation (TMR — Triple Modular Redundancy)",
      "Error detection codes on sensitive data paths",
      "Randomized layout of critical logic"
    ]
  },
  {
    id: "FI-004",
    name: "Electromagnetic Fault Injection (EMFI)",
    description: "Using a focused electromagnetic pulse to induce faults in a chip without physical contact or decapping.",
    mechanism: "A coil placed near the chip surface generates a brief, intense electromagnetic pulse that induces currents in the chip's metal layers, causing transient faults similar to voltage glitching but more localized.",
    equipment: [
      { name: "ChipSHOUTER", cost: "$500-$3500", description: "Portable EM fault injection tool by NewAE Technology" },
      { name: "Custom EM probe + pulse generator", cost: "$200-$5K", description: "Coil probe with high-voltage pulse driver" }
    ],
    advantage: "No chip decapping required. Can target specific areas. Relatively portable.",
    defense: "Similar to voltage glitching defenses — detectors, redundancy, integrity checks."
  }
];

export const USB_ATTACKS = [
  {
    id: "USB-001",
    name: "BadUSB / Rubber Ducky",
    mitre: "T1200",
    description: "USB device that emulates a keyboard and types pre-programmed keystrokes at high speed to execute commands on the target computer.",
    devices: [
      { name: "USB Rubber Ducky", vendor: "Hak5", cost: "$80", description: "Original keystroke injection tool. Programs with DuckyScript language. 60+ second payload capacity." },
      { name: "Bash Bunny", vendor: "Hak5", cost: "$100", description: "Multi-function USB attack tool — emulates keyboard, storage, network, serial. Supports complex multi-stage attacks." },
      { name: "O.MG Cable", vendor: "Hak5", cost: "$120-$180", description: "Looks like a normal USB cable but contains a hidden Wi-Fi-enabled implant for remote keystroke injection and data exfiltration." },
      { name: "USBNinja Cable", cost: "$100", description: "USB cable with Bluetooth-triggered keystroke injection" },
      { name: "Digispark ATtiny85", cost: "$2-$5", description: "Cheap USB development board that can be programmed as a BadUSB device" },
      { name: "WHID Injector", cost: "$15-$30", description: "WiFi-enabled HID injector based on ESP8266 + ATmega32U4" }
    ],
    payloadExamples: [
      { name: "Reverse Shell", description: "Open PowerShell, download and execute reverse shell payload in <5 seconds" },
      { name: "Credential Harvester", description: "Open browser, navigate to credential harvesting page, auto-fill saved credentials" },
      { name: "WiFi Password Exfiltration", description: "Run netsh wlan show profiles + export keys, send via HTTP" },
      { name: "Backdoor Installation", description: "Download and install persistent RAT in seconds" }
    ],
    defense: [
      "USB device whitelisting (only allow known device VID/PID)",
      "Disable USB ports via Group Policy or BIOS",
      "USB Guard (Linux) — policy-based USB device authorization",
      "Physical USB port blockers",
      "Monitor for rapid keyboard input (>300 chars/sec is suspicious)",
      "Application whitelisting (prevents execution of downloaded payloads)"
    ]
  },
  {
    id: "USB-002",
    name: "USB Kill",
    description: "USB device that rapidly charges capacitors from USB power and discharges -200V DC through the data pins, physically destroying the USB controller and often the motherboard.",
    devices: [
      { name: "USB Kill v4", cost: "$60", description: "Commercial USB Kill device — discharges 200V within microseconds" }
    ],
    impact: "Physical destruction of hardware — USB controller, motherboard, sometimes CPU/RAM. Data on storage drives may survive if not directly connected.",
    defense: [
      "USB port optoelectric isolation",
      "TVS (Transient Voltage Suppressor) diodes on USB data lines",
      "USB Kill detection circuits (detect abnormal charging patterns)",
      "Epoxy-filled USB ports on public terminals",
      "Physical USB port covers"
    ]
  },
  {
    id: "USB-003",
    name: "USB Data Exfiltration",
    description: "Using USB storage devices to steal data from air-gapped or restricted systems.",
    techniques: [
      { name: "Direct copy", description: "Simply copy files to USB drive — the most basic data theft method" },
      { name: "USB Armory", description: "Single-board computer in USB form factor — can emulate multiple USB devices simultaneously (storage, network, HID)" },
      { name: "Covert channels", description: "Hide data in USB firmware, HID reports, or modified file systems to bypass DLP" },
      { name: "USB air-gap bridging", description: "Malware that copies data to USB automatically when inserted (Stuxnet used this)" }
    ],
    defense: [
      "Data Loss Prevention (DLP) software monitoring USB transfers",
      "USB device whitelisting by serial number",
      "Encrypted USB drives with central management",
      "Disable USB storage class while allowing HID (keyboard/mouse)",
      "Physical security — restrict USB access in sensitive areas"
    ]
  }
];

export const RFID_NFC_ATTACKS = [
  {
    id: "RFID-001",
    name: "RFID Cloning",
    description: "Reading and duplicating RFID access cards to gain unauthorized physical access to buildings and restricted areas.",
    frequencies: [
      { freq: "125 kHz (LF)", cards: ["HID Prox", "EM4100", "T5577"], security: "Very weak — no encryption, easy to clone", tool: "Proxmark3 Easy ($50): lf hid clone -r CARD_DATA" },
      { freq: "13.56 MHz (HF)", cards: ["MIFARE Classic", "MIFARE DESFire", "iCLASS", "NFC"], security: "Varies — MIFARE Classic is broken, DESFire is strong", tool: "Proxmark3: hf mf autopwn (MIFARE Classic)" },
      { freq: "UHF (860-960 MHz)", cards: ["EPC Gen2"], security: "Minimal — designed for inventory, not security", tool: "Specialized UHF reader" }
    ],
    devices: [
      { name: "Proxmark3 RDV4", cost: "$300", description: "Gold standard for RFID research. Supports LF and HF. Built-in antenna, battery, Bluetooth." },
      { name: "Proxmark3 Easy", cost: "$40-$80", description: "Budget Proxmark clone. Same capabilities for basic cloning." },
      { name: "Flipper Zero", cost: "$170", description: "Multi-tool with RFID (125kHz + 13.56MHz), Sub-GHz, IR, iButton, GPIO" },
      { name: "ACR122U", cost: "$30", description: "USB NFC reader/writer for 13.56 MHz cards" },
      { name: "ChameleonMini / ChameleonUltra", cost: "$60-$100", description: "Card emulator — pretend to be any HF card type" },
      { name: "iCopy-XS", cost: "$400", description: "Standalone RFID copier with screen — no computer needed" }
    ],
    mifare_classic_attacks: [
      { name: "Darkside attack", description: "Exploit weak PRNG in MIFARE Classic to recover one key sector — then use nested attack for all others" },
      { name: "Nested attack", description: "With one known key, exploit the PRNG to recover all other sector keys" },
      { name: "Hardnested attack", description: "For newer MIFARE Classic with improved PRNG — still broken but requires more samples" },
      { name: "Static encrypted nonce attack", description: "For MIFARE Classic with static nonce (some Chinese clones)" }
    ],
    defense: [
      "Use MIFARE DESFire EV2/EV3 or iCLASS SE (not Classic — it's broken)",
      "Multi-factor: card + PIN or card + biometric",
      "Card enrollment database — reject unknown cards",
      "Anti-passback — prevent card being used twice in same direction",
      "Monitor for clone attempts (same card used at two locations simultaneously)"
    ]
  },
  {
    id: "RFID-002",
    name: "NFC Relay Attack",
    description: "Relay NFC communication between a victim's contactless card and a legitimate reader over a longer distance, enabling remote payments or access.",
    mechanism: "Two NFC-enabled phones: one near the victim's wallet (emulates the reader), one near the payment terminal (emulates the card). The phones relay the NFC protocol over the internet in real-time.",
    tools: [
      { name: "NFCGate", description: "Android app for NFC relay attacks — relay over network connection" },
      { name: "Custom Android apps", description: "HCE (Host Card Emulation) + NFC reader mode for relay" }
    ],
    impact: "Contactless payment fraud. Access card relay for physical entry.",
    defense: [
      "Distance bounding protocols (measure round-trip time to detect relay)",
      "Require PIN for transactions above threshold",
      "NFC-blocking wallets/sleeves (Faraday shielding)",
      "Behavioral analysis on payment networks (location, timing)"
    ]
  }
];

export const PHYSICAL_SECURITY = {
  lockPicking: {
    description: "Physical lock bypass techniques for security assessments.",
    types: [
      { type: "Pin Tumbler", difficulty: "varies", description: "Most common lock type. Picked by manipulating pins to the shear line using a tension wrench and pick." },
      { type: "Wafer Lock", difficulty: "easy", description: "Common in desks, cabinets, cars. Single-sided wafers — easier to pick than pin tumblers." },
      { type: "Disc Detainer", difficulty: "medium-hard", description: "Used in higher-security padlocks (Abloy). Rotating discs instead of pins." },
      { type: "Tubular Lock", difficulty: "easy with tool", description: "Circular keyway (vending machines, laptop locks). Defeated with tubular pick tool in seconds." },
      { type: "Dimple Lock", difficulty: "medium", description: "Pins are on the flat face of the key. Requires dimple picks." },
      { type: "Smart Lock", difficulty: "varies", description: "Electronic locks may have physical bypass, firmware vulnerabilities, or protocol weaknesses." }
    ],
    techniques: [
      { name: "Single Pin Picking (SPP)", description: "Set each pin individually using a pick and tension wrench. Most precise method.", skill: "intermediate" },
      { name: "Raking", description: "Rapidly move a rake pick across all pins while applying tension. Fast but less reliable on security pins.", skill: "beginner" },
      { name: "Bumping", description: "Insert a bump key (cut to maximum depth) and strike it while applying tension. Exploits mechanical inertia.", skill: "beginner" },
      { name: "Impressioning", description: "Insert a blank key, apply tension, and mark binding pins. File the key to match. Creates a working key.", skill: "advanced" },
      { name: "Bypass", description: "Circumvent the lock entirely — e.g., shim padlock shackle, bypass tool on spring bolts, comb pick.", skill: "beginner" },
      { name: "Destructive entry", description: "Drill, snap, or force the lock. Last resort for security assessments.", skill: "beginner" }
    ],
    tools: [
      { name: "Peterson picks", cost: "$15-$40/pick", description: "American-made high-quality picks. Government Steels line for thin keyways." },
      { name: "Sparrows picks", cost: "$10-$30/pick", description: "Canadian picks with good value. Spirit set is a solid starter." },
      { name: "Southord picks", cost: "$5-$25/pick", description: "Budget-friendly picks. PXS-14 is a popular starter set." },
      { name: "Covert Instruments", cost: "$30-$100/set", description: "Premium picks designed for professional use." },
      { name: "Lishi tools", cost: "$30-$80/tool", description: "Combined pick + decoder for specific keyway profiles (2-in-1 tools)." }
    ]
  },
  socialEngineering: {
    physicalTechniques: [
      { name: "Tailgating/Piggybacking", description: "Following an authorized person through a secure door. Simple but highly effective." },
      { name: "Impersonation", description: "Posing as delivery person, IT support, contractor, or executive to gain access." },
      { name: "Fake badge", description: "Creating a replica employee badge (cloned RFID + printed visual)." },
      { name: "Shoulder surfing", description: "Observing someone entering their PIN, password, or door code." },
      { name: "Dumpster diving", description: "Searching trash for sensitive documents, credentials, or hardware." },
      { name: "USB drop", description: "Leaving infected USB drives in parking lots or common areas." }
    ]
  },
  tamperDetection: [
    { method: "Tamper-evident seals", description: "Adhesive seals that show visible damage when removed. Use on hardware, ports, enclosures." },
    { method: "Glitter nail polish", description: "Apply over screw heads — unique pattern is impossible to replicate if screws are removed." },
    { method: "Tamper-evident enclosures", description: "Hardware enclosures that detect opening (mesh, breakwire, pressure sensors)." },
    { method: "Secure boot chain", description: "Cryptographic verification from first boot instruction to OS. Any modification prevents boot." },
    { method: "Anti-tamper coatings", description: "Epoxy or conformal coating over sensitive components to prevent probing." }
  ]
};

export const SECURE_BOOT_BYPASS = [
  {
    id: "SBOOT-001",
    name: "UEFI Secure Boot Bypass via Unsigned Bootloader",
    description: "Loading an unsigned or vulnerable signed bootloader that is still trusted by the Secure Boot database.",
    examples: [
      { name: "BootHole (CVE-2020-10713)", description: "Buffer overflow in GRUB2's config file parsing — execute arbitrary code despite Secure Boot verification" },
      { name: "BlackLotus", description: "UEFI bootkit that exploits CVE-2022-21894 to bypass Secure Boot on fully patched Windows 11 systems" }
    ],
    defense: "Update UEFI firmware, update DBX (forbidden signatures database), use measured boot with TPM attestation"
  },
  {
    id: "SBOOT-002",
    name: "Microcontroller Readout Protection Bypass",
    description: "Bypassing flash memory readout protection (RDP) on microcontrollers to extract firmware.",
    targets: [
      { mcu: "STM32F1xx", technique: "Voltage glitch during RDP check bypasses protection", difficulty: "medium" },
      { mcu: "STM32F4xx", technique: "Cold boot attack + voltage glitch combination", difficulty: "hard" },
      { mcu: "nRF52 (Nordic)", technique: "Fault injection during APPROTECT check", difficulty: "medium" },
      { mcu: "ESP32", technique: "Fault injection on secure boot verification (some models)", difficulty: "hard" },
      { mcu: "ATmega328P", technique: "High-voltage programming can sometimes bypass lock bits", difficulty: "easy" }
    ]
  },
  {
    id: "SBOOT-003",
    name: "TPM Attacks",
    description: "Attacks targeting Trusted Platform Module hardware for key extraction or bypass.",
    attacks: [
      { name: "TPM Bus Sniffing", description: "Intercept communication between CPU and discrete TPM chip via SPI/I2C/LPC bus to capture sealed keys during boot. Requires physical access and logic analyzer.", tool: "Saleae Logic Analyzer + custom scripts" },
      { name: "TPM Reset Attack", description: "Reset the TPM while the platform is running to clear PCR values, then use previously captured sealed data." },
      { name: "TPM-FAIL", cve: "CVE-2019-11090, CVE-2019-16863", description: "Timing leakage in TPM's ECDSA implementation — extract private keys through timing side-channel." },
      { name: "fTPM Vulnerabilities", description: "Firmware TPM (AMD) can be attacked via voltage fault injection on the CPU itself — extract fTPM-sealed keys like BitLocker volume master key." }
    ],
    defense: [
      "Use integrated (fTPM) over discrete TPM (harder to bus-sniff)",
      "Enable TPM firmware updates",
      "Use PIN + TPM for BitLocker (not TPM-only)",
      "Monitor TPM event log for unexpected PCR changes"
    ]
  }
];
