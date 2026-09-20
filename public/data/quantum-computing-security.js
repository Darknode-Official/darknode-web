/**
 * DARKNODE — Quantum Computing & Post-Quantum Cryptography Security Reference
 * Copyright 2024-2026 Darknode Project. All rights reserved.
 * For educational purposes only.
 */

export const QUANTUM_THREATS = [
  { algorithm: "RSA", type: "asymmetric", keySize: "2048-4096 bit", quantumAttack: "Shor's algorithm", timeToBreak: "Hours on a cryptographically relevant quantum computer (CRQC)", impact: "Breaks all RSA encryption/signatures. TLS, code signing, secure boot, PKI all compromised.", pqcReplacement: "ML-KEM (CRYSTALS-Kyber), ML-DSA (CRYSTALS-Dilithium)", status: "Vulnerable to future CRQC" },
  { algorithm: "ECDSA / ECDH", type: "asymmetric", keySize: "P-256, P-384, P-521", quantumAttack: "Shor's algorithm (ECDLP)", timeToBreak: "Hours on CRQC", impact: "Breaks TLS ECDHE key exchange, Bitcoin/Ethereum signatures, SSH keys, FIDO2/WebAuthn.", pqcReplacement: "ML-DSA, SLH-DSA (SPHINCS+), FN-DSA (FALCON)", status: "Vulnerable to future CRQC" },
  { algorithm: "Diffie-Hellman", type: "key exchange", keySize: "2048+ bit", quantumAttack: "Shor's algorithm (DLP)", timeToBreak: "Hours on CRQC", impact: "Breaks DH key exchange in TLS, IKE/IPsec, SSH.", pqcReplacement: "ML-KEM (CRYSTALS-Kyber)", status: "Vulnerable to future CRQC" },
  { algorithm: "DSA", type: "signature", keySize: "2048-3072 bit", quantumAttack: "Shor's algorithm", timeToBreak: "Hours on CRQC", impact: "Breaks DSA signatures.", pqcReplacement: "ML-DSA, SLH-DSA", status: "Vulnerable to future CRQC" },
  { algorithm: "AES-128", type: "symmetric", keySize: "128 bit", quantumAttack: "Grover's algorithm", timeToBreak: "Effective security reduced to 64-bit — feasibly brute-forceable", impact: "Requires doubling key size. AES-128 → AES-256.", pqcReplacement: "AES-256 (quantum-safe with 128-bit post-quantum security)", status: "Weakened but not broken" },
  { algorithm: "AES-256", type: "symmetric", keySize: "256 bit", quantumAttack: "Grover's algorithm", timeToBreak: "Effective security reduced to 128-bit — still computationally infeasible", impact: "Considered quantum-safe. No algorithm change needed.", pqcReplacement: "N/A — already quantum-resistant", status: "Quantum-safe" },
  { algorithm: "SHA-256", type: "hash", keySize: "256 bit", quantumAttack: "Grover's algorithm (collision search)", timeToBreak: "Collision resistance reduced from 2^128 to 2^85 — still safe", impact: "Hash functions are relatively quantum-resistant. SHA-256 remains adequate.", pqcReplacement: "N/A — SHA-256 and SHA-3 are quantum-safe", status: "Quantum-safe" },
  { algorithm: "SHA-3 (Keccak)", type: "hash", keySize: "256/512 bit", quantumAttack: "Grover's algorithm", timeToBreak: "Still computationally infeasible", impact: "Designed with quantum resistance in mind.", pqcReplacement: "N/A", status: "Quantum-safe" },
  { algorithm: "ChaCha20-Poly1305", type: "symmetric AEAD", keySize: "256 bit", quantumAttack: "Grover's algorithm", timeToBreak: "Effective 128-bit security — still safe", impact: "Quantum-resistant at current key sizes.", pqcReplacement: "N/A", status: "Quantum-safe" },
];

export const NIST_PQC_STANDARDS = [
  { name: "ML-KEM (CRYSTALS-Kyber)", fips: "FIPS 203", type: "Key Encapsulation Mechanism", family: "Lattice (Module-LWE)", securityLevels: ["ML-KEM-512 (Level 1)", "ML-KEM-768 (Level 3)", "ML-KEM-1024 (Level 5)"], keySize: "800-1568 bytes (public key)", ciphertextSize: "768-1568 bytes", performance: "Very fast — comparable to RSA key gen, faster than ECDH", useCase: "TLS key exchange, VPN, hybrid key exchange, general encryption", status: "NIST Standard (August 2024)", notes: "Primary PQC key exchange mechanism. Already being deployed in Chrome, Signal, Cloudflare, AWS." },
  { name: "ML-DSA (CRYSTALS-Dilithium)", fips: "FIPS 204", type: "Digital Signature", family: "Lattice (Module-LWE/SIS)", securityLevels: ["ML-DSA-44 (Level 2)", "ML-DSA-65 (Level 3)", "ML-DSA-87 (Level 5)"], keySize: "1312-2592 bytes (public key)", ciphertextSize: "2420-4627 bytes (signature)", performance: "Fast signing and verification", useCase: "Code signing, TLS certificates, document signing, authentication", status: "NIST Standard (August 2024)", notes: "Primary PQC signature scheme. Replaces RSA/ECDSA for most use cases." },
  { name: "SLH-DSA (SPHINCS+)", fips: "FIPS 205", type: "Digital Signature", family: "Hash-based (stateless)", securityLevels: ["SLH-DSA-128s/f", "SLH-DSA-192s/f", "SLH-DSA-256s/f"], keySize: "32-64 bytes (public key)", ciphertextSize: "7856-49856 bytes (signature)", performance: "Slow signing, fast verification. Large signatures.", useCase: "Backup signature scheme, firmware signing, root CA certificates, where conservative security is paramount", status: "NIST Standard (August 2024)", notes: "Conservative choice — security relies only on hash function security. Larger signatures than ML-DSA but minimal assumptions." },
  { name: "FN-DSA (FALCON)", fips: "FIPS 206 (draft)", type: "Digital Signature", family: "Lattice (NTRU)", securityLevels: ["FN-DSA-512 (Level 1)", "FN-DSA-1024 (Level 5)"], keySize: "897-1793 bytes (public key)", ciphertextSize: "666-1280 bytes (signature)", performance: "Compact signatures, complex implementation (requires constant-time Gaussian sampling)", useCase: "Bandwidth-constrained environments, IoT, embedded systems", status: "NIST Draft Standard (2024)", notes: "Smallest signature sizes among lattice schemes. Implementation complexity is a concern." },
  { name: "BIKE", fips: "Round 4 candidate", type: "KEM", family: "Code-based (QC-MDPC)", securityLevels: ["Level 1", "Level 3", "Level 5"], keySize: "1541-5122 bytes", ciphertextSize: "1573-5154 bytes", performance: "Reasonable, but decapsulation can have timing side-channels", useCase: "Alternative KEM if lattice-based schemes are broken", status: "NIST Round 4 (under evaluation)", notes: "Backup KEM based on different mathematical assumption than ML-KEM." },
  { name: "Classic McEliece", fips: "Round 4 candidate", type: "KEM", family: "Code-based (Goppa codes)", securityLevels: ["Level 1-5"], keySize: "261,120-1,044,992 bytes (public key)", ciphertextSize: "128-240 bytes (very small)", performance: "Extremely large public keys but tiny ciphertexts. Fast encapsulation.", useCase: "Long-term key storage, offline scenarios where key size isn't critical", status: "NIST Round 4 (under evaluation)", notes: "40+ years of cryptanalysis. Most conservative KEM candidate. Key sizes are the main drawback." },
  { name: "HQC", fips: "Round 4 candidate", type: "KEM", family: "Code-based (Quasi-Cyclic)", securityLevels: ["Level 1", "Level 3", "Level 5"], keySize: "2249-7285 bytes", ciphertextSize: "4481-14469 bytes", performance: "Moderate. Larger keys/ciphertexts than ML-KEM.", useCase: "Alternative KEM for code-based diversity", status: "NIST Round 4 (under evaluation)", notes: "Selected for Round 4 as code-based alternative to lattice KEM." },
];

export const HARVEST_NOW_DECRYPT_LATER = {
  description: "Adversaries capture encrypted traffic today, store it, and plan to decrypt it when quantum computers become available. Also known as 'Store Now, Decrypt Later' (SNDL) or 'retrospective decryption'.",
  timeline: "Nation-states are believed to already be stockpiling encrypted data. CRQC estimated 2030-2040.",
  atRisk: [
    "Government classified communications",
    "Military and intelligence traffic",
    "Financial transaction records",
    "Medical records (long retention requirements)",
    "Trade secrets and intellectual property",
    "Diplomatic communications",
    "Authentication credentials with long validity",
    "Cryptocurrency private keys (Bitcoin, Ethereum)",
    "Corporate M&A communications",
    "Legal privileged communications"
  ],
  mitigations: [
    "Deploy hybrid key exchange (classical + PQC) immediately",
    "Use ML-KEM for TLS 1.3 key exchange",
    "Prioritize data with long confidentiality requirements",
    "Implement crypto-agility — ability to swap algorithms quickly",
    "Inventory all cryptographic assets and dependencies",
    "Classify data by quantum risk based on required secrecy lifetime",
    "Monitor NIST PQC standardization progress",
    "Plan for certificate infrastructure migration"
  ],
  nationStateActivity: [
    { nation: "China", activity: "Massive quantum computing investment ($15B+). PLA actively stockpiling encrypted data per NSA assessment." },
    { nation: "United States", activity: "NSA Cybersecurity Advisory mandating PQC transition by 2035. CNSA 2.0 suite published." },
    { nation: "Russia", activity: "Quantum computing research at MIPT and Rosatom. Likely stockpiling diplomatic/military traffic." },
    { nation: "EU", activity: "EuroQCI quantum communication infrastructure. Quantum Flagship program." }
  ]
};

export const CRYPTO_AGILITY_CHECKLIST = [
  { phase: "inventory", step: 1, action: "Identify all cryptographic algorithms in use across the organization", tools: ["CryptoSense Analyzer", "IBM z/OS Crypto Analytics", "Venafi"], priority: "critical" },
  { phase: "inventory", step: 2, action: "Map algorithm usage to applications, protocols, and data flows", tools: ["Manual audit", "Network traffic analysis"], priority: "critical" },
  { phase: "inventory", step: 3, action: "Classify data by required confidentiality lifetime (5yr, 10yr, 25yr, 50yr+)", tools: ["Data classification tools"], priority: "high" },
  { phase: "inventory", step: 4, action: "Identify all PKI infrastructure — root CAs, intermediate CAs, certificate chains", tools: ["Venafi", "DigiCert", "Manual"], priority: "critical" },
  { phase: "risk", step: 5, action: "Assess HNDL exposure — what traffic could adversaries be capturing?", tools: ["Network monitoring", "Threat modeling"], priority: "critical" },
  { phase: "risk", step: 6, action: "Prioritize systems by quantum risk: highest value + longest secrecy requirement first", tools: ["Risk framework"], priority: "high" },
  { phase: "risk", step: 7, action: "Evaluate third-party/vendor quantum readiness", tools: ["Vendor questionnaires"], priority: "medium" },
  { phase: "plan", step: 8, action: "Design hybrid deployment strategy — classical + PQC algorithms in parallel", tools: ["Architecture review"], priority: "critical" },
  { phase: "plan", step: 9, action: "Select NIST-approved PQC algorithms (ML-KEM, ML-DSA, SLH-DSA)", tools: ["NIST SP 800-208, FIPS 203/204/205"], priority: "critical" },
  { phase: "plan", step: 10, action: "Update TLS configurations to support hybrid key exchange", tools: ["OpenSSL 3.x + OQS provider", "BoringSSL", "liboqs"], priority: "high" },
  { phase: "implement", step: 11, action: "Deploy hybrid TLS 1.3 with X25519+ML-KEM-768", tools: ["Cloudflare, AWS, Google already support this"], priority: "high" },
  { phase: "implement", step: 12, action: "Update code signing to use ML-DSA or SLH-DSA alongside existing signatures", tools: ["OpenSSL + OQS", "BouncyCastle"], priority: "medium" },
  { phase: "implement", step: 13, action: "Migrate VPN/IPsec to PQC key exchange", tools: ["strongSwan with PQC plugins", "WireGuard + Rosenpass"], priority: "medium" },
  { phase: "implement", step: 14, action: "Update SSH to use PQC key exchange (sntrup761x25519-sha512)", tools: ["OpenSSH 9.0+"], priority: "medium" },
  { phase: "validate", step: 15, action: "Test PQC implementations for correctness and performance", tools: ["KAT (Known Answer Tests)", "Performance benchmarks"], priority: "high" },
  { phase: "validate", step: 16, action: "Verify no regressions in interoperability", tools: ["Cross-implementation testing"], priority: "high" },
  { phase: "validate", step: 17, action: "Monitor for cryptanalytic advances against chosen PQC algorithms", tools: ["IACR ePrint", "NIST PQC mailing list", "Academic conferences"], priority: "ongoing" },
];

export const QUANTUM_COMPUTING_MILESTONES = [
  { year: 2019, event: "Google achieves 'quantum supremacy' with Sycamore (53 qubits)", significance: "First demonstration of quantum advantage on a specific task (random circuit sampling)", cryptoImpact: "None — task was not cryptographically relevant" },
  { year: 2020, event: "USTC (China) demonstrates photonic quantum advantage with Jiuzhang", significance: "Boson sampling with 76 photons", cryptoImpact: "None — different computational model" },
  { year: 2021, event: "IBM Eagle processor (127 qubits)", significance: "First processor over 100 qubits", cryptoImpact: "None — insufficient for Shor's algorithm" },
  { year: 2022, event: "NIST announces first PQC standard selections", significance: "CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (DSA), FALCON (DSA), SPHINCS+ (DSA)", cryptoImpact: "Critical milestone — industry can begin migration" },
  { year: 2023, event: "IBM Condor (1,121 qubits), Google claims below-threshold error correction", significance: "Qubit count milestones, but error rates still too high for Shor's", cryptoImpact: "None direct, but accelerating hardware timeline" },
  { year: 2024, event: "NIST publishes FIPS 203/204/205 (ML-KEM, ML-DSA, SLH-DSA)", significance: "Official US federal standards for post-quantum cryptography", cryptoImpact: "Migration can begin in earnest" },
  { year: 2024, event: "Google Willow achieves below-threshold error correction at scale (105 qubits)", significance: "Key milestone toward fault-tolerant quantum computing", cryptoImpact: "Accelerates CRQC timeline — still years away but progress is real" },
  { year: 2024, event: "Chrome, Signal, iMessage deploy PQC hybrid key exchange", significance: "First major consumer deployments of post-quantum protection", cryptoImpact: "Protects billions of users against HNDL attacks" },
  { year: 2025, event: "Microsoft announces topological qubit breakthrough", significance: "If verified, topological qubits have inherently lower error rates", cryptoImpact: "Could dramatically accelerate path to CRQC" },
  { year: "2030-2040", event: "Estimated CRQC availability (4,000+ logical qubits for Shor's)", significance: "Able to break RSA-2048, ECDSA P-256 in hours", cryptoImpact: "ALL non-PQC public key cryptography broken. Must complete migration before this date." },
];

export const PQC_IMPLEMENTATION_LIBRARIES = [
  { name: "liboqs", language: "C", maintainer: "Open Quantum Safe", algorithms: "ML-KEM, ML-DSA, SLH-DSA, FN-DSA, BIKE, Classic McEliece, HQC", integrations: "OpenSSL provider, BoringSSL, OpenSSH, nginx, curl", url: "github.com/open-quantum-safe/liboqs", maturity: "Production-ready for most algorithms" },
  { name: "OQS-OpenSSL", language: "C", maintainer: "Open Quantum Safe", algorithms: "All liboqs algorithms via OpenSSL provider", integrations: "Drop-in OpenSSL replacement", url: "github.com/open-quantum-safe/oqs-provider", maturity: "Production-ready" },
  { name: "pqcrypto", language: "Rust", maintainer: "rustpq", algorithms: "ML-KEM, ML-DSA, SLH-DSA, NTRU, Classic McEliece", integrations: "Rust ecosystem", url: "github.com/rustpq/pqcrypto", maturity: "Production-ready" },
  { name: "CIRCL", language: "Go", maintainer: "Cloudflare", algorithms: "ML-KEM, X25519-ML-KEM hybrid", integrations: "Cloudflare TLS, Go crypto", url: "github.com/cloudflare/circl", maturity: "Production — deployed at Cloudflare scale" },
  { name: "BouncyCastle PQC", language: "Java/C#", maintainer: "Legion of the Bouncy Castle", algorithms: "ML-KEM, ML-DSA, SLH-DSA, FN-DSA, BIKE, Classic McEliece, HQC, NTRU", integrations: "Java/JCA, .NET", url: "bouncycastle.org", maturity: "Production-ready" },
  { name: "PQClean", language: "C", maintainer: "Community", algorithms: "Clean, portable, auditable reference implementations", integrations: "Base for other libraries", url: "github.com/PQClean/PQClean", maturity: "Reference — for building production implementations" },
  { name: "aws-lc", language: "C", maintainer: "Amazon Web Services", algorithms: "ML-KEM (Kyber), ML-DSA (Dilithium)", integrations: "AWS SDK, s2n-tls", url: "github.com/aws/aws-lc", maturity: "Production — deployed across AWS" },
  { name: "wolfSSL PQC", language: "C", maintainer: "wolfSSL", algorithms: "ML-KEM, ML-DSA via liboqs integration", integrations: "wolfSSL TLS library, embedded systems", url: "wolfssl.com", maturity: "Production — IoT/embedded focus" },
];
