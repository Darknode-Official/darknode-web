// Cryptography Reference Data
// Comprehensive technical reference for cryptographic algorithms, protocols, and attacks.
// All content is factual and technically accurate.

const SYMMETRIC_CIPHERS = [
  {
    name: "AES-128",
    type: "block",
    keySizes: [128],
    blockSize: 128,
    description: "Advanced Encryption Standard with 128-bit key. NIST-standardized block cipher based on the Rijndael algorithm. Performs 10 rounds of substitution-permutation transformations. Adopted as a federal standard in 2001 after a five-year public competition.",
    status: "recommended",
    strengths: [
      "Extensively analyzed with no practical attacks on full-round variant",
      "Hardware acceleration (AES-NI) available on modern Intel, AMD, and ARM processors",
      "Efficient in both software and hardware implementations",
      "NIST approved for protecting sensitive but unclassified data"
    ],
    weaknesses: [
      "128-bit key may become vulnerable to Grover's algorithm on quantum computers",
      "Side-channel attacks possible without constant-time implementations",
      "Biclique attack reduces security margin to 126.1 bits (theoretical only)"
    ],
    useCases: [
      "TLS bulk encryption",
      "Wi-Fi WPA2/WPA3 encryption",
      "Database encryption",
      "File and disk encryption for non-classified data"
    ]
  },
  {
    name: "AES-192",
    type: "block",
    keySizes: [192],
    blockSize: 128,
    description: "Advanced Encryption Standard with 192-bit key. Performs 12 rounds of substitution-permutation transformations. Offers a middle ground between AES-128 and AES-256 in terms of security margin and performance.",
    status: "recommended",
    strengths: [
      "Greater security margin than AES-128 against brute force",
      "Hardware acceleration via AES-NI instructions",
      "No known practical attacks against full 12 rounds",
      "Compliant with NIST standards for government use"
    ],
    weaknesses: [
      "Less commonly deployed than AES-128 or AES-256",
      "Slightly slower than AES-128 due to additional 2 rounds",
      "Related-key attacks exist in reduced-round variants"
    ],
    useCases: [
      "Financial data protection",
      "Enterprise VPN tunnels",
      "Compliance-driven encryption requirements",
      "Data-at-rest encryption"
    ]
  },
  {
    name: "AES-256",
    type: "block",
    keySizes: [256],
    blockSize: 128,
    description: "Advanced Encryption Standard with 256-bit key. NIST-standardized block cipher based on the Rijndael algorithm. Performs 14 rounds of substitution-permutation transformations.",
    status: "recommended",
    strengths: [
      "Widely vetted and trusted",
      "Hardware acceleration (AES-NI) on modern CPUs",
      "No practical attacks against full-round AES-256",
      "NIST and NSA approved for TOP SECRET"
    ],
    weaknesses: [
      "Related-key attacks exist in theoretical models",
      "Slightly slower than AES-128 due to additional rounds",
      "Key schedule has known weaknesses that do not affect security in practice"
    ],
    useCases: [
      "Government classified data",
      "Full-disk encryption",
      "VPN tunnels",
      "TLS bulk encryption"
    ]
  },
  {
    name: "ChaCha20-Poly1305",
    type: "stream",
    keySizes: [256],
    blockSize: null,
    description: "Authenticated encryption scheme combining the ChaCha20 stream cipher with the Poly1305 message authentication code. Designed by Daniel J. Bernstein. Operates on 512-bit blocks internally using a quarter-round function applied over 20 rounds. Standardized in RFC 8439.",
    status: "recommended",
    strengths: [
      "Constant-time software implementation resistant to timing attacks",
      "Excellent performance on platforms without AES hardware acceleration",
      "Provides both confidentiality and authenticity in a single construction",
      "Simpler and less error-prone than AES-CBC + HMAC combinations",
      "No known patents"
    ],
    weaknesses: [
      "Nonce reuse completely destroys security",
      "Less hardware acceleration support compared to AES on x86 platforms",
      "Relatively newer than AES, though extensively analyzed"
    ],
    useCases: [
      "TLS 1.3 bulk encryption (preferred on mobile devices)",
      "WireGuard VPN protocol",
      "SSH encryption",
      "Mobile and embedded device encryption"
    ]
  },
  {
    name: "3DES",
    type: "block",
    keySizes: [112, 168],
    blockSize: 64,
    description: "Triple Data Encryption Standard. Applies the DES cipher three times with either two or three independent keys (EDE mode: encrypt-decrypt-encrypt). Effective key strength is 112 bits for 2-key variant and 168 bits for 3-key variant, though meet-in-the-middle attacks reduce the 3-key variant to 112 bits effective security.",
    status: "deprecated",
    strengths: [
      "Well-understood security properties from decades of analysis",
      "Backward compatible with single DES when all three keys are identical",
      "Widely supported in legacy systems and payment processing"
    ],
    weaknesses: [
      "64-bit block size makes it vulnerable to Sweet32 birthday attacks after 2^32 blocks",
      "Very slow compared to AES in both software and hardware",
      "NIST deprecated 3DES in 2023 and will disallow it after 2023",
      "Three sequential DES operations make it approximately three times slower than DES"
    ],
    useCases: [
      "Legacy payment card systems (being phased out)",
      "Backward compatibility with older financial infrastructure",
      "Legacy mainframe encryption"
    ]
  },
  {
    name: "Blowfish",
    type: "block",
    keySizes: [32, 448],
    blockSize: 64,
    description: "Variable-key-length block cipher designed by Bruce Schneier in 1993. Uses a 16-round Feistel network with key-dependent S-boxes. The key setup phase is intentionally expensive, processing the key through 521 iterations of the encryption algorithm to initialize the P-array and S-boxes.",
    status: "legacy",
    strengths: [
      "Fast in software when key setup is amortized",
      "No patents, freely available for any use",
      "Key-dependent S-boxes provide resistance against certain differential attacks",
      "Expensive key schedule makes it suitable as a basis for password hashing (bcrypt)"
    ],
    weaknesses: [
      "64-bit block size is vulnerable to birthday-bound attacks",
      "Not suitable for encrypting large amounts of data with the same key",
      "Superseded by Twofish and AES",
      "Weak keys exist that produce identical S-box entries"
    ],
    useCases: [
      "Password hashing (via bcrypt derivative)",
      "Legacy applications",
      "Embedded systems with limited resources"
    ]
  },
  {
    name: "Twofish",
    type: "block",
    keySizes: [128, 192, 256],
    blockSize: 128,
    description: "Block cipher designed by Bruce Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall, and Niels Ferguson. AES finalist that uses a 16-round Feistel network with key-dependent S-boxes, MDS matrices, and pseudo-Hadamard transforms. Combines elements from Blowfish's design philosophy with a 128-bit block size.",
    status: "current",
    strengths: [
      "128-bit block size avoids birthday-bound issues",
      "Very flexible key schedule supporting multiple key lengths",
      "No known practical attacks on the full cipher",
      "Unpatented and freely available"
    ],
    weaknesses: [
      "Slower than AES in hardware and on platforms with AES-NI",
      "Less widely adopted than AES, leading to fewer implementations and less scrutiny",
      "Complex key schedule can be slower for applications that change keys frequently"
    ],
    useCases: [
      "Alternative cipher in multi-cipher encryption (e.g., VeraCrypt cascaded encryption)",
      "Applications requiring an AES alternative for defense in depth",
      "Open-source encryption tools"
    ]
  },
  {
    name: "Serpent",
    type: "block",
    keySizes: [128, 192, 256],
    blockSize: 128,
    description: "Block cipher designed by Ross Anderson, Eli Biham, and Lars Knudsen. AES finalist that uses 32 rounds of substitution-permutation network operations, deliberately designed with a large security margin. Uses bitslice implementation technique for efficient software performance.",
    status: "current",
    strengths: [
      "Very large security margin with 32 rounds (compared to AES's 10-14)",
      "Conservative design philosophy prioritizing security over speed",
      "Bitslice implementation provides natural resistance to timing attacks",
      "No known attacks on the full 32-round cipher"
    ],
    weaknesses: [
      "Significantly slower than AES due to double the number of rounds",
      "Less hardware acceleration support than AES",
      "Limited adoption in commercial products"
    ],
    useCases: [
      "High-security applications where speed is secondary",
      "Cascaded encryption in tools like VeraCrypt",
      "Defense-in-depth as an AES alternative"
    ]
  },
  {
    name: "Camellia",
    type: "block",
    keySizes: [128, 192, 256],
    blockSize: 128,
    description: "Block cipher jointly developed by Mitsubishi Electric and NTT of Japan. Uses a Feistel structure with 18 rounds for 128-bit keys and 24 rounds for 192/256-bit keys. Approved by ISO/IEC, NESSIE, and CRYPTREC as a recommended cipher alongside AES.",
    status: "current",
    strengths: [
      "Comparable security to AES with extensive cryptanalysis",
      "Approved by multiple international standards bodies",
      "Efficient in both hardware and software implementations",
      "Royalty-free with open specification"
    ],
    weaknesses: [
      "Less hardware acceleration support than AES on Western-designed processors",
      "Lower adoption outside Japan compared to AES",
      "Fewer third-party implementations and less community scrutiny"
    ],
    useCases: [
      "TLS cipher suites (RFC 5932)",
      "IPsec VPN implementations",
      "Japanese government and banking systems",
      "Interoperable encryption with AES alternatives"
    ]
  },
  {
    name: "RC4",
    type: "stream",
    keySizes: [40, 128, 256],
    blockSize: null,
    description: "Rivest Cipher 4, a stream cipher designed by Ron Rivest in 1987. Generates a pseudorandom keystream using a 256-byte state array and two index pointers. Was widely used due to its simplicity and speed but has been found to have significant statistical biases in its output.",
    status: "deprecated",
    strengths: [
      "Extremely simple to implement",
      "Very fast in software",
      "Low memory requirements"
    ],
    weaknesses: [
      "Statistical biases in initial keystream bytes (Fluhrer-Mantin-Shamir attack)",
      "Key recovery attacks demonstrated against WEP and TLS",
      "Prohibited in TLS by RFC 7465",
      "Single-byte biases allow plaintext recovery given enough ciphertexts",
      "No authentication or integrity protection"
    ],
    useCases: [
      "Historical use only -- no longer recommended for any purpose",
      "Legacy WEP wireless encryption (broken)",
      "Study of stream cipher vulnerabilities"
    ]
  },
  {
    name: "IDEA",
    type: "block",
    keySizes: [128],
    blockSize: 64,
    description: "International Data Encryption Algorithm, designed by Xuejia Lai and James Massey in 1991. Uses 8.5 rounds of operations mixing three algebraic groups: XOR, addition modulo 2^16, and multiplication modulo 2^16+1. Was used in early versions of PGP.",
    status: "legacy",
    strengths: [
      "Strong algebraic structure mixing three incompatible group operations",
      "Resistant to differential and linear cryptanalysis",
      "Used successfully in PGP for many years"
    ],
    weaknesses: [
      "64-bit block size subject to birthday attacks",
      "Was patented until 2012, limiting adoption",
      "128-bit key size is now considered minimum acceptable",
      "Superseded by AES and other modern ciphers"
    ],
    useCases: [
      "Legacy PGP implementations",
      "Historical cryptographic education",
      "Interoperability with older systems"
    ]
  },
  {
    name: "Salsa20",
    type: "stream",
    keySizes: [128, 256],
    blockSize: null,
    description: "Stream cipher designed by Daniel J. Bernstein, submitted to the eSTREAM project. Uses an ARX (add-rotate-XOR) design operating on a 4x4 matrix of 32-bit words through 20 rounds of quarter-round functions. The predecessor to ChaCha20, which modifies the quarter-round function for better diffusion.",
    status: "current",
    strengths: [
      "Constant-time implementation straightforward to achieve",
      "Excellent software performance on general-purpose processors",
      "Provable security reduction to the hardness of the Salsa20 core function",
      "Selected for the eSTREAM portfolio of recommended stream ciphers",
      "No patents"
    ],
    weaknesses: [
      "Largely superseded by ChaCha20 which has better per-round diffusion",
      "Nonce reuse is catastrophic",
      "Less adoption in modern standards compared to ChaCha20"
    ],
    useCases: [
      "NaCl/libsodium cryptographic library",
      "High-performance encryption on devices without AES hardware",
      "Disk encryption in some implementations"
    ]
  },
  {
    name: "CAST-128",
    type: "block",
    keySizes: [40, 128],
    blockSize: 64,
    description: "Block cipher designed by Carlisle Adams and Stafford Tavares, described in RFC 2144. Uses a 12-round or 16-round Feistel network (12 rounds for keys up to 80 bits, 16 rounds for longer keys). Employs four 8x32-bit S-boxes derived from bent functions.",
    status: "legacy",
    strengths: [
      "Well-analyzed with no known practical attacks on the full cipher",
      "Used as the default cipher in older versions of GnuPG and PGP",
      "Good balance of security and performance for its era"
    ],
    weaknesses: [
      "64-bit block size is vulnerable to birthday attacks on large data volumes",
      "Superseded by AES and CAST-256",
      "Variable key length complicates security analysis for shorter keys"
    ],
    useCases: [
      "OpenPGP implementations (historical default)",
      "Legacy VPN and encryption systems",
      "Backward compatibility with older GnuPG encrypted data"
    ]
  },
  {
    name: "SEED",
    type: "block",
    keySizes: [128],
    blockSize: 128,
    description: "Block cipher developed by the Korea Information Security Agency (KISA) in 1998. Uses a 16-round Feistel network with two 8x8 S-boxes derived from the finite field GF(2^8). Standardized as a Korean national standard (TTAS.KO-12.0004) and recognized by ISO/IEC 18033-3.",
    status: "current",
    strengths: [
      "128-bit block size provides resistance to birthday attacks",
      "Well-analyzed by international cryptographic community",
      "Standardized by ISO and IETF (RFC 4269)",
      "Free from patents"
    ],
    weaknesses: [
      "Limited adoption outside South Korea",
      "Fixed 128-bit key length limits flexibility",
      "Fewer optimized implementations compared to AES"
    ],
    useCases: [
      "South Korean government and financial systems",
      "TLS cipher suites for Korean compliance",
      "Korean e-commerce and banking applications"
    ]
  }
];

const HASH_FUNCTIONS = [
  {
    name: "MD5",
    digestSize: 128,
    blockSize: 512,
    description: "Message Digest Algorithm 5, designed by Ronald Rivest in 1991. Processes messages in 512-bit blocks through four rounds of 16 operations each, using a Merkle-Damgard construction. Produces a 128-bit hash value typically rendered as a 32-character hexadecimal string.",
    status: "deprecated",
    knownAttacks: [
      "Collision attacks by Wang et al. (2004) can find collisions in seconds",
      "Chosen-prefix collision attacks enable forging certificates (demonstrated by Flame malware)",
      "Preimage attacks reduced to 2^123.4 (theoretical improvement over brute force)",
      "Length extension attacks due to Merkle-Damgard construction",
      "Identical-prefix collision attacks are trivial on modern hardware"
    ],
    useCases: [
      "Non-cryptographic checksums for file integrity (when collision resistance not required)",
      "Legacy system compatibility",
      "Hash table distribution (non-security context)"
    ]
  },
  {
    name: "SHA-1",
    digestSize: 160,
    blockSize: 512,
    description: "Secure Hash Algorithm 1, designed by the NSA and published by NIST in 1995. Uses a Merkle-Damgard construction with 80 rounds of processing per 512-bit message block. Produces a 160-bit digest. Deprecated for most cryptographic uses after practical collision attacks were demonstrated.",
    status: "deprecated",
    knownAttacks: [
      "SHAttered attack (2017) produced first public collision using 2^63.1 SHA-1 evaluations",
      "Shambles attack (2020) demonstrated chosen-prefix collisions for ~$45K in compute",
      "Theoretical attacks by Wang et al. (2005) first showed reduced-complexity collision finding",
      "Length extension attacks due to Merkle-Damgard construction",
      "Birthday attacks require only 2^80 operations for collision"
    ],
    useCases: [
      "Legacy Git commit hashing (Git is transitioning to SHA-256)",
      "HMAC-SHA1 is still considered safe due to HMAC construction",
      "Legacy certificate validation (no longer accepted by browsers)"
    ]
  },
  {
    name: "SHA-224",
    digestSize: 224,
    blockSize: 512,
    description: "Truncated variant of SHA-256 from the SHA-2 family, using different initial hash values. Produces a 224-bit digest by truncating the final output. Uses the same Merkle-Damgard construction and compression function as SHA-256 with 64 rounds per block.",
    status: "current",
    knownAttacks: [
      "No practical attacks known against the full algorithm",
      "Length extension attacks are partially mitigated by truncation but not eliminated",
      "Generic birthday attack resistance of 2^112"
    ],
    useCases: [
      "Shorter hash where 256 bits is unnecessary",
      "Digital signatures with elliptic curves using ~224-bit keys",
      "Protocols requiring a hash matched to 112-bit security level"
    ]
  },
  {
    name: "SHA-256",
    digestSize: 256,
    blockSize: 512,
    description: "Member of the SHA-2 family designed by the NSA, standardized by NIST in FIPS 180-4. Uses a Merkle-Damgard construction with a Davies-Meyer compression function. Processes 512-bit message blocks through 64 rounds using 8 working variables, bitwise operations, and modular additions.",
    status: "recommended",
    knownAttacks: [
      "No practical collision or preimage attacks known",
      "Length extension attacks possible due to Merkle-Damgard construction (use HMAC or SHA-3 to mitigate)",
      "Theoretical preimage attack on 52 of 64 rounds (does not threaten full algorithm)"
    ],
    useCases: [
      "TLS certificate fingerprinting",
      "Bitcoin proof-of-work and blockchain hashing",
      "Code signing and software integrity verification",
      "Password hashing as inner function of PBKDF2 and HMAC",
      "Digital signatures (RSA, ECDSA)"
    ]
  },
  {
    name: "SHA-384",
    digestSize: 384,
    blockSize: 1024,
    description: "Truncated variant of SHA-512 from the SHA-2 family, using different initial hash values and producing a 384-bit digest. Operates on 1024-bit message blocks with 80 rounds per block, using 64-bit word operations. Offers higher performance than SHA-256 on 64-bit platforms due to native 64-bit arithmetic.",
    status: "recommended",
    knownAttacks: [
      "No practical attacks known against the full algorithm",
      "Length extension attacks are partially mitigated by truncation",
      "Generic birthday attack resistance of 2^192"
    ],
    useCases: [
      "TLS cipher suites requiring 192-bit security level",
      "Government applications at higher security levels",
      "Elliptic curve digital signatures with P-384 curves",
      "IPsec integrity verification"
    ]
  },
  {
    name: "SHA-512",
    digestSize: 512,
    blockSize: 1024,
    description: "Largest standard member of the SHA-2 family. Uses a Merkle-Damgard construction with 80 rounds per 1024-bit message block. Operates on 64-bit words, making it faster than SHA-256 on 64-bit processors despite producing a longer digest. Provides 256-bit collision resistance.",
    status: "recommended",
    knownAttacks: [
      "No practical attacks known against the full 80-round algorithm",
      "Length extension attacks possible due to Merkle-Damgard construction",
      "Theoretical attacks on reduced-round variants do not threaten the full algorithm"
    ],
    useCases: [
      "High-security digital signatures",
      "Long-term data integrity verification",
      "Ed448 and other high-security elliptic curve schemes",
      "Cryptographic protocols requiring 256-bit security level"
    ]
  },
  {
    name: "SHA3-256",
    digestSize: 256,
    blockSize: 1088,
    description: "SHA-3 variant producing a 256-bit digest, standardized by NIST in FIPS 202. Based on the Keccak sponge construction designed by Guido Bertoni, Joan Daemen, Michael Peeters, and Gilles Van Assche. Uses a 1600-bit state with 24 rounds of permutation. The sponge construction fundamentally differs from Merkle-Damgard, absorbing input and squeezing output.",
    status: "recommended",
    knownAttacks: [
      "No practical attacks known",
      "Immune to length extension attacks due to sponge construction",
      "Best known attack on full Keccak is generic birthday at 2^128"
    ],
    useCases: [
      "Applications requiring resistance to length extension attacks",
      "Post-quantum hash function (256-bit quantum security via Grover's bound)",
      "Ethereum blockchain address derivation",
      "Alternative to SHA-256 for defense in depth"
    ]
  },
  {
    name: "SHA3-512",
    digestSize: 512,
    blockSize: 576,
    description: "SHA-3 variant producing a 512-bit digest. Uses the Keccak sponge construction with a 1600-bit state and 576-bit rate (narrower rate than SHA3-256 for higher security margin). The smaller rate means each block absorbed is 576 bits, making it slower than SHA3-256 per byte of input.",
    status: "recommended",
    knownAttacks: [
      "No practical attacks known",
      "Immune to length extension attacks",
      "Provides 256-bit collision resistance and 512-bit preimage resistance"
    ],
    useCases: [
      "Maximum security hashing applications",
      "Long-term archival integrity verification",
      "High-security digital signature schemes",
      "Protocols requiring 256-bit collision resistance with sponge construction"
    ]
  },
  {
    name: "BLAKE2b",
    digestSize: 512,
    blockSize: 1024,
    description: "Cryptographic hash function designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein. Based on the BLAKE hash (SHA-3 finalist) which in turn is based on ChaCha. Optimized for 64-bit platforms with a configurable digest length from 1 to 64 bytes. Standardized in RFC 7693.",
    status: "recommended",
    knownAttacks: [
      "No practical attacks known on full-round BLAKE2b",
      "Inherits security margin from ChaCha/Salsa20 stream cipher family",
      "Theoretical analysis of reduced-round variants does not threaten full algorithm"
    ],
    useCases: [
      "High-performance file integrity checking",
      "Password hashing as inner hash for Argon2",
      "Digital signatures in libsodium/NaCl",
      "General-purpose replacement for MD5/SHA-1 with better performance than SHA-256"
    ]
  },
  {
    name: "BLAKE2s",
    digestSize: 256,
    blockSize: 512,
    description: "Variant of BLAKE2 optimized for 8-bit to 32-bit platforms. Uses 32-bit word operations and produces digests up to 32 bytes (256 bits). Uses 10 rounds compared to BLAKE2b's 12 rounds. Designed for constrained environments while maintaining cryptographic security.",
    status: "recommended",
    knownAttacks: [
      "No practical attacks known on full-round BLAKE2s",
      "Reduced-round analysis shows adequate security margin with 10 rounds"
    ],
    useCases: [
      "Embedded systems and IoT devices",
      "WireGuard VPN protocol (used for MAC and hashing)",
      "32-bit platforms where BLAKE2b is inefficient",
      "Tree hashing and parallel verification"
    ]
  },
  {
    name: "BLAKE3",
    digestSize: 256,
    blockSize: 512,
    description: "Latest member of the BLAKE family, designed by Jack O'Connor, Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox-O'Hearn. Uses a Merkle tree structure internally for unlimited parallelism. Reduces rounds to 7 (from BLAKE2s's 10) to maximize throughput. Supports keyed hashing, key derivation, and extendable output natively.",
    status: "recommended",
    knownAttacks: [
      "No practical attacks known",
      "Reduced round count compared to BLAKE2 has been debated but is considered safe",
      "Security margin is tighter than BLAKE2 but within acceptable bounds"
    ],
    useCases: [
      "High-throughput content-addressable storage",
      "Parallel file hashing on multi-core systems",
      "Key derivation function",
      "General-purpose hashing where maximum speed is required"
    ]
  },
  {
    name: "RIPEMD-160",
    digestSize: 160,
    blockSize: 512,
    description: "RACE Integrity Primitives Evaluation Message Digest, 160-bit variant. Designed in the European academic community as an open alternative to MD5 and SHA-1. Uses two independent parallel chains of five rounds each, with results combined at the end. Each chain processes the message block differently.",
    status: "legacy",
    knownAttacks: [
      "Collision attacks on reduced-round variants (up to 48 of 80 steps)",
      "Birthday bound at 2^80 operations for collision",
      "No practical collision on full RIPEMD-160 demonstrated, but 160-bit output is short by modern standards"
    ],
    useCases: [
      "Bitcoin address generation (SHA-256 followed by RIPEMD-160)",
      "OpenPGP fingerprints",
      "Legacy systems requiring RIPEMD compatibility"
    ]
  },
  {
    name: "Whirlpool",
    digestSize: 512,
    blockSize: 512,
    description: "Hash function designed by Vincent Rijmen (co-creator of AES) and Paulo Barreto. Based on a substantially modified AES block cipher used in a Miyaguchi-Preneel construction. Uses a 10-round block cipher with an 8x8 state matrix of bytes and operates in GF(2^8). Adopted by ISO/IEC 10118-3.",
    status: "current",
    knownAttacks: [
      "Rebound attack on 7 of 10 rounds (does not threaten full algorithm)",
      "No practical collision or preimage attacks on full Whirlpool",
      "Length extension attacks possible due to Miyaguchi-Preneel construction"
    ],
    useCases: [
      "ISO-standardized applications requiring 512-bit hash",
      "Digital signatures in European cryptographic standards",
      "Data integrity verification in compliance-oriented systems"
    ]
  }
];

const ASYMMETRIC_ALGORITHMS = [
  {
    name: "RSA",
    type: "encryption",
    keySizes: [2048, 3072, 4096],
    description: "Rivest-Shamir-Adleman public-key cryptosystem, published in 1977. Security is based on the computational difficulty of factoring the product of two large prime numbers. Supports both encryption (OAEP padding) and digital signatures (PSS padding). The most widely deployed public-key algorithm.",
    status: "current",
    mathematicalBasis: "Integer factorization problem. The public key contains the modulus n = p * q (product of two large primes) and public exponent e. The private key contains the private exponent d such that e * d is congruent to 1 mod phi(n).",
    performanceNotes: "Key generation is slow due to primality testing. Encryption and signature verification are fast (small public exponent e=65537). Decryption and signing are significantly slower, scaling roughly as O(k^3) where k is the key size in bits.",
    useCases: [
      "TLS/SSL certificate public keys",
      "Code signing certificates",
      "PGP/GPG email encryption",
      "SSH key authentication",
      "JWT token signing (RS256, RS384, RS512)"
    ]
  },
  {
    name: "DSA",
    type: "signature",
    keySizes: [1024, 2048, 3072],
    description: "Digital Signature Algorithm, proposed by NIST in 1991 and adopted as FIPS 186. Provides only digital signature capability (not encryption). Based on the discrete logarithm problem in a prime-order subgroup. Requires a per-signature random nonce; nonce reuse or bias leads to complete private key recovery.",
    status: "legacy",
    mathematicalBasis: "Discrete logarithm problem in a subgroup of Z*_p. Parameters include a prime p, a prime q dividing p-1, and a generator g of the subgroup of order q. The private key is a random integer x in [1, q-1] and the public key is y = g^x mod p.",
    performanceNotes: "Signature generation and verification are comparable in speed. Significantly faster than RSA for signature generation but verification is slower. Key generation requires generating a prime pair (p, q) which can be slow.",
    useCases: [
      "Legacy government digital signature applications",
      "Older SSH key types (ssh-dss)",
      "Legacy certificate authorities"
    ]
  },
  {
    name: "ECDSA",
    type: "signature",
    keySizes: [256, 384, 521],
    description: "Elliptic Curve Digital Signature Algorithm, the elliptic curve analogue of DSA. Operates over points on an elliptic curve over a finite field. Standard curves include NIST P-256, P-384, and P-521. Provides equivalent security to RSA with much smaller keys (256-bit ECDSA is roughly equivalent to 3072-bit RSA).",
    status: "current",
    mathematicalBasis: "Elliptic Curve Discrete Logarithm Problem (ECDLP). Given points P and Q on an elliptic curve where Q = kP, it is computationally infeasible to determine the scalar k. The private key is a random integer d and the public key is the point Q = dG where G is the generator point.",
    performanceNotes: "Much faster key generation and signing than RSA for equivalent security. Signatures are smaller than RSA signatures. Verification is slightly slower than RSA due to point multiplication. Requires high-quality random nonce for each signature; deterministic variant (RFC 6979) recommended.",
    useCases: [
      "TLS 1.2 and 1.3 certificate authentication",
      "Bitcoin and Ethereum transaction signing (secp256k1 curve)",
      "Code signing",
      "SSH key authentication (ecdsa-sha2-nistp256)",
      "WebAuthn/FIDO2 authentication"
    ]
  },
  {
    name: "Ed25519",
    type: "signature",
    keySizes: [256],
    description: "Edwards-curve Digital Signature Algorithm using Curve25519 in twisted Edwards form. Designed by Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, and Bo-Yin Yang. Provides 128-bit security level with deterministic signatures (no random nonce needed). Uses SHA-512 internally for hashing.",
    status: "recommended",
    mathematicalBasis: "Elliptic Curve Discrete Logarithm Problem on the twisted Edwards curve -x^2 + y^2 = 1 - (121665/121666)x^2y^2 over the prime field p = 2^255 - 19. The base point has order 2^252 + 27742317777372353535851937790883648493.",
    performanceNotes: "Extremely fast signature generation and verification. Deterministic signatures eliminate the catastrophic risk of nonce reuse. Constant-time implementations are straightforward due to the curve design. Public key is only 32 bytes; signature is 64 bytes.",
    useCases: [
      "SSH key authentication (ssh-ed25519, preferred over RSA and ECDSA)",
      "WireGuard VPN authentication",
      "Signal Protocol identity keys",
      "DNSSEC signing",
      "Age encryption tool"
    ]
  },
  {
    name: "Ed448",
    type: "signature",
    keySizes: [448],
    description: "Edwards-curve Digital Signature Algorithm using Curve448-Goldilocks. Provides 224-bit security level, higher than Ed25519's 128-bit level. Uses SHAKE256 internally for hashing. Designed by Mike Hamburg using a Solinas prime (2^448 - 2^224 - 1) for efficient arithmetic.",
    status: "current",
    mathematicalBasis: "Elliptic Curve Discrete Logarithm Problem on the Edwards curve x^2 + y^2 = 1 - 39081x^2y^2 over the prime field p = 2^448 - 2^224 - 1 (Goldilocks prime). The prime's structure enables efficient reduction.",
    performanceNotes: "Slower than Ed25519 due to larger field size, but still fast compared to RSA. Public key is 57 bytes; signature is 114 bytes. Provides a higher security margin for applications that need to plan for advances in cryptanalysis.",
    useCases: [
      "High-security applications requiring >128-bit security level",
      "Long-lived signing keys where security margin matters",
      "SSH authentication (ssh-ed448)",
      "Government systems requiring higher security curves"
    ]
  },
  {
    name: "DH",
    type: "key-exchange",
    keySizes: [2048, 3072, 4096],
    description: "Diffie-Hellman key exchange, published by Whitfield Diffie and Martin Hellman in 1976. The first practical public-key protocol. Allows two parties to establish a shared secret over an insecure channel without prior shared secrets. Does not provide authentication on its own.",
    status: "current",
    mathematicalBasis: "Discrete Logarithm Problem. Both parties agree on a prime p and generator g. Each party generates a private exponent (a or b) and sends g^a mod p or g^b mod p. Both can compute the shared secret g^(ab) mod p but an eavesdropper cannot.",
    performanceNotes: "Modular exponentiation is computationally expensive for large primes. 2048-bit DH provides approximately 112 bits of security. 4096-bit DH is significantly slower but provides ~140 bits. Ephemeral DH (DHE) provides forward secrecy at the cost of per-session key generation.",
    useCases: [
      "TLS key exchange (DHE cipher suites)",
      "IPsec IKE key establishment",
      "SSH key exchange (diffie-hellman-group14-sha256)",
      "Establishing shared secrets in custom protocols"
    ]
  },
  {
    name: "ECDH",
    type: "key-exchange",
    keySizes: [256, 384, 521],
    description: "Elliptic Curve Diffie-Hellman, the elliptic curve analogue of DH key exchange. Uses scalar multiplication on elliptic curve points instead of modular exponentiation. Standard curves include NIST P-256, P-384, and P-521. ECDHE (ephemeral variant) is the most common key exchange in modern TLS.",
    status: "recommended",
    mathematicalBasis: "Elliptic Curve Diffie-Hellman Problem. Each party generates a private scalar (a or b) and sends the public point aG or bG. Both compute the shared point abG using their private scalar and the other's public point. An eavesdropper seeing aG and bG cannot compute abG.",
    performanceNotes: "Significantly faster than finite-field DH for equivalent security. 256-bit ECDH provides ~128-bit security equivalent to 3072-bit DH. Key generation and shared secret computation involve elliptic curve point multiplication, which is fast with optimized implementations.",
    useCases: [
      "TLS 1.2 and 1.3 key exchange (ECDHE)",
      "Signal Protocol key agreement (X3DH)",
      "IKEv2 key exchange",
      "Secure messaging ephemeral key exchange"
    ]
  },
  {
    name: "X25519",
    type: "key-exchange",
    keySizes: [256],
    description: "Elliptic curve Diffie-Hellman function using Curve25519, designed by Daniel J. Bernstein. Uses the Montgomery form of the curve for efficient variable-base scalar multiplication using the Montgomery ladder algorithm. Provides 128-bit security. Keys are 32 bytes. Standardized in RFC 7748.",
    status: "recommended",
    mathematicalBasis: "Elliptic Curve Diffie-Hellman Problem on the Montgomery curve y^2 = x^3 + 486662x^2 + x over the prime field p = 2^255 - 19. The Montgomery ladder computes scalar multiplication using only the x-coordinate, making it naturally constant-time.",
    performanceNotes: "Extremely fast due to Curve25519's design. The Montgomery ladder algorithm provides natural resistance to timing attacks. All 32-byte strings are valid public keys (clamping is applied to private keys). Single, fixed-cost computation regardless of key bits.",
    useCases: [
      "TLS 1.3 key exchange (most common key agreement method)",
      "WireGuard VPN key exchange",
      "Signal Protocol key agreement",
      "Noise protocol framework",
      "Age encryption tool"
    ]
  },
  {
    name: "ElGamal",
    type: "encryption",
    keySizes: [2048, 3072, 4096],
    description: "Public-key encryption scheme proposed by Taher Elgamal in 1985. Based on the Diffie-Hellman key exchange, adapted for encryption and digital signatures. The encryption scheme is semantically secure under the Decisional Diffie-Hellman assumption. Ciphertexts are twice the size of the plaintext.",
    status: "legacy",
    mathematicalBasis: "Decisional Diffie-Hellman (DDH) assumption in the multiplicative group of integers modulo a prime. The public key is (p, g, h) where h = g^x mod p and x is the private key. Encryption produces (c1, c2) = (g^r mod p, m * h^r mod p) for random r.",
    performanceNotes: "Ciphertext expansion is 2x (two group elements per plaintext block). Encryption requires two modular exponentiations. Decryption requires one modular exponentiation and one modular inverse. Slower than RSA for both encryption and decryption.",
    useCases: [
      "GnuPG encryption subkeys (historical default)",
      "Homomorphic encryption schemes (additively homomorphic)",
      "Threshold cryptography applications",
      "Academic study of semantic security"
    ]
  }
];

const KEY_DERIVATION = [
  {
    name: "PBKDF2",
    description: "Password-Based Key Derivation Function 2, defined in RFC 8018 (PKCS #5 v2.1). Applies a pseudorandom function (typically HMAC-SHA-256) repeatedly to the password along with a salt. The iteration count controls computational cost. Widely supported but lacks memory-hardness, making it vulnerable to GPU and ASIC attacks.",
    parameters: {
      password: "The user's password or passphrase, used as the base input to the PRF",
      salt: "Random value of at least 16 bytes to prevent rainbow table attacks and ensure unique outputs for identical passwords",
      iterations: "Number of times the PRF is applied; higher values increase computation time linearly for both defender and attacker",
      keyLength: "Desired length of the derived key in bytes",
      hashFunction: "The pseudorandom function to use, typically HMAC-SHA-256 or HMAC-SHA-512"
    },
    recommendedSettings: {
      iterations: 600000,
      hashFunction: "SHA-256"
    },
    comparisonNotes: "PBKDF2 is the most widely supported KDF due to its inclusion in many standards (WPA2, LUKS, iOS keychain). However, it is computationally simple and parallelizable, meaning attackers with GPUs or ASICs can achieve very high throughput. For password hashing, Argon2id or bcrypt are preferred. OWASP recommends 600,000 iterations with SHA-256 as of 2023."
  },
  {
    name: "bcrypt",
    description: "Password hashing function based on the Blowfish cipher, designed by Niels Provos and David Mazieres in 1999. Uses an expensive key setup phase (Eksblowfish) that processes the password and salt through multiple iterations of Blowfish key scheduling. Incorporates a cost factor that doubles the work for each increment.",
    parameters: {
      password: "The user's password, truncated to 72 bytes",
      salt: "128-bit random salt, typically encoded in the output string along with the hash",
      costFactor: "Logarithmic work factor (2^cost iterations); each increment doubles the computation time"
    },
    recommendedSettings: {
      costFactor: 12
    },
    comparisonNotes: "bcrypt's Blowfish-based design is naturally resistant to GPU acceleration because it requires 4KB of fast memory for the S-boxes, which limits GPU parallelism. The 72-byte password limit can be worked around by pre-hashing with SHA-256. The output includes the algorithm identifier, cost, salt, and hash in a single string (e.g., $2b$12$...). Preferred over PBKDF2 but less configurable than Argon2."
  },
  {
    name: "scrypt",
    description: "Memory-hard password-based key derivation function designed by Colin Percival in 2009. Deliberately requires large amounts of memory in addition to CPU time, making hardware brute-force attacks expensive. Uses a sequential memory-hard function based on the ROMix algorithm with Salsa20/8 as the core mixing function.",
    parameters: {
      password: "The user's password or passphrase",
      salt: "Random salt value, at least 16 bytes recommended",
      N: "CPU/memory cost parameter, must be a power of 2. Determines the number of iterations and the memory required (N * r * 128 bytes)",
      r: "Block size parameter, controls the sequential memory access pattern. Increasing r increases memory usage and the number of SHA-256 iterations",
      p: "Parallelism parameter, number of independent mixing operations. Allows trading time for parallelism",
      keyLength: "Desired length of the derived key in bytes"
    },
    recommendedSettings: {
      N: 32768,
      r: 8,
      p: 1
    },
    comparisonNotes: "scrypt was the first widely-used memory-hard KDF. Its memory-hardness makes ASIC and GPU attacks significantly more expensive than against PBKDF2 or bcrypt. However, it has some weaknesses: the time and memory cost cannot be tuned independently, and with low memory settings it degrades to a PBKDF2-like function. Argon2 was designed to address these limitations. scrypt is used in Litecoin mining and several cryptocurrency protocols."
  },
  {
    name: "Argon2i",
    description: "Data-independent variant of the Argon2 password hashing function, winner of the Password Hashing Competition in 2015. Uses data-independent memory access patterns to resist side-channel attacks. Makes multiple passes over memory using a compression function based on BLAKE2b. Designed for environments where side-channel attacks are a concern (e.g., shared hosting).",
    parameters: {
      password: "The user's password",
      salt: "Random salt, at least 16 bytes",
      memory: "Memory cost in kibibytes (KiB), determines the total RAM used during hashing",
      iterations: "Number of passes over the memory, increases time cost without increasing memory",
      parallelism: "Number of threads/lanes used in the computation",
      keyLength: "Desired output length in bytes",
      type: "Fixed as Argon2i (data-independent addressing)"
    },
    recommendedSettings: {
      memory: 65536,
      iterations: 4,
      parallelism: 4
    },
    comparisonNotes: "Argon2i is the most conservative Argon2 variant against side-channel attacks. Its data-independent access pattern means the memory addresses accessed do not depend on the password, preventing cache-timing attacks. However, it has lower resistance to GPU/ASIC attacks with fewer passes compared to Argon2d. For most use cases, Argon2id is preferred as it combines the benefits of both variants."
  },
  {
    name: "Argon2d",
    description: "Data-dependent variant of the Argon2 password hashing function. Uses data-dependent memory access patterns that maximize resistance to GPU and ASIC cracking attacks. The memory addresses accessed depend on the password being hashed, making it harder for attackers to use time-memory tradeoffs.",
    parameters: {
      password: "The user's password",
      salt: "Random salt, at least 16 bytes",
      memory: "Memory cost in kibibytes (KiB)",
      iterations: "Number of passes over the memory",
      parallelism: "Number of threads/lanes used in the computation",
      keyLength: "Desired output length in bytes",
      type: "Fixed as Argon2d (data-dependent addressing)"
    },
    recommendedSettings: {
      memory: 65536,
      iterations: 3,
      parallelism: 4
    },
    comparisonNotes: "Argon2d provides the strongest resistance to GPU and ASIC attacks due to its data-dependent memory access pattern. However, this data-dependency means that an attacker who can observe memory access patterns (via cache-timing attacks or other side channels) can potentially learn information about the password. Suitable for backend servers where side-channel attacks are not a practical threat. For cryptocurrency proof-of-work and backend-only password hashing."
  },
  {
    name: "Argon2id",
    description: "Hybrid variant of Argon2 combining Argon2i and Argon2d. Uses data-independent memory access in the first half of the first pass (Argon2i mode) and data-dependent access for the rest (Argon2d mode). This provides both side-channel resistance during initialization and GPU/ASIC resistance during the main computation. Recommended by OWASP and RFC 9106.",
    parameters: {
      password: "The user's password",
      salt: "Random salt, at least 16 bytes (16 bytes recommended by RFC 9106)",
      memory: "Memory cost in kibibytes (KiB). RFC 9106 recommends at least 2 GiB for high-security, 64 MiB minimum",
      iterations: "Number of passes over the memory. More iterations increase time cost",
      parallelism: "Number of threads/lanes. Should match the number of available CPU cores",
      keyLength: "Desired output length in bytes, typically 32 bytes",
      type: "Fixed as Argon2id (hybrid addressing)"
    },
    recommendedSettings: {
      memory: 65536,
      iterations: 3,
      parallelism: 4
    },
    comparisonNotes: "Argon2id is the recommended default for password hashing in nearly all scenarios. It provides a good balance between side-channel resistance (from the Argon2i first pass) and GPU/ASIC resistance (from the Argon2d subsequent operations). RFC 9106 standardizes Argon2id and provides recommended parameters. OWASP recommends Argon2id as the first choice for password hashing, with bcrypt as a fallback."
  },
  {
    name: "HKDF",
    description: "HMAC-based Key Derivation Function, defined in RFC 5869. A two-stage extract-then-expand KDF designed for deriving multiple cryptographic keys from a single shared secret. Not designed for password hashing (no intentional slowness). Uses HMAC as the underlying PRF. Widely used in TLS 1.3 and Signal Protocol.",
    parameters: {
      inputKeyMaterial: "The source keying material (e.g., a Diffie-Hellman shared secret). Should have sufficient entropy but need not be uniformly distributed",
      salt: "Optional non-secret random value used in the extract step. If not provided, a string of zero bytes the length of the hash output is used",
      info: "Context and application-specific information for the expand step. Binds the derived key to a specific purpose (e.g., 'tls13 derived')",
      length: "Desired output key length in bytes (up to 255 * hash_length)",
      hashFunction: "The hash function for HMAC, typically SHA-256 or SHA-384"
    },
    recommendedSettings: {
      hashFunction: "SHA-256",
      saltLength: 32
    },
    comparisonNotes: "HKDF is a key derivation function, not a password hashing function. It is designed to extract entropy from a high-entropy source (like a DH shared secret) and expand it into multiple keys. It should never be used directly with low-entropy inputs like passwords. Use HKDF when you need to derive multiple keys from a single secret (e.g., separate encryption and MAC keys). TLS 1.3 uses HKDF exclusively for all key derivation."
  }
];

const MODES_OF_OPERATION = [
  {
    name: "ECB",
    fullName: "Electronic Codebook",
    description: "The simplest block cipher mode. Each plaintext block is encrypted independently with the same key. Identical plaintext blocks produce identical ciphertext blocks, which leaks patterns in the plaintext. Should never be used for encrypting data longer than one block.",
    properties: {
      parallelizable: true,
      errorPropagation: "Errors in one ciphertext block affect only that block's decryption",
      paddingRequired: true,
      providesAuthentication: false
    },
    securityNotes: "ECB mode is considered insecure for encrypting more than a single block because it does not hide data patterns. The classic demonstration is encrypting a bitmap image -- the encrypted image clearly shows the original shapes. Never use ECB for general-purpose encryption. The only acceptable use is encrypting a single block (e.g., a single AES key wrap operation).",
    useCases: [
      "Encrypting single blocks (e.g., individual database fields shorter than block size)",
      "Educational demonstrations of why modes of operation matter",
      "AES key wrapping (single-block operations)"
    ],
    diagram: "  Plaintext1       Plaintext2       Plaintext3\n      |                |                |\n  [Encrypt K]     [Encrypt K]     [Encrypt K]\n      |                |                |\n  Ciphertext1      Ciphertext2      Ciphertext3\n\n  (Each block is independent -- identical plaintext\n   blocks produce identical ciphertext blocks)"
  },
  {
    name: "CBC",
    fullName: "Cipher Block Chaining",
    description: "Each plaintext block is XORed with the previous ciphertext block before encryption. An initialization vector (IV) is XORed with the first plaintext block. Chaining ensures identical plaintext blocks produce different ciphertext when preceded by different blocks. Requires padding for messages not aligned to the block size.",
    properties: {
      parallelizable: false,
      errorPropagation: "A single-bit error in ciphertext corrupts the corresponding plaintext block entirely and flips the corresponding bit in the next plaintext block",
      paddingRequired: true,
      providesAuthentication: false
    },
    securityNotes: "CBC is vulnerable to padding oracle attacks (e.g., POODLE, Lucky13) when used with padding validation that leaks timing information. The IV must be unpredictable (random) for CPA security; using a counter or predictable IV enables the BEAST attack. Always pair with a MAC (encrypt-then-MAC) for authenticated encryption. Decryption can be parallelized even though encryption cannot.",
    useCases: [
      "Legacy TLS encryption (TLS 1.0-1.2)",
      "Disk encryption (when combined with other techniques)",
      "IPsec ESP encryption"
    ],
    diagram: "  Plaintext1    Plaintext2    Plaintext3\n      |              |              |\n  IV--XOR         +--XOR         +--XOR\n      |           |    |         |    |\n  [Encrypt K]    | [Encrypt K]  | [Encrypt K]\n      |          |    |         |    |\n  Ciphertext1----+  Ciphertext2-+  Ciphertext3"
  },
  {
    name: "CTR",
    fullName: "Counter Mode",
    description: "Turns a block cipher into a stream cipher by encrypting successive values of a counter to produce a keystream. The keystream is XORed with plaintext to produce ciphertext. The counter is typically formed from a nonce concatenated with an incrementing block counter. No padding is needed.",
    properties: {
      parallelizable: true,
      errorPropagation: "A single-bit error in ciphertext flips only the corresponding bit in plaintext",
      paddingRequired: false,
      providesAuthentication: false
    },
    securityNotes: "Nonce reuse in CTR mode is catastrophic: XORing two ciphertexts encrypted with the same nonce/key reveals the XOR of the two plaintexts. The nonce must never repeat for a given key. Random nonces are safe for messages if the nonce space is large enough (96-bit nonces limit to 2^32 messages before birthday bound). Pre-computation of keystream blocks enables random access decryption.",
    useCases: [
      "High-throughput encryption requiring parallelism",
      "Building block for GCM authenticated encryption",
      "Disk encryption (allows random access to encrypted sectors)",
      "Network encryption where packet reordering may occur"
    ],
    diagram: "  Nonce|Ctr=1     Nonce|Ctr=2     Nonce|Ctr=3\n      |               |               |\n  [Encrypt K]    [Encrypt K]    [Encrypt K]\n      |               |               |\n  Keystream1      Keystream2      Keystream3\n      |               |               |\n  Plaintext1--XOR Plaintext2--XOR Plaintext3--XOR\n      |               |               |\n  Ciphertext1     Ciphertext2     Ciphertext3"
  },
  {
    name: "GCM",
    fullName: "Galois/Counter Mode",
    description: "Authenticated encryption mode combining CTR mode encryption with GHASH authentication. Provides both confidentiality and authenticity with a single key. Uses finite field multiplication in GF(2^128) for the authentication tag computation. Standardized in NIST SP 800-38D. The dominant AEAD mode in TLS 1.2 and 1.3.",
    properties: {
      parallelizable: true,
      errorPropagation: "Single-bit errors detected by authentication tag; entire message rejected on tag mismatch",
      paddingRequired: false,
      providesAuthentication: true
    },
    securityNotes: "Nonce reuse in GCM is catastrophic: it allows both forgery and plaintext recovery through polynomial root finding in GF(2^128). The 96-bit nonce limits safe usage to 2^32 messages per key. Short tags (less than 128 bits) weaken forgery resistance. GCM is fragile against nonce misuse compared to SIV mode. Hardware support for CLMUL (carry-less multiply) instructions makes GHASH very fast.",
    useCases: [
      "TLS 1.2 and 1.3 bulk encryption (AES-128-GCM, AES-256-GCM)",
      "IPsec ESP authenticated encryption",
      "SSH encryption (aes256-gcm@openssh.com)",
      "Google Cloud and AWS server-side encryption"
    ],
    diagram: "  Nonce|Ctr=0        Nonce|Ctr=1        Nonce|Ctr=2\n      |                   |                   |\n  [Encrypt K]         [Encrypt K]         [Encrypt K]\n      |                   |                   |\n      |              Plaintext1--XOR     Plaintext2--XOR\n      |                   |                   |\n      |              Ciphertext1          Ciphertext2\n      |                   |                   |\n      |              [GHASH(H)]------>[GHASH(H)]\n      |                                       |\n      +--XOR <----- Auth Tag (GHASH output)---+\n      |\n  Final Tag"
  },
  {
    name: "CCM",
    fullName: "Counter with CBC-MAC",
    description: "Authenticated encryption mode combining CTR mode for encryption with CBC-MAC for authentication. Designed for constrained environments where code size and simplicity matter. Requires two passes over the data (one for MAC, one for encryption). Standardized in NIST SP 800-38C.",
    properties: {
      parallelizable: false,
      errorPropagation: "Errors detected by CBC-MAC tag; entire message rejected if authentication fails",
      paddingRequired: false,
      providesAuthentication: true
    },
    securityNotes: "CCM requires the message length to be known before encryption begins, which makes it unsuitable for streaming applications. The nonce length is configurable but affects the maximum message size. The two-pass nature (CBC-MAC then CTR) makes it slower than GCM's single-pass operation. Nonce reuse compromises both authenticity and confidentiality.",
    useCases: [
      "IEEE 802.11i (WPA2) wireless encryption",
      "Bluetooth Low Energy encryption",
      "TLS cipher suites (TLS_AES_128_CCM_SHA256)",
      "IoT protocols (ZigBee, Thread)"
    ],
    diagram: "  First pass: CBC-MAC over (AAD || Plaintext)\n\n  Flags|Nonce|Len    Plaintext1      Plaintext2\n       |                |                |\n   [Encrypt K]     +---XOR          +---XOR\n       |           |     |          |     |\n       +---XOR-----+ [Encrypt K]    + [Encrypt K]\n            |            |                |\n            +---......---+--------> CBC-MAC Tag\n\n  Second pass: CTR encryption of plaintext + tag\n\n  Nonce|Ctr=1      Nonce|Ctr=2      Nonce|Ctr=0\n       |                |                |\n   [Encrypt K]     [Encrypt K]     [Encrypt K]\n       |                |                |\n   Plaintext1--XOR Plaintext2--XOR  Tag--XOR\n       |                |                |\n   Ciphertext1     Ciphertext2     Enc Tag"
  },
  {
    name: "OFB",
    fullName: "Output Feedback",
    description: "Generates a keystream by repeatedly encrypting the IV (output feedback). The keystream is independent of the plaintext, allowing it to be pre-computed. Effectively converts a block cipher into a synchronous stream cipher. Errors in ciphertext do not propagate.",
    properties: {
      parallelizable: false,
      errorPropagation: "A single-bit error in ciphertext flips only the corresponding bit in plaintext (no error propagation)",
      paddingRequired: false,
      providesAuthentication: false
    },
    securityNotes: "The keystream generation cannot be parallelized since each output block depends on the previous one. Using less than the full block size for feedback was once common but creates a short-cycle vulnerability; always use full-block feedback. OFB has the unusual property that encryption and decryption are the same operation. Nonce/IV reuse produces the same keystream, which is catastrophic.",
    useCases: [
      "Satellite communication (error tolerance without propagation)",
      "Applications requiring identical encryption and decryption operations",
      "Legacy systems where pre-computation of keystream is beneficial"
    ],
    diagram: "       IV\n       |\n   [Encrypt K]----> Output1\n       |               |\n   [Encrypt K]    Plaintext1--XOR\n       |               |\n   Output2         Ciphertext1\n       |\n  Plaintext2--XOR\n       |\n  Ciphertext2\n\n  (Keystream is independent of plaintext)"
  },
  {
    name: "CFB",
    fullName: "Cipher Feedback",
    description: "Creates a self-synchronizing stream cipher from a block cipher. The previous ciphertext block is encrypted and XORed with the current plaintext to produce the current ciphertext. Similar to CBC but the XOR occurs after encryption rather than before. Can operate on segments smaller than the full block size (e.g., CFB-8 for byte-at-a-time encryption).",
    properties: {
      parallelizable: false,
      errorPropagation: "A single-bit error in ciphertext corrupts the current plaintext bit and the entire next block, then the stream re-synchronizes",
      paddingRequired: false,
      providesAuthentication: false
    },
    securityNotes: "CFB mode has self-synchronizing properties: if a bit is inserted or deleted from the ciphertext stream, the error propagates for one block length before re-synchronization. CFB-1 (1-bit CFB) processes one bit at a time but requires a full block encryption per bit, making it extremely slow. CFB decryption can be parallelized even though encryption cannot.",
    useCases: [
      "OpenPGP encryption (CFB mode with modification)",
      "Applications requiring self-synchronization after transmission errors",
      "Legacy protocols using sub-block encryption (CFB-8)"
    ],
    diagram: "       IV                  Ciphertext1           Ciphertext2\n       |                        |                      |\n   [Encrypt K]             [Encrypt K]            [Encrypt K]\n       |                        |                      |\n  Plaintext1--XOR          Plaintext2--XOR        Plaintext3--XOR\n       |                        |                      |\n  Ciphertext1              Ciphertext2            Ciphertext3\n       |                        |\n       +---feedback--->         +---feedback--->"
  },
  {
    name: "XTS",
    fullName: "XEX-based Tweaked-codebook mode with ciphertext Stealing",
    description: "Disk encryption mode designed for encrypting data on block-oriented storage devices. Uses two AES keys: one for encryption and one for generating a tweak value from the sector number. Each block within a sector is encrypted with a different tweak, preventing identical blocks at different positions from producing identical ciphertext. Standardized in IEEE 1619-2007.",
    properties: {
      parallelizable: true,
      errorPropagation: "Errors affect only the corresponding block within a sector",
      paddingRequired: false,
      providesAuthentication: false
    },
    securityNotes: "XTS does not provide authentication, which means an attacker can flip bits or reorder blocks within a sector without detection. It only protects against attacks that can observe the ciphertext (e.g., stolen disk). Ciphertext stealing allows encrypting data that is not a multiple of the block size without expanding the ciphertext. The tweak is typically derived from the sector number, ensuring each sector is encrypted differently.",
    useCases: [
      "Full-disk encryption (BitLocker, FileVault 2, LUKS)",
      "Self-encrypting drives (SED/OPAL)",
      "Storage-level encryption in enterprise systems"
    ],
    diagram: "  Key1 (encryption)    Key2 (tweak generation)\n                              |\n  Sector Number -------> [Encrypt K2] = T (tweak)\n\n  Plaintext1    Plaintext2    Plaintext3\n      |              |              |\n  T*a^0--XOR    T*a^1--XOR    T*a^2--XOR\n      |              |              |\n  [Encrypt K1]  [Encrypt K1]  [Encrypt K1]\n      |              |              |\n  T*a^0--XOR    T*a^1--XOR    T*a^2--XOR\n      |              |              |\n  Ciphertext1    Ciphertext2    Ciphertext3\n\n  (a = GF(2^128) primitive element, T varies per sector)"
  },
  {
    name: "SIV",
    fullName: "Synthetic Initialization Vector",
    description: "Nonce-misuse-resistant authenticated encryption mode defined in RFC 5297. Computes a synthetic IV from the plaintext and associated data using S2V (a PRF based on CMAC), then uses this IV as the nonce for CTR mode encryption. Provides deterministic authenticated encryption when no nonce is supplied, and nonce-misuse-resistant AE when a nonce is used.",
    properties: {
      parallelizable: true,
      errorPropagation: "Errors detected by authentication tag; entire message rejected on verification failure",
      paddingRequired: false,
      providesAuthentication: true
    },
    securityNotes: "SIV's key advantage is nonce-misuse resistance: if a nonce is accidentally reused, the only information leaked is whether the same plaintext was encrypted twice (the ciphertexts will be identical). This is the minimum possible leakage, unlike GCM where nonce reuse is catastrophic. The downside is that SIV requires two passes over the data (S2V then CTR), making it unsuitable for streaming. AES-GCM-SIV (RFC 8452) is an optimized variant.",
    useCases: [
      "Key wrapping and key management systems",
      "Environments where nonce uniqueness is hard to guarantee",
      "Database column encryption (deterministic encryption for searchability)",
      "AES-GCM-SIV in TLS 1.3 (draft)"
    ],
    diagram: "  Associated Data    Plaintext\n       |                 |\n       +-->[  S2V  ]<----+\n           (CMAC-based PRF)\n               |\n           Synthetic IV\n           /        \\\n          /          \\\n     [CTR Encrypt]   Auth Tag\n          |              |\n     Ciphertext     Appended to output\n\n  (S2V binds the IV to the plaintext, providing\n   nonce-misuse resistance)"
  }
];

const TLS_VERSIONS = [
  {
    version: "TLS 1.0",
    year: 1999,
    status: "deprecated",
    keyFeatures: [
      "First IETF standardization of SSL (based on SSL 3.0 with security fixes)",
      "HMAC-based PRF for key derivation",
      "Support for RSA, DH, and ECDH key exchange",
      "Block cipher modes CBC and stream cipher RC4",
      "Alert protocol for error signaling",
      "Standardized as RFC 2246"
    ],
    handshakeSteps: [
      "Client sends ClientHello with supported cipher suites and a client random value",
      "Server responds with ServerHello selecting cipher suite, plus its certificate",
      "Server sends ServerKeyExchange if using DHE/ECDHE (not needed for RSA key exchange)",
      "Server sends ServerHelloDone",
      "Client sends ClientKeyExchange (RSA-encrypted pre-master secret or DH public value)",
      "Client sends ChangeCipherSpec and Finished (encrypted with derived keys)",
      "Server sends ChangeCipherSpec and Finished",
      "Two round trips (2-RTT) required before application data"
    ],
    deprecatedCipherSuites: [
      "TLS_RSA_WITH_RC4_128_MD5",
      "TLS_RSA_WITH_RC4_128_SHA",
      "TLS_RSA_WITH_DES_CBC_SHA",
      "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
      "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"
    ],
    securityIssues: [
      "BEAST attack exploits predictable IV in CBC mode (IV is the last ciphertext block of the previous record)",
      "Vulnerable to POODLE when falling back to SSL 3.0",
      "No support for AEAD cipher suites (GCM, ChaCha20-Poly1305)",
      "MD5 and SHA-1 used in handshake hash, both now considered weak",
      "Deprecated by RFC 8996 (March 2021) -- must not be used",
      "Supports insecure EXPORT cipher suites with 40-bit keys"
    ]
  },
  {
    version: "TLS 1.1",
    year: 2006,
    status: "deprecated",
    keyFeatures: [
      "Explicit IV for CBC mode (fixes BEAST attack vector)",
      "Protection against CBC padding errors (alert changed from decryption_failed to bad_record_mac)",
      "IANA TLS parameter registry established",
      "Standardized as RFC 4346"
    ],
    handshakeSteps: [
      "Client sends ClientHello with supported cipher suites and client random",
      "Server responds with ServerHello, certificate, and optionally ServerKeyExchange",
      "Server sends ServerHelloDone",
      "Client sends ClientKeyExchange with key material",
      "Client sends ChangeCipherSpec and Finished",
      "Server sends ChangeCipherSpec and Finished",
      "Two round trips (2-RTT) before application data"
    ],
    deprecatedCipherSuites: [
      "TLS_RSA_WITH_RC4_128_MD5",
      "TLS_RSA_WITH_RC4_128_SHA",
      "TLS_RSA_WITH_DES_CBC_SHA",
      "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
    ],
    securityIssues: [
      "Still lacks AEAD cipher suites",
      "Uses SHA-1 in the PRF and handshake signatures",
      "No support for stronger hash algorithms in the PRF",
      "Does not support modern cipher suites like AES-GCM",
      "Deprecated by RFC 8996 (March 2021) -- must not be used",
      "Removed from all major browsers starting in 2020"
    ]
  },
  {
    version: "TLS 1.2",
    year: 2008,
    status: "current",
    keyFeatures: [
      "AEAD cipher suites (AES-GCM, AES-CCM) supported for the first time",
      "Configurable PRF hash function (SHA-256 default, SHA-384 for some suites)",
      "Signature algorithm negotiation via signature_algorithms extension",
      "Support for SHA-256 and SHA-384 in certificate verification",
      "Removal of MD5/SHA-1 requirement from PRF",
      "Standardized as RFC 5246, updated by RFC 8446"
    ],
    handshakeSteps: [
      "Client sends ClientHello with cipher suites, extensions (SNI, signature_algorithms, supported_groups)",
      "Server responds with ServerHello selecting parameters, sends certificate chain",
      "Server sends ServerKeyExchange for DHE/ECDHE with digital signature",
      "Server optionally sends CertificateRequest for mutual TLS",
      "Server sends ServerHelloDone",
      "Client sends ClientKeyExchange (ECDHE public key or RSA-encrypted pre-master secret)",
      "Client sends ChangeCipherSpec and Finished (verified with PRF)",
      "Server sends ChangeCipherSpec and Finished",
      "Two round trips (2-RTT) before application data; session resumption reduces to 1-RTT"
    ],
    deprecatedCipherSuites: [
      "TLS_RSA_WITH_RC4_128_SHA (RFC 7465 prohibits RC4)",
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA (Sweet32 attack)",
      "TLS_RSA_WITH_AES_128_CBC_SHA (no forward secrecy)",
      "TLS_RSA_WITH_AES_256_CBC_SHA (no forward secrecy)",
      "Any suite using static RSA key exchange (no forward secrecy)"
    ],
    securityIssues: [
      "Vulnerable to downgrade attacks if not properly configured (mitigated by TLS_FALLBACK_SCSV)",
      "CBC cipher suites still vulnerable to Lucky13 timing attacks",
      "Static RSA key exchange suites lack forward secrecy",
      "Renegotiation can be exploited if secure renegotiation extension is not enforced",
      "Complex configuration surface -- easy to deploy insecurely with weak cipher suites",
      "Handshake hash uses only SHA-256, not negotiated stronger algorithms"
    ]
  },
  {
    version: "TLS 1.3",
    year: 2018,
    status: "recommended",
    keyFeatures: [
      "Only AEAD cipher suites permitted (GCM, CCM, ChaCha20-Poly1305)",
      "Forward secrecy required for all connections (only DHE and ECDHE key exchange)",
      "1-RTT handshake (reduced from 2-RTT in TLS 1.2)",
      "0-RTT resumption mode for repeat connections (with replay protection caveats)",
      "Handshake messages encrypted after ServerHello",
      "Simplified cipher suite negotiation (key exchange and authentication separated from cipher suite)",
      "Removed RSA key transport, CBC mode, RC4, SHA-1, MD5, DES, 3DES, EXPORT ciphers, and compression",
      "HKDF-based key schedule replacing the legacy PRF",
      "Downgrade protection built into the ServerHello random field",
      "Standardized as RFC 8446"
    ],
    handshakeSteps: [
      "Client sends ClientHello with supported cipher suites, key_share (ECDHE public keys), and supported_groups",
      "Server selects parameters, sends ServerHello with its key_share",
      "Server derives handshake keys and sends encrypted EncryptedExtensions, Certificate, and CertificateVerify",
      "Server sends encrypted Finished message",
      "Client verifies server's certificate and Finished, derives application keys",
      "Client sends encrypted Finished message",
      "One round trip (1-RTT) before application data; 0-RTT possible for resumed sessions"
    ],
    deprecatedCipherSuites: [
      "All non-AEAD suites removed entirely",
      "All CBC mode suites removed",
      "All RC4 suites removed",
      "All static RSA and static DH suites removed",
      "All EXPORT suites removed",
      "All suites using MD5 or SHA-1 for record protection removed"
    ],
    securityIssues: [
      "0-RTT data is vulnerable to replay attacks (applications must implement replay protection)",
      "0-RTT early data cannot carry non-idempotent requests safely",
      "Middlebox compatibility mode adds a dummy ChangeCipherSpec for traversal through broken network equipment",
      "Downgrade attacks from TLS 1.3 to 1.2 are detectable but require client implementation vigilance",
      "Encrypted ClientHello (ECH) is still in draft, meaning SNI leaks the target hostname"
    ]
  }
];

const CIPHER_SUITES = [
  // TLS 1.3 cipher suites (5 suites)
  {
    name: "TLS_AES_256_GCM_SHA384",
    keyExchange: "Any (negotiated separately in TLS 1.3)",
    authentication: "Any (negotiated separately in TLS 1.3)",
    bulkCipher: "AES-256-GCM",
    mac: "AEAD (SHA-384 for HKDF)",
    tlsVersion: "TLS 1.3",
    status: "recommended",
    forwardSecrecy: true
  },
  {
    name: "TLS_AES_128_GCM_SHA256",
    keyExchange: "Any (negotiated separately in TLS 1.3)",
    authentication: "Any (negotiated separately in TLS 1.3)",
    bulkCipher: "AES-128-GCM",
    mac: "AEAD (SHA-256 for HKDF)",
    tlsVersion: "TLS 1.3",
    status: "recommended",
    forwardSecrecy: true
  },
  {
    name: "TLS_CHACHA20_POLY1305_SHA256",
    keyExchange: "Any (negotiated separately in TLS 1.3)",
    authentication: "Any (negotiated separately in TLS 1.3)",
    bulkCipher: "ChaCha20-Poly1305",
    mac: "AEAD (SHA-256 for HKDF)",
    tlsVersion: "TLS 1.3",
    status: "recommended",
    forwardSecrecy: true
  },
  {
    name: "TLS_AES_128_CCM_SHA256",
    keyExchange: "Any (negotiated separately in TLS 1.3)",
    authentication: "Any (negotiated separately in TLS 1.3)",
    bulkCipher: "AES-128-CCM",
    mac: "AEAD (SHA-256 for HKDF)",
    tlsVersion: "TLS 1.3",
    status: "recommended",
    forwardSecrecy: true
  },
  {
    name: "TLS_AES_128_CCM_8_SHA256",
    keyExchange: "Any (negotiated separately in TLS 1.3)",
    authentication: "Any (negotiated separately in TLS 1.3)",
    bulkCipher: "AES-128-CCM-8 (short tag)",
    mac: "AEAD (SHA-256 for HKDF)",
    tlsVersion: "TLS 1.3",
    status: "recommended",
    forwardSecrecy: true
  },
  // TLS 1.2 ECDHE suites - recommended (10 suites)
  {
    name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "AES-256-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "recommended",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "AES-128-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "recommended",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    keyExchange: "ECDHE",
    authentication: "ECDSA",
    bulkCipher: "AES-256-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "recommended",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    keyExchange: "ECDHE",
    authentication: "ECDSA",
    bulkCipher: "AES-128-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "recommended",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "ChaCha20-Poly1305",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "recommended",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    keyExchange: "ECDHE",
    authentication: "ECDSA",
    bulkCipher: "ChaCha20-Poly1305",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "recommended",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "AES-256-CBC",
    mac: "SHA-384",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "AES-128-CBC",
    mac: "SHA-256",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    keyExchange: "ECDHE",
    authentication: "ECDSA",
    bulkCipher: "AES-256-CBC",
    mac: "SHA-384",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    keyExchange: "ECDHE",
    authentication: "ECDSA",
    bulkCipher: "AES-128-CBC",
    mac: "SHA-256",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  // TLS 1.2 DHE suites - acceptable (6 suites)
  {
    name: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    keyExchange: "DHE",
    authentication: "RSA",
    bulkCipher: "AES-256-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    keyExchange: "DHE",
    authentication: "RSA",
    bulkCipher: "AES-128-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    keyExchange: "DHE",
    authentication: "RSA",
    bulkCipher: "AES-256-CBC",
    mac: "SHA-256",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    keyExchange: "DHE",
    authentication: "RSA",
    bulkCipher: "AES-128-CBC",
    mac: "SHA-256",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    keyExchange: "DHE",
    authentication: "RSA",
    bulkCipher: "ChaCha20-Poly1305",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    keyExchange: "DHE",
    authentication: "RSA",
    bulkCipher: "AES-256-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  // TLS 1.2 static RSA key exchange - deprecated (6 suites)
  {
    name: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "AES-256-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "deprecated",
    forwardSecrecy: false
  },
  {
    name: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "AES-128-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "deprecated",
    forwardSecrecy: false
  },
  {
    name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "AES-256-CBC",
    mac: "SHA-256",
    tlsVersion: "TLS 1.2",
    status: "deprecated",
    forwardSecrecy: false
  },
  {
    name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "AES-128-CBC",
    mac: "SHA-256",
    tlsVersion: "TLS 1.2",
    status: "deprecated",
    forwardSecrecy: false
  },
  {
    name: "TLS_RSA_WITH_AES_256_CBC_SHA",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "AES-256-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.2",
    status: "deprecated",
    forwardSecrecy: false
  },
  {
    name: "TLS_RSA_WITH_AES_128_CBC_SHA",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "AES-128-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.2",
    status: "deprecated",
    forwardSecrecy: false
  },
  // TLS 1.2 Camellia suites - acceptable (4 suites)
  {
    name: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "Camellia-256-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "Camellia-128-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    keyExchange: "DHE",
    authentication: "RSA",
    bulkCipher: "Camellia-256-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    keyExchange: "DHE",
    authentication: "RSA",
    bulkCipher: "Camellia-128-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  // Insecure suites - RC4 (4 suites)
  {
    name: "TLS_RSA_WITH_RC4_128_SHA",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "RC4-128",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0-1.2",
    status: "insecure",
    forwardSecrecy: false
  },
  {
    name: "TLS_RSA_WITH_RC4_128_MD5",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "RC4-128",
    mac: "MD5",
    tlsVersion: "TLS 1.0-1.2",
    status: "insecure",
    forwardSecrecy: false
  },
  {
    name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "RC4-128",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0-1.2",
    status: "insecure",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    keyExchange: "ECDHE",
    authentication: "ECDSA",
    bulkCipher: "RC4-128",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0-1.2",
    status: "insecure",
    forwardSecrecy: true
  },
  // Insecure suites - DES and 3DES (3 suites)
  {
    name: "TLS_RSA_WITH_DES_CBC_SHA",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "DES-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0-1.1",
    status: "insecure",
    forwardSecrecy: false
  },
  {
    name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "3DES-EDE-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0-1.2",
    status: "insecure",
    forwardSecrecy: false
  },
  {
    name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "3DES-EDE-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0-1.2",
    status: "insecure",
    forwardSecrecy: true
  },
  // Insecure suites - NULL encryption (3 suites)
  {
    name: "TLS_RSA_WITH_NULL_MD5",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "NULL",
    mac: "MD5",
    tlsVersion: "TLS 1.0-1.2",
    status: "insecure",
    forwardSecrecy: false
  },
  {
    name: "TLS_RSA_WITH_NULL_SHA",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "NULL",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0-1.2",
    status: "insecure",
    forwardSecrecy: false
  },
  {
    name: "TLS_RSA_WITH_NULL_SHA256",
    keyExchange: "RSA",
    authentication: "RSA",
    bulkCipher: "NULL",
    mac: "SHA-256",
    tlsVersion: "TLS 1.2",
    status: "insecure",
    forwardSecrecy: false
  },
  // Insecure suites - EXPORT grade (3 suites)
  {
    name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    keyExchange: "RSA (512-bit export)",
    authentication: "RSA",
    bulkCipher: "RC4-40",
    mac: "MD5",
    tlsVersion: "TLS 1.0",
    status: "insecure",
    forwardSecrecy: false
  },
  {
    name: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    keyExchange: "RSA (512-bit export)",
    authentication: "RSA",
    bulkCipher: "DES40-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0",
    status: "insecure",
    forwardSecrecy: false
  },
  {
    name: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    keyExchange: "DHE (512-bit export)",
    authentication: "RSA",
    bulkCipher: "DES40-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0",
    status: "insecure",
    forwardSecrecy: true
  },
  // Additional ECDHE suites with older SHA-1 MAC (2 suites)
  {
    name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "AES-256-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0-1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  {
    name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    keyExchange: "ECDHE",
    authentication: "RSA",
    bulkCipher: "AES-128-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0-1.2",
    status: "acceptable",
    forwardSecrecy: true
  },
  // Anonymous key exchange - insecure (2 suites)
  {
    name: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    keyExchange: "DH (anonymous)",
    authentication: "None",
    bulkCipher: "AES-256-GCM",
    mac: "AEAD",
    tlsVersion: "TLS 1.2",
    status: "insecure",
    forwardSecrecy: false
  },
  {
    name: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    keyExchange: "ECDH (anonymous)",
    authentication: "None",
    bulkCipher: "AES-128-CBC",
    mac: "SHA-1",
    tlsVersion: "TLS 1.0-1.2",
    status: "insecure",
    forwardSecrecy: false
  }
];

const CRYPTO_ATTACKS = [
  {
    name: "Birthday Attack",
    target: "Hash functions and MACs",
    description: "Exploits the birthday paradox in probability theory to find collisions in hash functions. For an n-bit hash function, the expected number of random inputs to find a collision is approximately 2^(n/2), not 2^n. This means a 128-bit hash like MD5 provides only 64 bits of collision resistance, making collision finding feasible with modern hardware.",
    prerequisites: [
      "Ability to compute a large number of hash values",
      "Sufficient storage to compare computed hashes",
      "Target hash function with output smaller than ~256 bits for practical attacks"
    ],
    impact: "Collision allows attacker to create two different documents with the same hash, enabling certificate forgery, code signing bypass, or integrity check circumvention.",
    mitigation: "Use hash functions with output size at least twice the desired security level (e.g., SHA-256 for 128-bit collision resistance). Avoid MD5 and SHA-1 where collision resistance matters.",
    cveId: null
  },
  {
    name: "Length Extension Attack",
    target: "Merkle-Damgard hash functions (MD5, SHA-1, SHA-256, SHA-512)",
    description: "Exploits the Merkle-Damgard construction where the hash of a message is the internal state of the hash function after processing the message. An attacker who knows H(secret || message) and the length of the secret can compute H(secret || message || padding || extension) without knowing the secret. This breaks naive MAC constructions of the form H(key || message).",
    prerequisites: [
      "Knowledge of H(secret || message) for some message",
      "Knowledge of the length of the secret (or ability to guess it)",
      "Target system uses H(key || message) as a MAC instead of HMAC"
    ],
    impact: "Attacker can forge MACs for extended messages without knowing the key, leading to authentication bypass in APIs and web applications using naive hash-based authentication.",
    mitigation: "Use HMAC (RFC 2104) instead of raw H(key || message). Alternatively, use SHA-3 or BLAKE2/BLAKE3 which are resistant to length extension attacks due to their sponge or tree construction.",
    cveId: null
  },
  {
    name: "Padding Oracle Attack",
    target: "CBC mode block ciphers with padding validation",
    description: "Exploits systems that reveal whether a ciphertext has valid padding after decryption. By manipulating ciphertext bytes and observing whether the server reports a padding error versus a different error, the attacker can decrypt ciphertext one byte at a time without the key. Each byte requires at most 256 oracle queries, making full decryption practical.",
    prerequisites: [
      "Target uses CBC mode with PKCS#7 or similar padding",
      "Attacker can submit modified ciphertexts for decryption",
      "Decryption oracle distinguishes padding errors from other errors (via error messages, timing, or behavior)"
    ],
    impact: "Complete plaintext recovery of encrypted data without knowing the encryption key. Can also be used for encryption of arbitrary plaintext in some implementations.",
    mitigation: "Use authenticated encryption (AES-GCM, ChaCha20-Poly1305) instead of CBC. If CBC must be used, apply encrypt-then-MAC and verify the MAC before attempting decryption. Ensure constant-time comparison and uniform error responses.",
    cveId: "CVE-2014-3566"
  },
  {
    name: "BEAST",
    target: "TLS 1.0 CBC cipher suites",
    description: "Browser Exploit Against SSL/TLS, demonstrated by Thai Duong and Juliano Rizzo in 2011. Exploits TLS 1.0's use of the last ciphertext block as the IV for the next record, making the IV predictable. The attacker uses a chosen-plaintext attack via JavaScript in the browser to decrypt HTTPS cookies one byte at a time by observing whether guessed plaintext blocks produce expected ciphertext patterns.",
    prerequisites: [
      "Target uses TLS 1.0 with CBC mode cipher suites",
      "Attacker can inject chosen plaintext into the encrypted stream (e.g., via JavaScript in same-origin or adjacent context)",
      "Attacker can observe the resulting ciphertext"
    ],
    impact: "Decryption of sensitive data such as session cookies transmitted over HTTPS, enabling session hijacking.",
    mitigation: "Upgrade to TLS 1.1+ which uses explicit, random IVs for each record. Apply 1/n-1 record splitting as a workaround for TLS 1.0. Prefer AEAD cipher suites (GCM, ChaCha20-Poly1305) which are not affected.",
    cveId: "CVE-2011-3389"
  },
  {
    name: "CRIME",
    target: "TLS compression",
    description: "Compression Ratio Info-leak Made Easy, demonstrated by Juliano Rizzo and Thai Duong in 2012. Exploits TLS-level compression by observing how the compressed ciphertext size changes when attacker-controlled data is compressed alongside secret data (such as session cookies). If the attacker's guess matches part of the secret, the compressed size decreases, leaking the secret one byte at a time.",
    prerequisites: [
      "Target uses TLS-level compression (DEFLATE)",
      "Attacker can inject chosen plaintext into the compressed stream",
      "Attacker can observe the length of encrypted TLS records"
    ],
    impact: "Recovery of secret values such as session cookies or CSRF tokens from HTTPS-protected requests.",
    mitigation: "Disable TLS-level compression (all modern browsers and servers disable it by default). TLS 1.3 removed compression entirely from the protocol.",
    cveId: "CVE-2012-4929"
  },
  {
    name: "BREACH",
    target: "HTTP compression over TLS",
    description: "Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext. An extension of the CRIME attack that targets HTTP-level compression (gzip/deflate) rather than TLS-level compression. Since HTTP compression is far more common than TLS compression, BREACH has broader applicability. The attacker makes the victim's browser issue requests and observes the compressed response sizes to extract secrets reflected in the response body.",
    prerequisites: [
      "Target uses HTTP-level compression (Content-Encoding: gzip)",
      "Response body contains a secret value (CSRF token, session identifier)",
      "Attacker can cause the victim to make requests to the target with attacker-controlled input reflected in the response",
      "Attacker can observe response sizes"
    ],
    impact: "Extraction of CSRF tokens, session identifiers, and other secrets from compressed HTTPS responses in as few as 1,000 requests.",
    mitigation: "Separate secrets from user-controlled content in responses. Use per-request CSRF tokens. Add random padding to responses. Rate-limit requests. Disable HTTP compression for pages containing sensitive tokens.",
    cveId: "CVE-2013-3587"
  },
  {
    name: "POODLE",
    target: "SSL 3.0 and TLS 1.0 CBC cipher suites",
    description: "Padding Oracle On Downgraded Legacy Encryption, published by Google researchers in 2014. Exploits a design flaw in SSL 3.0's CBC padding: SSL 3.0 specifies that the padding content is not checked, only the padding length byte. This allows an attacker to modify padding bytes and determine whether decrypted plaintext ends with a valid padding byte, creating a padding oracle. A variant affects some TLS implementations that do not properly validate padding.",
    prerequisites: [
      "Target supports SSL 3.0 (or TLS implementation with padding validation bug)",
      "Attacker can perform a protocol downgrade to SSL 3.0 (e.g., via network interference)",
      "Attacker can inject chosen plaintext and observe server responses"
    ],
    impact: "Decryption of HTTPS session cookies and other sensitive data, enabling session hijacking. Each byte requires approximately 256 requests to decrypt.",
    mitigation: "Disable SSL 3.0 entirely. Implement TLS_FALLBACK_SCSV to prevent downgrade attacks. Use TLS 1.2+ with AEAD cipher suites.",
    cveId: "CVE-2014-3566"
  },
  {
    name: "DROWN",
    target: "Servers supporting SSLv2 alongside modern TLS",
    description: "Decrypting RSA with Obsolete and Weakened eNcryption. Exploits servers that support SSLv2 (even if TLS connections do not use it) by performing a Bleichenbacher-style attack against SSLv2's export-grade cryptography. The attacker captures modern TLS handshakes using RSA key exchange and then uses SSLv2 connections to the same server (or another server sharing the same RSA key) as a decryption oracle.",
    prerequisites: [
      "Server supports SSLv2 or shares an RSA private key with a server that supports SSLv2",
      "Target TLS connections use RSA key exchange (not ECDHE)",
      "Attacker can capture TLS handshakes and connect to the SSLv2 endpoint"
    ],
    impact: "Decryption of passively captured TLS sessions that used RSA key exchange. A general DROWN attack requires 2^50 SSLv2 connections; a special DROWN variant against OpenSSL is much faster.",
    mitigation: "Disable SSLv2 on all servers. Ensure RSA private keys are not shared between servers that support SSLv2 and those that do not. Use ECDHE key exchange for forward secrecy.",
    cveId: "CVE-2016-0800"
  },
  {
    name: "Bleichenbacher Attack",
    target: "RSA PKCS#1 v1.5 encryption padding",
    description: "An adaptive chosen-ciphertext attack against RSA PKCS#1 v1.5 padding, published by Daniel Bleichenbacher in 1998. The attacker sends modified ciphertexts to a server and observes whether the server indicates that the PKCS#1 v1.5 padding is valid. By systematically narrowing the range of possible plaintexts through millions of carefully chosen ciphertexts, the attacker eventually recovers the full plaintext (including the pre-master secret in TLS).",
    prerequisites: [
      "Target uses RSA PKCS#1 v1.5 for key transport (e.g., TLS RSA key exchange)",
      "Server reveals whether PKCS#1 v1.5 padding is valid (via error messages, timing, or alerts)",
      "Attacker can send a large number of modified ciphertexts (typically millions)"
    ],
    impact: "Recovery of RSA-encrypted pre-master secret in TLS, allowing decryption of the entire session. Can also be used to forge RSA signatures in some contexts.",
    mitigation: "Use RSA-OAEP instead of PKCS#1 v1.5 for encryption. In TLS, use ECDHE key exchange instead of RSA key transport. Implement constant-time padding validation and generate a random pre-master secret on padding failure (as specified in TLS RFC).",
    cveId: null
  },
  {
    name: "ROBOT",
    target: "RSA PKCS#1 v1.5 in TLS implementations",
    description: "Return Of Bleichenbacher's Oracle Threat, published in 2017. Demonstrates that the original Bleichenbacher attack from 1998 still affects many modern TLS implementations despite nearly 20 years of patches. The researchers found that timing differences, error code variations, and connection behavior in servers from F5, Citrix, Cisco, and others still leak whether RSA PKCS#1 v1.5 padding is valid.",
    prerequisites: [
      "Target TLS server supports RSA key exchange cipher suites",
      "Implementation has subtle timing or behavior differences for valid vs. invalid PKCS#1 padding",
      "Attacker can send many TLS handshake messages to the server"
    ],
    impact: "Passive decryption of recorded TLS sessions using RSA key exchange. Affects TLS connections to major vendors including F5 BIG-IP, Citrix, and Cisco ACE.",
    mitigation: "Disable RSA key exchange cipher suites entirely and use only ECDHE-based suites. Apply vendor patches for affected implementations. Use TLS 1.3 which removed RSA key transport.",
    cveId: "CVE-2017-13099"
  },
  {
    name: "Sweet32",
    target: "64-bit block ciphers (3DES, Blowfish, IDEA)",
    description: "A birthday attack against block ciphers with 64-bit block sizes. After encrypting 2^32 blocks (approximately 32 GB) with the same key in CBC mode, the probability of a block collision reaches 50%. When a collision occurs, the attacker can XOR the two ciphertext blocks to obtain the XOR of the corresponding plaintext blocks. In a web context, an attacker who can trigger long-lived HTTPS connections can recover HTTP cookies.",
    prerequisites: [
      "Target uses a 64-bit block cipher (3DES, Blowfish) in CBC or similar mode",
      "A single key is used to encrypt more than 2^32 blocks (32 GB) of data",
      "Attacker can observe the ciphertext and cause the victim to send large amounts of known or partially-known data"
    ],
    impact: "Recovery of secret data (such as HTTP cookies) transmitted over long-lived connections encrypted with 64-bit block ciphers.",
    mitigation: "Avoid 64-bit block ciphers entirely. Use AES (128-bit block) or ChaCha20. If 3DES must be used, rekey after 2^20 blocks (approximately 8 MB) to prevent the birthday bound from being reached.",
    cveId: "CVE-2016-2183"
  },
  {
    name: "Timing Attack",
    target: "Non-constant-time cryptographic implementations",
    description: "A side-channel attack that exploits variations in execution time to extract secret information. For example, a string comparison that returns early on the first non-matching byte reveals information about the correct value. In cryptographic contexts, RSA implementations with non-constant-time modular exponentiation leak bits of the private key through timing measurements. Kocher's 1996 paper demonstrated this against RSA, DH, and DSS.",
    prerequisites: [
      "Target implementation has data-dependent execution time",
      "Attacker can make repeated queries and measure response time with sufficient precision",
      "Noise in timing measurements is manageable (local attacks are easier than remote)"
    ],
    impact: "Extraction of private keys, passwords, or other secrets through statistical analysis of timing data. Remote timing attacks have been demonstrated against TLS servers.",
    mitigation: "Use constant-time implementations for all operations involving secret data. Use constant-time comparison functions for MAC verification. Avoid branching on secret data. Use blinding techniques for RSA operations.",
    cveId: null
  },
  {
    name: "Cache-Timing Attack",
    target: "AES and other table-lookup-based cipher implementations",
    description: "A side-channel attack exploiting CPU cache behavior to extract cryptographic keys. When a cipher implementation uses lookup tables (T-tables in AES), the memory access pattern depends on the secret key. An attacker sharing the same CPU can monitor cache lines using techniques like Flush+Reload or Prime+Probe to determine which table entries were accessed, revealing key bits. Demonstrated to extract full AES keys from co-located virtual machines.",
    prerequisites: [
      "Attacker has code execution on the same physical CPU as the victim (co-located VMs, shared hosting)",
      "Target uses table-lookup-based cipher implementation (not bitsliced or AES-NI)",
      "Attacker can trigger or observe encryption operations with high timing resolution"
    ],
    impact: "Full recovery of AES encryption keys from co-located processes. Demonstrated in cloud environments (cross-VM attacks) and local privilege escalation scenarios.",
    mitigation: "Use hardware AES instructions (AES-NI) which do not use lookup tables. Use bitsliced implementations. Use constant-time scatter/gather instructions. Deploy cache partitioning in cloud environments.",
    cveId: null
  },
  {
    name: "Power Analysis",
    target: "Hardware cryptographic implementations",
    description: "A side-channel attack measuring the power consumption of a device during cryptographic operations. Simple Power Analysis (SPA) directly interprets power traces to distinguish operations (e.g., square vs. multiply in RSA). Differential Power Analysis (DPA) uses statistical analysis of many power traces to extract secret keys by correlating predicted power consumption with measured values. A single power trace can reveal an RSA private key in unprotected implementations.",
    prerequisites: [
      "Physical access to the target device",
      "Ability to measure power consumption with sufficient precision (oscilloscope and current probe)",
      "Ability to trigger cryptographic operations with known or chosen inputs"
    ],
    impact: "Complete extraction of cryptographic keys from smart cards, embedded devices, and hardware security modules that lack countermeasures.",
    mitigation: "Implement power analysis countermeasures: random delays, operation shuffling, masking (randomizing intermediate values), dual-rail logic. Use certified hardware with DPA resistance (Common Criteria, FIPS 140-2/3 Level 3+).",
    cveId: null
  },
  {
    name: "Meet-in-the-Middle Attack",
    target: "Multiple-encryption schemes (Double DES, Triple DES 3-key)",
    description: "A time-memory tradeoff attack against schemes that apply encryption multiple times with independent keys. Instead of brute-forcing the combined key space (2^(k1+k2) for two keys), the attacker encrypts the plaintext with all possible first keys and decrypts the ciphertext with all possible second keys, looking for matches. This reduces double encryption from 2^(2k) to 2^(k+1) time with 2^k storage. This attack is why Double DES provides only 57 bits of security despite using 112-bit total key material.",
    prerequisites: [
      "Target uses multiple independent encryption passes with separate keys",
      "At least one known plaintext-ciphertext pair",
      "Sufficient memory to store 2^k intermediate values"
    ],
    impact: "Reduces the effective security of double encryption to barely more than single encryption. Makes Triple DES with three independent 56-bit keys provide only 112 bits of security instead of the expected 168 bits.",
    mitigation: "Use single-pass ciphers with sufficiently long keys (AES-256) instead of multiple passes of weaker ciphers. When multiple encryption is necessary, use constructions proven resistant to meet-in-the-middle (e.g., triple encryption with EDE provides 2k security).",
    cveId: null
  },
  {
    name: "Related-Key Attack",
    target: "Block cipher key schedules (AES-256, KASUMI)",
    description: "An attack where the adversary can observe encryption under multiple keys that have a known or chosen mathematical relationship (such as XOR differences). The attack exploits weaknesses in the key schedule that cause related keys to produce related subkeys. Biryukov and Khovratovich demonstrated related-key attacks on full AES-256 and AES-192 in 2009, though these require the impractical assumption that the attacker can choose key relationships.",
    prerequisites: [
      "Attacker can cause encryption under keys with known mathematical relationships",
      "Target cipher's key schedule does not provide sufficient independence between related keys",
      "Multiple encryption operations observable under related keys"
    ],
    impact: "In theoretical models, allows distinguishing the cipher from a random permutation or recovering the key. For AES-256, the attack finds a related-key distinguisher with 2^99.5 time and data complexity. Practical impact is limited because real-world protocols rarely allow related-key scenarios.",
    mitigation: "Ensure protocols never use related keys for different encryption operations. Derive independent keys using a KDF (HKDF) from a master secret. The attack does not affect AES security in standard single-key usage.",
    cveId: null
  },
  {
    name: "Differential Cryptanalysis",
    target: "Block ciphers (DES, reduced-round AES, FEAL)",
    description: "A general attack technique introduced by Biham and Shamir in 1990 that studies how differences in plaintext pairs propagate through the cipher to produce differences in ciphertext pairs. By choosing plaintext pairs with specific XOR differences and analyzing the resulting ciphertext differences, the attacker can determine information about the secret key. DES was designed with resistance to this attack (which the NSA knew about since the 1970s), but FEAL and other ciphers are highly vulnerable.",
    prerequisites: [
      "Ability to encrypt chosen plaintext pairs with specific differences",
      "Knowledge of the cipher's S-box differential properties",
      "Sufficient number of plaintext-ciphertext pairs (depends on cipher; 2^47 for DES)"
    ],
    impact: "Recovery of the secret key with fewer operations than brute force. For DES, 2^47 chosen plaintexts suffice (versus 2^55 for brute force). FEAL-4 can be broken with just 8 chosen plaintexts.",
    mitigation: "Modern ciphers (AES, ChaCha20) are designed with provable resistance to differential cryptanalysis. AES requires 2^128 or more chosen plaintexts for a differential attack, exceeding the codebook limit. Use well-analyzed ciphers with known differential bounds.",
    cveId: null
  }
];

const POST_QUANTUM = [
  {
    name: "ML-KEM",
    formerName: "Kyber",
    type: "KEM",
    description: "Module-Lattice-based Key Encapsulation Mechanism, formerly known as CRYSTALS-Kyber. Selected by NIST as the primary post-quantum KEM standard (FIPS 203). Based on the hardness of the Module Learning With Errors (MLWE) problem. Uses polynomial rings over a power-of-two cyclotomic ring with modular arithmetic for efficient implementation.",
    keySizes: {
      "ML-KEM-512": { publicKey: 800, secretKey: 1632, ciphertext: 768, sharedSecret: 32, securityLevel: "NIST Level 1 (equivalent to AES-128)" },
      "ML-KEM-768": { publicKey: 1184, secretKey: 2400, ciphertext: 1088, sharedSecret: 32, securityLevel: "NIST Level 3 (equivalent to AES-192)" },
      "ML-KEM-1024": { publicKey: 1568, secretKey: 3168, ciphertext: 1568, sharedSecret: 32, securityLevel: "NIST Level 5 (equivalent to AES-256)" }
    },
    signatureSizes: null,
    nistStatus: "Standardized as FIPS 203 (August 2024). Primary recommended KEM for post-quantum key exchange.",
    performanceNotes: "Very fast key generation, encapsulation, and decapsulation. Performance is competitive with or faster than ECDH on most platforms. Small public keys and ciphertexts compared to other post-quantum KEMs. NTT-based polynomial multiplication enables efficient implementation."
  },
  {
    name: "ML-DSA",
    formerName: "Dilithium",
    type: "signature",
    description: "Module-Lattice-based Digital Signature Algorithm, formerly known as CRYSTALS-Dilithium. Selected by NIST as the primary post-quantum digital signature standard (FIPS 204). Based on the hardness of the Module Learning With Errors (MLWE) and Module Short Integer Solution (MSIS) problems. Uses a Fiat-Shamir with Aborts framework.",
    keySizes: {
      "ML-DSA-44": { publicKey: 1312, secretKey: 2560, securityLevel: "NIST Level 2 (equivalent to SHA-256 collision resistance)" },
      "ML-DSA-65": { publicKey: 1952, secretKey: 4032, securityLevel: "NIST Level 3 (equivalent to AES-192)" },
      "ML-DSA-87": { publicKey: 2592, secretKey: 4896, securityLevel: "NIST Level 5 (equivalent to AES-256)" }
    },
    signatureSizes: {
      "ML-DSA-44": 2420,
      "ML-DSA-65": 3309,
      "ML-DSA-87": 4627
    },
    nistStatus: "Standardized as FIPS 204 (August 2024). Primary recommended signature algorithm for post-quantum digital signatures.",
    performanceNotes: "Fast signing and verification. Key generation is very fast. Signature sizes are moderate (2-5 KB). The rejection sampling (abort) step in signing means signing time has some variance but averages well. Deterministic signing is supported to avoid nonce-related vulnerabilities."
  },
  {
    name: "FALCON",
    formerName: null,
    type: "signature",
    description: "Fast-Fourier Lattice-based Compact Signatures over NTRU. Selected by NIST as an additional post-quantum signature standard. Based on the hardness of the NTRU lattice problem and uses a hash-and-sign paradigm with a trapdoor sampler over NTRU lattices. Produces the most compact signatures among lattice-based schemes.",
    keySizes: {
      "FALCON-512": { publicKey: 897, secretKey: 1281, securityLevel: "NIST Level 1 (equivalent to AES-128)" },
      "FALCON-1024": { publicKey: 1793, secretKey: 2305, securityLevel: "NIST Level 5 (equivalent to AES-256)" }
    },
    signatureSizes: {
      "FALCON-512": 666,
      "FALCON-1024": 1280
    },
    nistStatus: "Selected for standardization by NIST (draft FIPS 206). Recommended when compact signatures are critical.",
    performanceNotes: "Very compact signatures (smallest among NIST PQC finalists). Verification is very fast. Signing requires floating-point arithmetic for the discrete Gaussian sampler, which makes implementation more complex and potentially vulnerable to side-channel attacks. Signing is slower than ML-DSA. Constant-time implementation of the sampler is challenging."
  },
  {
    name: "SPHINCS+",
    formerName: null,
    type: "signature",
    description: "Stateless hash-based signature scheme. Selected by NIST as FIPS 205 (SLH-DSA). Based only on the security of hash functions, making it the most conservative post-quantum signature scheme with minimal cryptographic assumptions. Uses a hypertree of many-time signature schemes (XMSS-like trees) to build a stateless scheme from Winternitz one-time signatures and FORS (Forest of Random Subsets).",
    keySizes: {
      "SLH-DSA-SHA2-128s": { publicKey: 32, secretKey: 64, securityLevel: "NIST Level 1 (small signature variant)" },
      "SLH-DSA-SHA2-128f": { publicKey: 32, secretKey: 64, securityLevel: "NIST Level 1 (fast signing variant)" },
      "SLH-DSA-SHA2-256s": { publicKey: 64, secretKey: 128, securityLevel: "NIST Level 5 (small signature variant)" },
      "SLH-DSA-SHA2-256f": { publicKey: 64, secretKey: 128, securityLevel: "NIST Level 5 (fast signing variant)" }
    },
    signatureSizes: {
      "SLH-DSA-SHA2-128s": 7856,
      "SLH-DSA-SHA2-128f": 17088,
      "SLH-DSA-SHA2-256s": 29792,
      "SLH-DSA-SHA2-256f": 49856
    },
    nistStatus: "Standardized as FIPS 205 / SLH-DSA (August 2024). Recommended as a conservative backup due to minimal assumptions.",
    performanceNotes: "Very small public keys (32-64 bytes) but large signatures (8-50 KB). Signing is slow, especially for the 's' (small signature) variants. Verification is moderate. The 'f' (fast) variants trade larger signatures for faster signing. The scheme's security relies only on the security of the underlying hash function, providing confidence even if lattice problems are broken."
  },
  {
    name: "BIKE",
    formerName: null,
    type: "KEM",
    description: "Bit Flipping Key Encapsulation. A code-based KEM founded on the hardness of the syndrome decoding problem for quasi-cyclic moderate-density parity-check (QC-MDPC) codes. Uses iterative bit-flipping decoding. BIKE offers compact key and ciphertext sizes for a code-based scheme and is a candidate in NIST's fourth round of post-quantum standardization.",
    keySizes: {
      "BIKE-Level1": { publicKey: 1541, secretKey: 3749, ciphertext: 1573, sharedSecret: 32, securityLevel: "NIST Level 1 (equivalent to AES-128)" },
      "BIKE-Level3": { publicKey: 3083, secretKey: 7467, ciphertext: 3115, sharedSecret: 32, securityLevel: "NIST Level 3 (equivalent to AES-192)" }
    },
    signatureSizes: null,
    nistStatus: "NIST Round 4 candidate. Under evaluation for potential future standardization alongside ML-KEM.",
    performanceNotes: "Decapsulation involves iterative decoding which has variable runtime, complicating constant-time implementations. Key generation and encapsulation are fast. The decoding failure rate must be kept negligibly low (below 2^-128) to prevent key recovery attacks via decoding failure information."
  },
  {
    name: "HQC",
    formerName: null,
    type: "KEM",
    description: "Hamming Quasi-Cyclic. A code-based KEM based on the hardness of decoding random quasi-cyclic codes in the Hamming metric. Combines a public-key encryption scheme with a KEM transformation. Uses tensor product codes (a combination of a quasi-cyclic code with a Reed-Muller or Reed-Solomon code) for decryption error correction.",
    keySizes: {
      "HQC-128": { publicKey: 2249, secretKey: 2289, ciphertext: 4497, sharedSecret: 64, securityLevel: "NIST Level 1 (equivalent to AES-128)" },
      "HQC-192": { publicKey: 4522, secretKey: 4562, ciphertext: 9042, sharedSecret: 64, securityLevel: "NIST Level 3 (equivalent to AES-192)" },
      "HQC-256": { publicKey: 7245, secretKey: 7285, ciphertext: 14469, sharedSecret: 64, securityLevel: "NIST Level 5 (equivalent to AES-256)" }
    },
    signatureSizes: null,
    nistStatus: "NIST Round 4 candidate. Selected for continued evaluation as an alternative code-based KEM.",
    performanceNotes: "Larger ciphertexts than ML-KEM but based on different mathematical assumptions (coding theory vs. lattices), providing cryptographic diversity. Encapsulation and decapsulation are reasonably fast. Implementation is simpler than BIKE as it does not require iterative decoding."
  },
  {
    name: "Classic McEliece",
    formerName: null,
    type: "KEM",
    description: "A code-based KEM based on the McEliece cryptosystem from 1978, making it one of the oldest post-quantum proposals. Uses binary Goppa codes with a hidden structure. The original McEliece system has withstood over 45 years of cryptanalysis with no significant structural attacks. Provides the highest confidence in security among post-quantum candidates but has very large public keys.",
    keySizes: {
      "mceliece348864": { publicKey: 261120, secretKey: 6492, ciphertext: 128, sharedSecret: 32, securityLevel: "NIST Level 1 (equivalent to AES-128)" },
      "mceliece460896": { publicKey: 524160, secretKey: 13608, ciphertext: 188, sharedSecret: 32, securityLevel: "NIST Level 3 (equivalent to AES-192)" },
      "mceliece6688128": { publicKey: 1044992, secretKey: 13932, ciphertext: 240, sharedSecret: 32, securityLevel: "NIST Level 5 (equivalent to AES-256)" },
      "mceliece6960119": { publicKey: 1047319, secretKey: 13948, ciphertext: 226, sharedSecret: 32, securityLevel: "NIST Level 5 (equivalent to AES-256)" },
      "mceliece8192128": { publicKey: 1357824, secretKey: 14120, ciphertext: 240, sharedSecret: 32, securityLevel: "NIST Level 5 (equivalent to AES-256)" }
    },
    signatureSizes: null,
    nistStatus: "NIST Round 4 candidate. The oldest and most conservative post-quantum proposal, under evaluation for scenarios where maximum confidence in security is required.",
    performanceNotes: "Extremely large public keys (256 KB to 1.3 MB) make it impractical for many applications. However, ciphertexts are very small (128-240 bytes) and encapsulation/decapsulation are extremely fast. Key generation is slow due to Goppa code construction. Best suited for applications where public keys can be cached or pre-distributed."
  }
];

const ASCII_TABLE = [
  { dec: 0, hex: "0x00", oct: "000", bin: "00000000", char: "NUL", description: "Null character" },
  { dec: 1, hex: "0x01", oct: "001", bin: "00000001", char: "SOH", description: "Start of Heading" },
  { dec: 2, hex: "0x02", oct: "002", bin: "00000010", char: "STX", description: "Start of Text" },
  { dec: 3, hex: "0x03", oct: "003", bin: "00000011", char: "ETX", description: "End of Text" },
  { dec: 4, hex: "0x04", oct: "004", bin: "00000100", char: "EOT", description: "End of Transmission" },
  { dec: 5, hex: "0x05", oct: "005", bin: "00000101", char: "ENQ", description: "Enquiry" },
  { dec: 6, hex: "0x06", oct: "006", bin: "00000110", char: "ACK", description: "Acknowledge" },
  { dec: 7, hex: "0x07", oct: "007", bin: "00000111", char: "BEL", description: "Bell (alert)" },
  { dec: 8, hex: "0x08", oct: "010", bin: "00001000", char: "BS", description: "Backspace" },
  { dec: 9, hex: "0x09", oct: "011", bin: "00001001", char: "HT", description: "Horizontal Tab" },
  { dec: 10, hex: "0x0A", oct: "012", bin: "00001010", char: "LF", description: "Line Feed (newline)" },
  { dec: 11, hex: "0x0B", oct: "013", bin: "00001011", char: "VT", description: "Vertical Tab" },
  { dec: 12, hex: "0x0C", oct: "014", bin: "00001100", char: "FF", description: "Form Feed" },
  { dec: 13, hex: "0x0D", oct: "015", bin: "00001101", char: "CR", description: "Carriage Return" },
  { dec: 14, hex: "0x0E", oct: "016", bin: "00001110", char: "SO", description: "Shift Out" },
  { dec: 15, hex: "0x0F", oct: "017", bin: "00001111", char: "SI", description: "Shift In" },
  { dec: 16, hex: "0x10", oct: "020", bin: "00010000", char: "DLE", description: "Data Link Escape" },
  { dec: 17, hex: "0x11", oct: "021", bin: "00010001", char: "DC1", description: "Device Control 1 (XON)" },
  { dec: 18, hex: "0x12", oct: "022", bin: "00010010", char: "DC2", description: "Device Control 2" },
  { dec: 19, hex: "0x13", oct: "023", bin: "00010011", char: "DC3", description: "Device Control 3 (XOFF)" },
  { dec: 20, hex: "0x14", oct: "024", bin: "00010100", char: "DC4", description: "Device Control 4" },
  { dec: 21, hex: "0x15", oct: "025", bin: "00010101", char: "NAK", description: "Negative Acknowledge" },
  { dec: 22, hex: "0x16", oct: "026", bin: "00010110", char: "SYN", description: "Synchronous Idle" },
  { dec: 23, hex: "0x17", oct: "027", bin: "00010111", char: "ETB", description: "End of Transmission Block" },
  { dec: 24, hex: "0x18", oct: "030", bin: "00011000", char: "CAN", description: "Cancel" },
  { dec: 25, hex: "0x19", oct: "031", bin: "00011001", char: "EM", description: "End of Medium" },
  { dec: 26, hex: "0x1A", oct: "032", bin: "00011010", char: "SUB", description: "Substitute" },
  { dec: 27, hex: "0x1B", oct: "033", bin: "00011011", char: "ESC", description: "Escape" },
  { dec: 28, hex: "0x1C", oct: "034", bin: "00011100", char: "FS", description: "File Separator" },
  { dec: 29, hex: "0x1D", oct: "035", bin: "00011101", char: "GS", description: "Group Separator" },
  { dec: 30, hex: "0x1E", oct: "036", bin: "00011110", char: "RS", description: "Record Separator" },
  { dec: 31, hex: "0x1F", oct: "037", bin: "00011111", char: "US", description: "Unit Separator" },
  { dec: 32, hex: "0x20", oct: "040", bin: "00100000", char: " ", description: "Space" },
  { dec: 33, hex: "0x21", oct: "041", bin: "00100001", char: "!", description: "Exclamation mark" },
  { dec: 34, hex: "0x22", oct: "042", bin: "00100010", char: "\"", description: "Double quotation mark" },
  { dec: 35, hex: "0x23", oct: "043", bin: "00100011", char: "#", description: "Number sign (hash)" },
  { dec: 36, hex: "0x24", oct: "044", bin: "00100100", char: "$", description: "Dollar sign" },
  { dec: 37, hex: "0x25", oct: "045", bin: "00100101", char: "%", description: "Percent sign" },
  { dec: 38, hex: "0x26", oct: "046", bin: "00100110", char: "&", description: "Ampersand" },
  { dec: 39, hex: "0x27", oct: "047", bin: "00100111", char: "'", description: "Apostrophe (single quote)" },
  { dec: 40, hex: "0x28", oct: "050", bin: "00101000", char: "(", description: "Left parenthesis" },
  { dec: 41, hex: "0x29", oct: "051", bin: "00101001", char: ")", description: "Right parenthesis" },
  { dec: 42, hex: "0x2A", oct: "052", bin: "00101010", char: "*", description: "Asterisk" },
  { dec: 43, hex: "0x2B", oct: "053", bin: "00101011", char: "+", description: "Plus sign" },
  { dec: 44, hex: "0x2C", oct: "054", bin: "00101100", char: ",", description: "Comma" },
  { dec: 45, hex: "0x2D", oct: "055", bin: "00101101", char: "-", description: "Hyphen-minus" },
  { dec: 46, hex: "0x2E", oct: "056", bin: "00101110", char: ".", description: "Period (full stop)" },
  { dec: 47, hex: "0x2F", oct: "057", bin: "00101111", char: "/", description: "Slash (solidus)" },
  { dec: 48, hex: "0x30", oct: "060", bin: "00110000", char: "0", description: "Digit zero" },
  { dec: 49, hex: "0x31", oct: "061", bin: "00110001", char: "1", description: "Digit one" },
  { dec: 50, hex: "0x32", oct: "062", bin: "00110010", char: "2", description: "Digit two" },
  { dec: 51, hex: "0x33", oct: "063", bin: "00110011", char: "3", description: "Digit three" },
  { dec: 52, hex: "0x34", oct: "064", bin: "00110100", char: "4", description: "Digit four" },
  { dec: 53, hex: "0x35", oct: "065", bin: "00110101", char: "5", description: "Digit five" },
  { dec: 54, hex: "0x36", oct: "066", bin: "00110110", char: "6", description: "Digit six" },
  { dec: 55, hex: "0x37", oct: "067", bin: "00110111", char: "7", description: "Digit seven" },
  { dec: 56, hex: "0x38", oct: "070", bin: "00111000", char: "8", description: "Digit eight" },
  { dec: 57, hex: "0x39", oct: "071", bin: "00111001", char: "9", description: "Digit nine" },
  { dec: 58, hex: "0x3A", oct: "072", bin: "00111010", char: ":", description: "Colon" },
  { dec: 59, hex: "0x3B", oct: "073", bin: "00111011", char: ";", description: "Semicolon" },
  { dec: 60, hex: "0x3C", oct: "074", bin: "00111100", char: "<", description: "Less-than sign" },
  { dec: 61, hex: "0x3D", oct: "075", bin: "00111101", char: "=", description: "Equals sign" },
  { dec: 62, hex: "0x3E", oct: "076", bin: "00111110", char: ">", description: "Greater-than sign" },
  { dec: 63, hex: "0x3F", oct: "077", bin: "00111111", char: "?", description: "Question mark" },
  { dec: 64, hex: "0x40", oct: "100", bin: "01000000", char: "@", description: "At sign (commercial at)" },
  { dec: 65, hex: "0x41", oct: "101", bin: "01000001", char: "A", description: "Latin capital letter A" },
  { dec: 66, hex: "0x42", oct: "102", bin: "01000010", char: "B", description: "Latin capital letter B" },
  { dec: 67, hex: "0x43", oct: "103", bin: "01000011", char: "C", description: "Latin capital letter C" },
  { dec: 68, hex: "0x44", oct: "104", bin: "01000100", char: "D", description: "Latin capital letter D" },
  { dec: 69, hex: "0x45", oct: "105", bin: "01000101", char: "E", description: "Latin capital letter E" },
  { dec: 70, hex: "0x46", oct: "106", bin: "01000110", char: "F", description: "Latin capital letter F" },
  { dec: 71, hex: "0x47", oct: "107", bin: "01000111", char: "G", description: "Latin capital letter G" },
  { dec: 72, hex: "0x48", oct: "110", bin: "01001000", char: "H", description: "Latin capital letter H" },
  { dec: 73, hex: "0x49", oct: "111", bin: "01001001", char: "I", description: "Latin capital letter I" },
  { dec: 74, hex: "0x4A", oct: "112", bin: "01001010", char: "J", description: "Latin capital letter J" },
  { dec: 75, hex: "0x4B", oct: "113", bin: "01001011", char: "K", description: "Latin capital letter K" },
  { dec: 76, hex: "0x4C", oct: "114", bin: "01001100", char: "L", description: "Latin capital letter L" },
  { dec: 77, hex: "0x4D", oct: "115", bin: "01001101", char: "M", description: "Latin capital letter M" },
  { dec: 78, hex: "0x4E", oct: "116", bin: "01001110", char: "N", description: "Latin capital letter N" },
  { dec: 79, hex: "0x4F", oct: "117", bin: "01001111", char: "O", description: "Latin capital letter O" },
  { dec: 80, hex: "0x50", oct: "120", bin: "01010000", char: "P", description: "Latin capital letter P" },
  { dec: 81, hex: "0x51", oct: "121", bin: "01010001", char: "Q", description: "Latin capital letter Q" },
  { dec: 82, hex: "0x52", oct: "122", bin: "01010010", char: "R", description: "Latin capital letter R" },
  { dec: 83, hex: "0x53", oct: "123", bin: "01010011", char: "S", description: "Latin capital letter S" },
  { dec: 84, hex: "0x54", oct: "124", bin: "01010100", char: "T", description: "Latin capital letter T" },
  { dec: 85, hex: "0x55", oct: "125", bin: "01010101", char: "U", description: "Latin capital letter U" },
  { dec: 86, hex: "0x56", oct: "126", bin: "01010110", char: "V", description: "Latin capital letter V" },
  { dec: 87, hex: "0x57", oct: "127", bin: "01010111", char: "W", description: "Latin capital letter W" },
  { dec: 88, hex: "0x58", oct: "130", bin: "01011000", char: "X", description: "Latin capital letter X" },
  { dec: 89, hex: "0x59", oct: "131", bin: "01011001", char: "Y", description: "Latin capital letter Y" },
  { dec: 90, hex: "0x5A", oct: "132", bin: "01011010", char: "Z", description: "Latin capital letter Z" },
  { dec: 91, hex: "0x5B", oct: "133", bin: "01011011", char: "[", description: "Left square bracket" },
  { dec: 92, hex: "0x5C", oct: "134", bin: "01011100", char: "\\", description: "Backslash (reverse solidus)" },
  { dec: 93, hex: "0x5D", oct: "135", bin: "01011101", char: "]", description: "Right square bracket" },
  { dec: 94, hex: "0x5E", oct: "136", bin: "01011110", char: "^", description: "Caret (circumflex accent)" },
  { dec: 95, hex: "0x5F", oct: "137", bin: "01011111", char: "_", description: "Underscore (low line)" },
  { dec: 96, hex: "0x60", oct: "140", bin: "01100000", char: "`", description: "Grave accent (backtick)" },
  { dec: 97, hex: "0x61", oct: "141", bin: "01100001", char: "a", description: "Latin small letter a" },
  { dec: 98, hex: "0x62", oct: "142", bin: "01100010", char: "b", description: "Latin small letter b" },
  { dec: 99, hex: "0x63", oct: "143", bin: "01100011", char: "c", description: "Latin small letter c" },
  { dec: 100, hex: "0x64", oct: "144", bin: "01100100", char: "d", description: "Latin small letter d" },
  { dec: 101, hex: "0x65", oct: "145", bin: "01100101", char: "e", description: "Latin small letter e" },
  { dec: 102, hex: "0x66", oct: "146", bin: "01100110", char: "f", description: "Latin small letter f" },
  { dec: 103, hex: "0x67", oct: "147", bin: "01100111", char: "g", description: "Latin small letter g" },
  { dec: 104, hex: "0x68", oct: "150", bin: "01101000", char: "h", description: "Latin small letter h" },
  { dec: 105, hex: "0x69", oct: "151", bin: "01101001", char: "i", description: "Latin small letter i" },
  { dec: 106, hex: "0x6A", oct: "152", bin: "01101010", char: "j", description: "Latin small letter j" },
  { dec: 107, hex: "0x6B", oct: "153", bin: "01101011", char: "k", description: "Latin small letter k" },
  { dec: 108, hex: "0x6C", oct: "154", bin: "01101100", char: "l", description: "Latin small letter l" },
  { dec: 109, hex: "0x6D", oct: "155", bin: "01101101", char: "m", description: "Latin small letter m" },
  { dec: 110, hex: "0x6E", oct: "156", bin: "01101110", char: "n", description: "Latin small letter n" },
  { dec: 111, hex: "0x6F", oct: "157", bin: "01101111", char: "o", description: "Latin small letter o" },
  { dec: 112, hex: "0x70", oct: "160", bin: "01110000", char: "p", description: "Latin small letter p" },
  { dec: 113, hex: "0x71", oct: "161", bin: "01110001", char: "q", description: "Latin small letter q" },
  { dec: 114, hex: "0x72", oct: "162", bin: "01110010", char: "r", description: "Latin small letter r" },
  { dec: 115, hex: "0x73", oct: "163", bin: "01110011", char: "s", description: "Latin small letter s" },
  { dec: 116, hex: "0x74", oct: "164", bin: "01110100", char: "t", description: "Latin small letter t" },
  { dec: 117, hex: "0x75", oct: "165", bin: "01110101", char: "u", description: "Latin small letter u" },
  { dec: 118, hex: "0x76", oct: "166", bin: "01110110", char: "v", description: "Latin small letter v" },
  { dec: 119, hex: "0x77", oct: "167", bin: "01110111", char: "w", description: "Latin small letter w" },
  { dec: 120, hex: "0x78", oct: "170", bin: "01111000", char: "x", description: "Latin small letter x" },
  { dec: 121, hex: "0x79", oct: "171", bin: "01111001", char: "y", description: "Latin small letter y" },
  { dec: 122, hex: "0x7A", oct: "172", bin: "01111010", char: "z", description: "Latin small letter z" },
  { dec: 123, hex: "0x7B", oct: "173", bin: "01111011", char: "{", description: "Left curly bracket (brace)" },
  { dec: 124, hex: "0x7C", oct: "174", bin: "01111100", char: "|", description: "Vertical bar (pipe)" },
  { dec: 125, hex: "0x7D", oct: "175", bin: "01111101", char: "}", description: "Right curly bracket (brace)" },
  { dec: 126, hex: "0x7E", oct: "176", bin: "01111110", char: "~", description: "Tilde" },
  { dec: 127, hex: "0x7F", oct: "177", bin: "01111111", char: "DEL", description: "Delete" }
];
