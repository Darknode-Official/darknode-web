// PHANTOM — Packet Handler, Analyzer, Network Topology & Operations Monitor
// Browser-based network traffic analysis and deep packet inspection platform
// Copyright (c) 2026 Darknode-Official. All rights reserved.

import { mountModeSwitcher, filterTabsByMode, getToolMode } from '/js/core/tool-modes.js';

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ============================================================================
// SAMPLE PACKET DATA (50 realistic packets)
// ============================================================================
const SAMPLE_PACKETS = [
  { id: 1, ts: 0.000000, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '93.184.216.34', srcPort: 49152, dstPort: 443, protocol: 'TLS', length: 583, ttl: 64, flags: 'PSH,ACK', payload: '16030100f4010000f0030358b4...', info: 'Client Hello - example.com' },
  { id: 2, ts: 0.034521, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '93.184.216.34', dstIP: '10.0.0.5', srcPort: 443, dstPort: 49152, protocol: 'TLS', length: 3847, ttl: 52, flags: 'PSH,ACK', payload: '160303...', info: 'Server Hello, Certificate, Done' },
  { id: 3, ts: 0.035112, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '93.184.216.34', srcPort: 49152, dstPort: 443, protocol: 'TLS', length: 147, ttl: 64, flags: 'PSH,ACK', payload: '160301...', info: 'Client Key Exchange, Change Cipher Spec' },
  { id: 4, ts: 0.068230, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '8.8.8.8', srcPort: 51234, dstPort: 53, protocol: 'DNS', length: 74, ttl: 64, flags: '', payload: 'aabb01000001000000000000...', info: 'Query A api.github.com' },
  { id: 5, ts: 0.089451, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '8.8.8.8', dstIP: '10.0.0.5', srcPort: 53, dstPort: 51234, protocol: 'DNS', length: 106, ttl: 117, flags: '', payload: 'aabb81800001000200000000...', info: 'Response A 140.82.121.5, A 140.82.121.6' },
  { id: 6, ts: 0.091003, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '140.82.121.5', srcPort: 49200, dstPort: 443, protocol: 'TCP', length: 74, ttl: 64, flags: 'SYN', payload: '', info: '49200 -> 443 [SYN] Seq=0 Win=65535' },
  { id: 7, ts: 0.112445, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '140.82.121.5', dstIP: '10.0.0.5', srcPort: 443, dstPort: 49200, protocol: 'TCP', length: 74, ttl: 48, flags: 'SYN,ACK', payload: '', info: '443 -> 49200 [SYN,ACK] Seq=0 Ack=1 Win=65535' },
  { id: 8, ts: 0.112890, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '140.82.121.5', srcPort: 49200, dstPort: 443, protocol: 'TCP', length: 66, ttl: 64, flags: 'ACK', payload: '', info: '49200 -> 443 [ACK] Seq=1 Ack=1 Win=65535' },
  { id: 9, ts: 0.115200, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '140.82.121.5', srcPort: 49200, dstPort: 443, protocol: 'TLS', length: 571, ttl: 64, flags: 'PSH,ACK', payload: '16030100...', info: 'Client Hello - api.github.com' },
  { id: 10, ts: 0.143892, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '140.82.121.5', dstIP: '10.0.0.5', srcPort: 443, dstPort: 49200, protocol: 'TLS', length: 4211, ttl: 48, flags: 'PSH,ACK', payload: '160303...', info: 'Server Hello, Certificate, Done' },
  { id: 11, ts: 0.200100, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '8.8.8.8', srcPort: 51235, dstPort: 53, protocol: 'DNS', length: 78, ttl: 64, flags: '', payload: 'ccdd01000001...', info: 'Query A cdn.jsdelivr.net' },
  { id: 12, ts: 0.221340, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '8.8.8.8', dstIP: '10.0.0.5', srcPort: 53, dstPort: 51235, protocol: 'DNS', length: 142, ttl: 117, flags: '', payload: 'ccdd81800001...', info: 'Response A 104.16.85.20, A 104.16.86.20' },
  { id: 13, ts: 0.300450, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '192.168.1.1', srcPort: 49210, dstPort: 80, protocol: 'HTTP', length: 412, ttl: 64, flags: 'PSH,ACK', payload: '474554202f...', info: 'GET /admin/status HTTP/1.1' },
  { id: 14, ts: 0.302100, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '192.168.1.1', dstIP: '10.0.0.5', srcPort: 80, dstPort: 49210, protocol: 'HTTP', length: 1250, ttl: 64, flags: 'PSH,ACK', payload: '485454502f...', info: 'HTTP/1.1 200 OK (text/html)' },
  { id: 15, ts: 0.400000, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '10.0.0.1', srcPort: 0, dstPort: 0, protocol: 'ICMP', length: 98, ttl: 64, flags: '', payload: '0800...', info: 'Echo (ping) request id=0x1234 seq=1' },
  { id: 16, ts: 0.401230, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '10.0.0.1', dstIP: '10.0.0.5', srcPort: 0, dstPort: 0, protocol: 'ICMP', length: 98, ttl: 64, flags: '', payload: '0000...', info: 'Echo (ping) reply id=0x1234 seq=1' },
  { id: 17, ts: 0.500100, srcMAC: 'aa:bb:cc:00:11:02', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.12', dstIP: '10.0.0.5', srcPort: 22, dstPort: 55001, protocol: 'TCP', length: 1400, ttl: 64, flags: 'PSH,ACK', payload: '00001a...', info: 'SSH Encrypted Data' },
  { id: 18, ts: 0.510200, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '10.0.0.12', srcPort: 55001, dstPort: 22, protocol: 'TCP', length: 66, ttl: 64, flags: 'ACK', payload: '', info: '55001 -> 22 [ACK] Seq=1 Ack=1335 Win=65535' },
  { id: 19, ts: 0.600000, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '8.8.8.8', srcPort: 51236, dstPort: 53, protocol: 'DNS', length: 82, ttl: 64, flags: '', payload: 'eeff01000001...', info: 'Query AAAA fonts.googleapis.com' },
  { id: 20, ts: 0.621100, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '8.8.8.8', dstIP: '10.0.0.5', srcPort: 53, dstPort: 51236, protocol: 'DNS', length: 110, ttl: 117, flags: '', payload: 'eeff81800001...', info: 'Response AAAA 2607:f8b0:4004:800::200a' },
  { id: 21, ts: 0.700500, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '104.26.10.33', srcPort: 49220, dstPort: 443, protocol: 'TLS', length: 517, ttl: 64, flags: 'PSH,ACK', payload: '16030100...', info: 'Client Hello - api.cloudflare.com' },
  { id: 22, ts: 0.800100, srcMAC: 'aa:bb:cc:00:11:03', dstMAC: 'ff:ff:ff:ff:ff:ff', srcIP: '10.0.0.20', dstIP: '10.0.0.255', srcPort: 137, dstPort: 137, protocol: 'UDP', length: 92, ttl: 128, flags: '', payload: '80b201100001...', info: 'NetBIOS Name Query NB WORKGROUP<00>' },
  { id: 23, ts: 0.900200, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '172.217.14.99', srcPort: 49230, dstPort: 443, protocol: 'TCP', length: 74, ttl: 64, flags: 'SYN', payload: '', info: '49230 -> 443 [SYN] Seq=0 Win=65535' },
  { id: 24, ts: 0.920100, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '172.217.14.99', dstIP: '10.0.0.5', srcPort: 443, dstPort: 49230, protocol: 'TCP', length: 74, ttl: 55, flags: 'SYN,ACK', payload: '', info: '443 -> 49230 [SYN,ACK] Seq=0 Ack=1' },
  { id: 25, ts: 1.000000, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '8.8.8.8', srcPort: 51237, dstPort: 53, protocol: 'DNS', length: 96, ttl: 64, flags: '', payload: '1122010000010...', info: 'Query TXT _dmarc.darknode.ai' },
  { id: 26, ts: 1.021400, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '8.8.8.8', dstIP: '10.0.0.5', srcPort: 53, dstPort: 51237, protocol: 'DNS', length: 228, ttl: 117, flags: '', payload: '1122818000010...', info: 'Response TXT "v=DMARC1; p=reject"' },
  { id: 27, ts: 1.100300, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '185.199.108.153', srcPort: 49240, dstPort: 443, protocol: 'TLS', length: 1200, ttl: 64, flags: 'PSH,ACK', payload: '170303...', info: 'Application Data (encrypted)' },
  { id: 28, ts: 1.200100, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '185.199.108.153', dstIP: '10.0.0.5', srcPort: 443, dstPort: 49240, protocol: 'TLS', length: 8921, ttl: 56, flags: 'PSH,ACK', payload: '170303...', info: 'Application Data (encrypted, 8855 bytes)' },
  { id: 29, ts: 1.300000, srcMAC: 'aa:bb:cc:00:11:04', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.30', dstIP: '10.0.0.5', srcPort: 445, dstPort: 56001, protocol: 'TCP', length: 1460, ttl: 128, flags: 'PSH,ACK', payload: 'fe534d42...', info: 'SMB2 Session Setup Response' },
  { id: 30, ts: 1.400500, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '10.0.0.30', srcPort: 56001, dstPort: 445, protocol: 'TCP', length: 230, ttl: 64, flags: 'PSH,ACK', payload: 'fe534d42...', info: 'SMB2 Tree Connect Request \\\\10.0.0.30\\ADMIN$' },
  { id: 31, ts: 1.500100, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '8.8.4.4', srcPort: 51238, dstPort: 53, protocol: 'DNS', length: 88, ttl: 64, flags: '', payload: '3344010000010...', info: 'Query MX darknode.ai' },
  { id: 32, ts: 1.522100, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '8.8.4.4', dstIP: '10.0.0.5', srcPort: 53, dstPort: 51238, protocol: 'DNS', length: 158, ttl: 115, flags: '', payload: '3344818000010...', info: 'Response MX 10 mail.darknode.ai' },
  { id: 33, ts: 1.600200, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '142.250.80.46', srcPort: 49250, dstPort: 80, protocol: 'HTTP', length: 380, ttl: 64, flags: 'PSH,ACK', payload: '474554202f...', info: 'GET /generate_204 HTTP/1.1 (connectivity check)' },
  { id: 34, ts: 1.621300, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '142.250.80.46', dstIP: '10.0.0.5', srcPort: 80, dstPort: 49250, protocol: 'HTTP', length: 258, ttl: 55, flags: 'PSH,ACK', payload: '485454502f...', info: 'HTTP/1.1 204 No Content' },
  { id: 35, ts: 1.700000, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '10.0.0.1', srcPort: 0, dstPort: 0, protocol: 'ICMP', length: 98, ttl: 64, flags: '', payload: '0800...', info: 'Echo (ping) request id=0x1234 seq=2' },
  { id: 36, ts: 1.701500, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '10.0.0.1', dstIP: '10.0.0.5', srcPort: 0, dstPort: 0, protocol: 'ICMP', length: 98, ttl: 64, flags: '', payload: '0000...', info: 'Echo (ping) reply id=0x1234 seq=2' },
  { id: 37, ts: 1.800300, srcMAC: 'aa:bb:cc:00:11:05', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.50', dstIP: '10.0.0.5', srcPort: 8080, dstPort: 57001, protocol: 'HTTP', length: 2450, ttl: 64, flags: 'PSH,ACK', payload: '485454502f...', info: 'HTTP/1.1 200 OK (application/json, 2.3KB)' },
  { id: 38, ts: 1.900100, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '10.0.0.50', srcPort: 57001, dstPort: 8080, protocol: 'HTTP', length: 520, ttl: 64, flags: 'PSH,ACK', payload: '504f5354...', info: 'POST /api/v1/scan HTTP/1.1 (application/json)' },
  { id: 39, ts: 2.000000, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '8.8.8.8', srcPort: 51239, dstPort: 53, protocol: 'DNS', length: 92, ttl: 64, flags: '', payload: '5566010000010...', info: 'Query A xn--80aswg.xn--p1ai' },
  { id: 40, ts: 2.023400, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '8.8.8.8', dstIP: '10.0.0.5', srcPort: 53, dstPort: 51239, protocol: 'DNS', length: 108, ttl: 117, flags: '', payload: '5566818000010...', info: 'Response A 77.88.55.88' },
  { id: 41, ts: 2.100500, srcMAC: 'aa:bb:cc:00:11:06', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '198.51.100.44', dstIP: '10.0.0.5', srcPort: 4444, dstPort: 58001, protocol: 'TCP', length: 120, ttl: 42, flags: 'PSH,ACK', payload: '2f62696e2f...', info: '/bin/sh -i 2>&1 (reverse shell)' },
  { id: 42, ts: 2.101200, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '198.51.100.44', srcPort: 58001, dstPort: 4444, protocol: 'TCP', length: 320, ttl: 64, flags: 'PSH,ACK', payload: '69643b75...', info: 'id;uname -a;cat /etc/passwd' },
  { id: 43, ts: 2.200000, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '8.8.8.8', srcPort: 51240, dstPort: 53, protocol: 'DNS', length: 120, ttl: 64, flags: '', payload: '7788010000010...', info: 'Query TXT aGVsbG8gd29ybGQ.c2.evil.com' },
  { id: 44, ts: 2.300100, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '203.0.113.10', srcPort: 49260, dstPort: 443, protocol: 'TLS', length: 485, ttl: 64, flags: 'PSH,ACK', payload: '16030100...', info: 'Client Hello - suspicious.example.xyz' },
  { id: 45, ts: 2.400200, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '10.0.0.30', srcPort: 49270, dstPort: 3389, protocol: 'TCP', length: 74, ttl: 64, flags: 'SYN', payload: '', info: '49270 -> 3389 [SYN] Seq=0 (RDP)' },
  { id: 46, ts: 2.420100, srcMAC: 'aa:bb:cc:00:11:04', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '10.0.0.30', dstIP: '10.0.0.5', srcPort: 3389, dstPort: 49270, protocol: 'TCP', length: 74, ttl: 128, flags: 'SYN,ACK', payload: '', info: '3389 -> 49270 [SYN,ACK] (RDP)' },
  { id: 47, ts: 2.500000, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '8.8.8.8', srcPort: 51241, dstPort: 53, protocol: 'DNS', length: 76, ttl: 64, flags: '', payload: '9900010000010...', info: 'Query A ntp.ubuntu.com' },
  { id: 48, ts: 2.521200, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '8.8.8.8', dstIP: '10.0.0.5', srcPort: 53, dstPort: 51241, protocol: 'DNS', length: 92, ttl: 117, flags: '', payload: '9900818000010...', info: 'Response A 91.189.91.157' },
  { id: 49, ts: 2.600300, srcMAC: 'aa:bb:cc:00:11:01', dstMAC: 'aa:bb:cc:00:11:ff', srcIP: '10.0.0.5', dstIP: '91.189.91.157', srcPort: 54321, dstPort: 123, protocol: 'UDP', length: 90, ttl: 64, flags: '', payload: '230300...', info: 'NTP Version 4, Client' },
  { id: 50, ts: 2.700100, srcMAC: 'aa:bb:cc:00:11:ff', dstMAC: 'aa:bb:cc:00:11:01', srcIP: '91.189.91.157', dstIP: '10.0.0.5', srcPort: 123, dstPort: 54321, protocol: 'UDP', length: 90, ttl: 52, flags: '', payload: '240300...', info: 'NTP Version 4, Server' },
];

// ============================================================================
// SAMPLE TLS CERTIFICATES
// ============================================================================
const SAMPLE_CERTS = [
  { subject: 'CN=*.github.com', issuer: 'DigiCert TLS RSA SHA256 2020 CA1', validFrom: '2024-03-07', validTo: '2025-03-12', keySize: 2048, sigAlg: 'SHA256withRSA', serial: '0A:9B:22:7A:BB:3E:44:01', san: '*.github.com, github.com' },
  { subject: 'CN=example.com', issuer: "Let's Encrypt Authority X3", validFrom: '2024-06-01', validTo: '2024-08-30', keySize: 2048, sigAlg: 'SHA256withRSA', serial: '03:FF:AA:12:34:56:78', san: 'example.com, www.example.com' },
  { subject: 'CN=*.cloudflare.com', issuer: 'Cloudflare Inc ECC CA-3', validFrom: '2024-01-15', validTo: '2025-01-14', keySize: 256, sigAlg: 'SHA256withECDSA', serial: '0B:CD:EF:01:23:45:67', san: '*.cloudflare.com, cloudflare.com' },
  { subject: 'CN=api.stripe.com', issuer: 'DigiCert SHA2 Extended Validation Server CA', validFrom: '2024-05-20', validTo: '2025-05-20', keySize: 2048, sigAlg: 'SHA256withRSA', serial: '0C:11:22:33:44:55:66', san: 'api.stripe.com' },
  { subject: 'CN=self-signed.internal', issuer: 'self-signed.internal', validFrom: '2023-01-01', validTo: '2033-01-01', keySize: 1024, sigAlg: 'SHA1withRSA', serial: 'AA:BB:CC:DD', san: 'self-signed.internal' },
  { subject: 'CN=*.google.com', issuer: 'GTS CA 1C3', validFrom: '2024-08-01', validTo: '2024-10-24', keySize: 256, sigAlg: 'SHA256withECDSA', serial: '12:34:56:78:9A:BC:DE', san: '*.google.com, google.com, *.google.co.uk' },
  { subject: 'CN=expired.badssl.com', issuer: 'COMODO RSA Domain Validation Secure Server CA', validFrom: '2015-04-09', validTo: '2015-04-12', keySize: 2048, sigAlg: 'SHA256withRSA', serial: 'EE:FF:00:11:22:33', san: 'expired.badssl.com' },
  { subject: 'CN=weak.example.net', issuer: 'Internal CA', validFrom: '2024-01-01', validTo: '2025-01-01', keySize: 512, sigAlg: 'MD5withRSA', serial: '00:11:22:33', san: 'weak.example.net' },
  { subject: 'CN=*.amazonaws.com', issuer: 'Amazon RSA 2048 M01', validFrom: '2024-07-01', validTo: '2025-07-01', keySize: 2048, sigAlg: 'SHA256withRSA', serial: 'AA:00:BB:11:CC:22', san: '*.amazonaws.com, *.s3.amazonaws.com' },
  { subject: 'CN=darknode.ai', issuer: 'Google Trust Services LLC', validFrom: '2024-09-01', validTo: '2025-02-28', keySize: 256, sigAlg: 'SHA256withECDSA', serial: 'DD:EE:FF:00:11', san: 'darknode.ai, www.darknode.ai, sentinel-b4194.web.app' },
];

// ============================================================================
// JA3 FINGERPRINT DATABASE
// ============================================================================
const JA3_DB = [
  { hash: 'e7d705a3286e19ea42f587b344ee6865', client: 'Chrome 120+', confidence: 'High' },
  { hash: '473cd7cb9faa642487833865d516e578', client: 'Firefox 120+', confidence: 'High' },
  { hash: 'b32309a26951912be7dba376398abc3b', client: 'Safari 17', confidence: 'High' },
  { hash: 'a0e9f5d64349fb13191bc781f81f42e1', client: 'curl/8.x', confidence: 'High' },
  { hash: '3b5074b1b5d032e5620f69f9f700ff0e', client: 'Python requests', confidence: 'Medium' },
  { hash: 'e35f5f2b6d25675d54afec5d54fa5b96', client: 'Cobalt Strike Beacon', confidence: 'Critical' },
  { hash: '72a589da586844d7f0818ce684948eea', client: 'Metasploit Meterpreter', confidence: 'Critical' },
  { hash: '6734f37431670b3ab4292b8f60f29984', client: 'Trickbot/Emotet', confidence: 'Critical' },
];

// ============================================================================
// ANOMALY DETECTION RULES
// ============================================================================
const SAMPLE_ANOMALIES = [
  { severity: 'CRITICAL', type: 'Reverse Shell', description: 'Outbound connection to 198.51.100.44:4444 followed by /bin/sh execution detected.', evidence: 'Packet #41-42: 10.0.0.5 -> 198.51.100.44:4444, payload contains shell commands', recommendation: 'Isolate host 10.0.0.5 immediately. Check for persistence mechanisms. Investigate lateral movement.' },
  { severity: 'HIGH', type: 'DNS Tunneling', description: 'Unusually long subdomain label detected in DNS query suggesting data exfiltration via DNS.', evidence: 'Packet #43: TXT query for aGVsbG8gd29ybGQ.c2.evil.com (base64-encoded subdomain, 20+ chars)', recommendation: 'Block DNS queries to evil.com. Investigate all DNS traffic from 10.0.0.5.' },
  { severity: 'HIGH', type: 'SMB Admin Share Access', description: 'Connection to ADMIN$ share on remote host detected, common in lateral movement.', evidence: 'Packet #29-30: SMB2 Tree Connect to \\\\10.0.0.30\\ADMIN$', recommendation: 'Verify this is authorized admin activity. Check if credentials were stolen.' },
  { severity: 'MEDIUM', type: 'Suspicious TLS Connection', description: 'TLS handshake to a domain with low reputation score and unusual characteristics.', evidence: 'Packet #44: Client Hello to suspicious.example.xyz on non-standard infrastructure', recommendation: 'Investigate the domain. Check VirusTotal and threat intel feeds.' },
  { severity: 'MEDIUM', type: 'NetBIOS Broadcast', description: 'NetBIOS name service broadcast detected, potential network reconnaissance.', evidence: 'Packet #22: 10.0.0.20 broadcasting NetBIOS name query for WORKGROUP', recommendation: 'Disable NetBIOS if not needed. Monitor for enumeration patterns.' },
  { severity: 'LOW', type: 'Unencrypted HTTP', description: 'HTTP traffic detected on internal network without TLS encryption.', evidence: 'Packets #13-14, #33-34: Plaintext HTTP to 192.168.1.1:80 and 142.250.80.46:80', recommendation: 'Migrate internal services to HTTPS. Configure HSTS.' },
  { severity: 'LOW', type: 'NTP Traffic', description: 'NTP client communication detected to external server.', evidence: 'Packets #49-50: NTP v4 exchange with 91.189.91.157 (ntp.ubuntu.com)', recommendation: 'Informational. Ensure NTP servers are trusted and rate-limited.' },
  { severity: 'INFO', type: 'RDP Connection', description: 'Remote Desktop Protocol connection initiated to internal host.', evidence: 'Packets #45-46: TCP SYN to 10.0.0.30:3389 (RDP)', recommendation: 'Verify this is authorized remote access. Enable NLA and MFA for RDP.' },
];

// ============================================================================
// PROTOCOL COLORS
// ============================================================================
const PROTO_COLORS = {
  TCP: { bg: '#dbeafe', text: '#1e40af', dark: '#1e3a5f' },
  UDP: { bg: '#dcfce7', text: '#166534', dark: '#14532d' },
  DNS: { bg: '#fef9c3', text: '#854d0e', dark: '#713f12' },
  HTTP: { bg: '#ffedd5', text: '#9a3412', dark: '#7c2d12' },
  TLS: { bg: '#f3e8ff', text: '#6b21a8', dark: '#581c87' },
  ICMP: { bg: '#ecfeff', text: '#0e7490', dark: '#155e75' },
};

function protoColor(proto) {
  return PROTO_COLORS[proto] || { bg: '#f1f5f9', text: '#475569', dark: '#334155' };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(2) + ' MB';
}

function fmtTime(ts) {
  return ts.toFixed(6);
}

function genHexDump(pkt) {
  var hex = pkt.payload || '';
  var rows = [];
  for (var i = 0; i < Math.min(hex.length, 320); i += 32) {
    var chunk = hex.slice(i, i + 32);
    var offset = (i / 2).toString(16).padStart(8, '0');
    var hexPart = '';
    var asciiPart = '';
    for (var j = 0; j < chunk.length; j += 2) {
      var byte = parseInt(chunk.slice(j, j + 2), 16) || 0;
      hexPart += chunk.slice(j, j + 2) + ' ';
      asciiPart += (byte >= 32 && byte < 127) ? String.fromCharCode(byte) : '.';
    }
    rows.push(offset + '  ' + hexPart.padEnd(49, ' ') + ' ' + asciiPart);
  }
  if (rows.length === 0) rows.push('(no payload data)');
  return rows.join('\n');
}

function entropy(str) {
  var freq = {};
  for (var i = 0; i < str.length; i++) {
    var c = str[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  var h = 0;
  for (var k in freq) {
    var p = freq[k] / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// ============================================================================
// CLASSIC PCAP PARSER (libpcap format, not pcapng)
// ============================================================================
// Parses the 24-byte global header (either byte order, micro- or nanosecond
// timestamps) and each 16-byte packet record header. Supported link types:
// 0 (BSD loopback), 1 (Ethernet, incl. one 802.1Q tag), 101/12/14 (raw IP) and
// 113 (Linux cooked SLL). Decodes IPv4/IPv6, TCP, UDP and ICMP headers into the
// same packet shape the demo data uses, so every tab works on imported captures.
var PH_PCAP_MAX_PACKETS = 20000;
var PH_PAYLOAD_HEX_BYTES = 160; // genHexDump shows at most 160 bytes

function phHex(bytes, start, end) {
  var s = '';
  for (var i = start; i < end; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
  return s;
}
function phMac(b, o) {
  var parts = [];
  for (var i = 0; i < 6; i++) parts.push((b[o + i] < 16 ? '0' : '') + b[o + i].toString(16));
  return parts.join(':');
}
function phIPv6(b, o) {
  var g = [];
  for (var i = 0; i < 16; i += 2) g.push(((b[o + i] << 8) | b[o + i + 1]).toString(16));
  // Compress the longest run of zero groups (RFC 5952 style).
  var best = -1, bestLen = 0, cur = -1, curLen = 0;
  for (var j = 0; j < 8; j++) {
    if (g[j] === '0') { if (cur < 0) { cur = j; curLen = 0; } curLen++; if (curLen > bestLen) { best = cur; bestLen = curLen; } }
    else cur = -1;
  }
  if (bestLen < 2) return g.join(':');
  return g.slice(0, best).join(':') + '::' + g.slice(best + bestLen).join(':');
}
function phAscii(b, start, end) {
  var s = '';
  for (var i = start; i < end; i++) {
    var ch = b[i];
    if (ch === 13 || ch === 10) break;
    if (ch < 32 || ch > 126) return null;
    s += String.fromCharCode(ch);
  }
  return s;
}
var PH_DNS_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY' };
function phDnsInfo(b, o, end) {
  if (end - o < 12) return null;
  var isResp = (b[o + 2] & 0x80) !== 0;
  var qd = (b[o + 4] << 8) | b[o + 5];
  var an = (b[o + 6] << 8) | b[o + 7];
  var p = o + 12, labels = [], guard = 0;
  if (qd < 1) return isResp ? 'Response' : 'Query';
  while (p < end && b[p] !== 0 && guard++ < 64) {
    var len = b[p];
    if ((len & 0xc0) || p + 1 + len > end) return isResp ? 'Response' : 'Query';
    labels.push(phAscii(b, p + 1, p + 1 + len) || '?');
    p += 1 + len;
  }
  var qtype = p + 3 <= end ? ((b[p + 1] << 8) | b[p + 2]) : 0;
  var t = PH_DNS_TYPES[qtype] || ('TYPE' + qtype);
  var name = labels.join('.') || '<root>';
  return isResp ? 'Response ' + t + ' ' + name + ' (' + an + ' answer' + (an === 1 ? '' : 's') + ')' : 'Query ' + t + ' ' + name;
}
var PH_TLS_HS = { 1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 11: 'Certificate', 12: 'Server Key Exchange', 14: 'Server Hello Done', 16: 'Client Key Exchange' };
function phTlsSni(b, o, end) {
  // o points at the handshake header of a ClientHello.
  var p = o + 4 + 2 + 32;
  if (p >= end) return '';
  p += 1 + b[p]; // session id
  if (p + 2 > end) return '';
  p += 2 + ((b[p] << 8) | b[p + 1]); // cipher suites
  if (p >= end) return '';
  p += 1 + b[p]; // compression methods
  if (p + 2 > end) return '';
  var extEnd = Math.min(end, p + 2 + ((b[p] << 8) | b[p + 1]));
  p += 2;
  while (p + 4 <= extEnd) {
    var type = (b[p] << 8) | b[p + 1], len = (b[p + 2] << 8) | b[p + 3];
    if (type === 0 && p + 9 <= extEnd) {
      var nlen = (b[p + 7] << 8) | b[p + 8];
      return phAscii(b, p + 9, Math.min(extEnd, p + 9 + nlen)) || '';
    }
    p += 4 + len;
  }
  return '';
}
function phTlsInfo(b, o, end) {
  if (end - o < 5) return null;
  var ct = b[o];
  if (ct < 20 || ct > 23 || b[o + 1] !== 3) return null;
  if (ct === 20) return 'Change Cipher Spec';
  if (ct === 21) return 'Alert';
  if (ct === 23) return 'Application Data';
  var hs = b[o + 5];
  var name = PH_TLS_HS[hs] || ('Handshake type ' + hs);
  if (hs === 1) { var sni = phTlsSni(b, o + 5, end); return sni ? name + ' - ' + sni : name; }
  return name;
}
var PH_TCP_FLAGS = [[0x02, 'SYN'], [0x01, 'FIN'], [0x04, 'RST'], [0x08, 'PSH'], [0x10, 'ACK'], [0x20, 'URG']];

function phDecodeIP(b, o, end, pkt) {
  if (o >= end) return false;
  var ver = b[o] >> 4, proto, l4;
  if (ver === 4) {
    if (end - o < 20) return false;
    var ihl = (b[o] & 0x0f) * 4;
    var totLen = (b[o + 2] << 8) | b[o + 3];
    if (totLen >= ihl && o + totLen < end) end = o + totLen; // strip Ethernet padding
    pkt.ipVersion = 4; pkt.ipHeaderLen = ihl; pkt.ipTotalLen = totLen;
    pkt.ttl = b[o + 8]; proto = b[o + 9];
    pkt.srcIP = b[o + 12] + '.' + b[o + 13] + '.' + b[o + 14] + '.' + b[o + 15];
    pkt.dstIP = b[o + 16] + '.' + b[o + 17] + '.' + b[o + 18] + '.' + b[o + 19];
    var fragOff = ((b[o + 6] & 0x1f) << 8) | b[o + 7];
    l4 = o + ihl;
    if (fragOff !== 0) { pkt.protocol = 'IPv4'; pkt.info = 'Fragment (offset ' + fragOff * 8 + '), proto ' + proto; pkt.ipProto = proto; return true; }
  } else if (ver === 6) {
    if (end - o < 40) return false;
    pkt.ipVersion = 6; pkt.ipHeaderLen = 40;
    var plen = (b[o + 4] << 8) | b[o + 5];
    if (o + 40 + plen < end) end = o + 40 + plen;
    proto = b[o + 6]; pkt.ttl = b[o + 7];
    pkt.srcIP = phIPv6(b, o + 8); pkt.dstIP = phIPv6(b, o + 24);
    l4 = o + 40;
    // Skip common extension headers (hop-by-hop, routing, destination options).
    var guard = 0;
    while ((proto === 0 || proto === 43 || proto === 60) && l4 + 2 <= end && guard++ < 8) {
      proto = b[l4]; l4 += (b[l4 + 1] + 1) * 8;
    }
  } else {
    return false;
  }
  pkt.ipProto = proto;
  if (proto === 6 && end - l4 >= 20) {
    var sp = (b[l4] << 8) | b[l4 + 1], dp = (b[l4 + 2] << 8) | b[l4 + 3];
    var seq = ((b[l4 + 4] << 24) | (b[l4 + 5] << 16) | (b[l4 + 6] << 8) | b[l4 + 7]) >>> 0;
    var ack = ((b[l4 + 8] << 24) | (b[l4 + 9] << 16) | (b[l4 + 10] << 8) | b[l4 + 11]) >>> 0;
    var doff = (b[l4 + 12] >> 4) * 4, fl = b[l4 + 13];
    var win = (b[l4 + 14] << 8) | b[l4 + 15];
    var flags = PH_TCP_FLAGS.filter(function(f) { return fl & f[0]; }).map(function(f) { return f[1]; });
    pkt.srcPort = sp; pkt.dstPort = dp; pkt.flags = flags.join(','); pkt.seq = seq; pkt.ack = ack; pkt.window = win;
    pkt.checksum = '0x' + phHex(b, l4 + 16, l4 + 18);
    var pl = Math.min(end, l4 + doff);
    pkt.payload = phHex(b, pl, Math.min(end, pl + PH_PAYLOAD_HEX_BYTES));
    pkt.protocol = 'TCP';
    var app = null;
    if (pl < end) {
      if (sp === 443 || dp === 443 || sp === 8443 || dp === 8443 || (b[pl] >= 20 && b[pl] <= 23 && b[pl + 1] === 3)) {
        app = phTlsInfo(b, pl, end); if (app) pkt.protocol = 'TLS';
      }
      if (!app) {
        var line = phAscii(b, pl, Math.min(end, pl + 200));
        if (line && /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT) \S+ HTTP\/\d|^HTTP\/\d\.\d \d{3}/.test(line)) { app = line; pkt.protocol = 'HTTP'; }
      }
      if (!app && (sp === 53 || dp === 53) && end - pl > 2) { app = phDnsInfo(b, pl + 2, end); if (app) pkt.protocol = 'DNS'; }
    }
    pkt.info = app || (sp + ' -> ' + dp + ' [' + pkt.flags + '] Seq=' + seq + (fl & 0x10 ? ' Ack=' + ack : '') + ' Win=' + win + ' Len=' + Math.max(0, end - pl));
  } else if (proto === 17 && end - l4 >= 8) {
    var usp = (b[l4] << 8) | b[l4 + 1], udp = (b[l4 + 2] << 8) | b[l4 + 3];
    pkt.srcPort = usp; pkt.dstPort = udp; pkt.udpLength = (b[l4 + 4] << 8) | b[l4 + 5];
    pkt.checksum = '0x' + phHex(b, l4 + 6, l4 + 8);
    pkt.payload = phHex(b, l4 + 8, Math.min(end, l4 + 8 + PH_PAYLOAD_HEX_BYTES));
    pkt.protocol = 'UDP';
    var dinfo = (usp === 53 || udp === 53 || usp === 5353 || udp === 5353) ? phDnsInfo(b, l4 + 8, end) : null;
    if (dinfo) { pkt.protocol = 'DNS'; pkt.info = dinfo; }
    else pkt.info = usp + ' -> ' + udp + ' Len=' + Math.max(0, pkt.udpLength - 8);
  } else if ((proto === 1 || proto === 58) && end - l4 >= 4) {
    var it = b[l4], ic = b[l4 + 1];
    pkt.protocol = 'ICMP'; pkt.icmpType = it; pkt.icmpCode = ic;
    pkt.checksum = '0x' + phHex(b, l4 + 2, l4 + 4);
    pkt.payload = phHex(b, l4, Math.min(end, l4 + PH_PAYLOAD_HEX_BYTES));
    var names = proto === 1 ? { 0: 'Echo (ping) reply', 3: 'Destination unreachable', 5: 'Redirect', 8: 'Echo (ping) request', 11: 'Time exceeded' }
                            : { 1: 'Destination unreachable', 3: 'Time exceeded', 128: 'Echo (ping) request', 129: 'Echo (ping) reply', 133: 'Router solicitation', 134: 'Router advertisement', 135: 'Neighbor solicitation', 136: 'Neighbor advertisement' };
    var nm = names[it] || ('Type ' + it + ' code ' + ic);
    if ((/Echo/.test(nm)) && end - l4 >= 8) {
      nm += ' id=0x' + phHex(b, l4 + 4, l4 + 6) + ' seq=' + ((b[l4 + 6] << 8) | b[l4 + 7]);
    }
    pkt.info = (proto === 58 ? 'ICMPv6 ' : '') + nm;
  } else {
    pkt.protocol = 'IPv' + pkt.ipVersion;
    pkt.payload = phHex(b, l4, Math.min(end, l4 + PH_PAYLOAD_HEX_BYTES));
    pkt.info = 'IP protocol ' + proto;
  }
  return true;
}

// Returns { packets, linktype, nanos, truncated, skipped } or throws Error with a
// user-facing message.
function phParsePcap(buf) {
  var b = new Uint8Array(buf);
  if (b.length < 24) throw new Error('File is too small to be a pcap capture (' + b.length + ' bytes).');
  var dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  var m = dv.getUint32(0, false);
  if (m === 0x0a0d0d0a) throw new Error('This is a pcapng file. Only classic pcap is supported: in Wireshark use File > Save As > "Wireshark/tcpdump - pcap", or run: editcap -F pcap in.pcapng out.pcap');
  var le, nanos;
  if (m === 0xa1b2c3d4) { le = false; nanos = false; }
  else if (m === 0xd4c3b2a1) { le = true; nanos = false; }
  else if (m === 0xa1b23c4d) { le = false; nanos = true; }
  else if (m === 0x4d3cb2a1) { le = true; nanos = true; }
  else throw new Error('Not a pcap file (unknown magic number 0x' + m.toString(16).padStart(8, '0') + ').');
  var linktype = dv.getUint32(20, le) & 0x0fffffff;
  if ([0, 1, 12, 14, 101, 113].indexOf(linktype) === -1) {
    throw new Error('Unsupported link type ' + linktype + '. Supported: Ethernet (1), raw IP (101), Linux cooked (113), loopback (0).');
  }
  var packets = [], skipped = 0, truncated = false, off = 24, t0 = null;
  while (off + 16 <= b.length) {
    if (packets.length + skipped >= PH_PCAP_MAX_PACKETS) { truncated = true; break; }
    var sec = dv.getUint32(off, le), frac = dv.getUint32(off + 4, le);
    var incl = dv.getUint32(off + 8, le), orig = dv.getUint32(off + 12, le);
    var start = off + 16, end = start + incl;
    if (end > b.length) { truncated = true; break; }
    off = end;
    var ts = sec + frac / (nanos ? 1e9 : 1e6);
    if (t0 === null) t0 = ts;
    var pkt = {
      id: packets.length + skipped + 1, ts: ts - t0, absTs: ts,
      srcMAC: '', dstMAC: '', srcIP: '', dstIP: '', srcPort: 0, dstPort: 0,
      protocol: 'Other', length: orig, capLength: incl, ttl: 0, flags: '', payload: '', info: '',
      linktype: linktype, imported: true
    };
    var o = start, ethType = 0;
    if (linktype === 1) {
      if (incl < 14) { skipped++; continue; }
      pkt.dstMAC = phMac(b, o); pkt.srcMAC = phMac(b, o + 6);
      ethType = (b[o + 12] << 8) | b[o + 13]; o += 14;
      if ((ethType === 0x8100 || ethType === 0x88a8) && o + 4 <= end) { pkt.vlan = ((b[o] << 8) | b[o + 1]) & 0x0fff; ethType = (b[o + 2] << 8) | b[o + 3]; o += 4; }
    } else if (linktype === 113) {
      if (incl < 16) { skipped++; continue; }
      ethType = (b[o + 14] << 8) | b[o + 15]; o += 16;
    } else if (linktype === 0) {
      if (incl < 4) { skipped++; continue; }
      o += 4; ethType = (b[o] >> 4) === 6 ? 0x86dd : 0x0800;
    } else {
      ethType = (b[o] >> 4) === 6 ? 0x86dd : 0x0800;
    }
    pkt.ethType = ethType;
    if (ethType === 0x0800 || ethType === 0x86dd) {
      if (!phDecodeIP(b, o, end, pkt)) { pkt.protocol = 'Other'; pkt.info = 'Malformed or truncated IP header'; }
    } else if (ethType === 0x0806) {
      pkt.protocol = 'ARP';
      if (end - o >= 28) {
        var op = (b[o + 6] << 8) | b[o + 7];
        var spa = b[o + 14] + '.' + b[o + 15] + '.' + b[o + 16] + '.' + b[o + 17];
        var tpa = b[o + 24] + '.' + b[o + 25] + '.' + b[o + 26] + '.' + b[o + 27];
        pkt.srcIP = spa; pkt.dstIP = tpa;
        pkt.info = op === 1 ? 'Who has ' + tpa + '? Tell ' + spa : op === 2 ? spa + ' is at ' + phMac(b, o + 8) : 'ARP op ' + op;
      } else pkt.info = 'ARP (truncated)';
      pkt.payload = phHex(b, o, Math.min(end, o + PH_PAYLOAD_HEX_BYTES));
    } else {
      pkt.info = 'EtherType 0x' + ethType.toString(16).padStart(4, '0');
      pkt.payload = phHex(b, o, Math.min(end, o + PH_PAYLOAD_HEX_BYTES));
    }
    packets.push(pkt);
  }
  if (off < b.length && !truncated) truncated = true;
  return { packets: packets, linktype: linktype, nanos: nanos, truncated: truncated, skipped: skipped };
}

// ============================================================================
// SECURITY GRAPH EXPORT
// ============================================================================
// PHANTOM has no live capture path. Packets come either from the demo dataset
// (tagged simulated) or from a user-imported classic pcap file (tagged imported).
// The anomaly list is always demo data, so it is always tagged simulated.
var PH_SEV = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };
var PH_IP_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
var PH_DOMAIN_RE = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;

function phIsPrivate(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip);
}

function phHostItem(ip, extra, imported) {
  var tags = ['phantom', 'network', imported ? 'pcap-import' : 'simulated', phIsPrivate(ip) ? 'internal' : 'external'];
  var base = imported ? { source: 'pcap import' } : { simulated: true };
  return { type: 'IP', name: ip, data: Object.assign(base, extra || {}), opts: { tags: tags } };
}

function phUnique(arr) {
  return arr.filter(function(v, i) { return arr.indexOf(v) === i; });
}

function phSendGraph(btn, build, tagNote) {
  btn.disabled = true;
  import('/js/graph-bridge.js?v=20260923c').then(function(gb) {
    var res = build(gb);
    btn.textContent = 'Sent: ' + res.created + ' new, ' + res.updated + ' merged';
    gb.showGraphToast('Security Graph: ' + res.summary + ' (' + (tagNote || 'tagged simulated') + ')');
  }).catch(function() { btn.textContent = 'Security Graph unavailable'; btn.disabled = false; });
}

// Unique hosts seen in the capture -> IP entities with traffic totals.
function phSendHosts(btn, packets, imported) {
  phSendGraph(btn, function(gb) {
    var hosts = {};
    packets.forEach(function(p) {
      [[p.srcIP, 'sent'], [p.dstIP, 'recv']].forEach(function(pair) {
        var ip = pair[0];
        if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return;
        var h = hosts[ip] || (hosts[ip] = { packets: 0, bytes: 0, protocols: [] });
        h.packets++; h.bytes += p.length || 0;
        if (h.protocols.indexOf(p.protocol) === -1) h.protocols.push(p.protocol);
      });
    });
    var items = Object.keys(hosts).map(function(ip) {
      var h = hosts[ip];
      return phHostItem(ip, { packets: h.packets, bytes: h.bytes, protocols: h.protocols.join(', ') }, imported);
    });
    var r = gb.sendToGraph('PHANTOM', items, undefined, true);
    r.summary = items.length + ' hosts, ' + r.created + ' added';
    return r;
  }, imported ? 'tagged pcap-import' : 'tagged simulated');
}

// Anomalies -> ALERT (with severity), linked to the IPs/domains named in their evidence.
function phSendAnomalies(btn, anomalies) {
  phSendGraph(btn, function(gb) {
    var created = 0, updated = 0, links = 0;
    anomalies.forEach(function(a) {
      var text = a.description + ' ' + a.evidence;
      var ips = phUnique(text.match(PH_IP_RE) || []);
      var domains = phUnique((text.match(PH_DOMAIN_RE) || []).filter(function(d) { return !/^\d+(\.\d+)+$/.test(d); }));
      var ar = gb.sendToGraph('PHANTOM', [{
        type: 'ALERT', name: 'PHANTOM: ' + a.type,
        data: { description: a.description, evidence: a.evidence, recommendation: a.recommendation, involvedIPs: ips.join(', '), simulated: true },
        opts: { tags: ['phantom', 'anomaly', 'simulated'], severity: PH_SEV[a.severity] || null }
      }], undefined, true);
      created += ar.created; updated += ar.updated;
      var alert = ar.entities[0];
      var rr = gb.sendToGraph('PHANTOM', ips.map(function(ip) { return phHostItem(ip, { seenIn: a.type }); }).concat(domains.map(function(d) {
        return { type: 'DOMAIN', name: d.toLowerCase(), data: { seenIn: a.type, simulated: true }, opts: { tags: ['phantom', 'network', 'simulated'] } };
      })), undefined, true);
      created += rr.created; updated += rr.updated;
      if (alert) rr.entities.forEach(function(e) {
        if (gb.linkEntities(alert.id, e.id, e.type === 'IP' ? 'observed_in' : 'related_to')) links++;
      });
    });
    return { created: created, updated: updated, summary: anomalies.length + ' alerts, ' + created + ' added, ' + links + ' links' };
  });
}

// ============================================================================
// STREAM / FILTER / EXPORT HELPERS (added features)
// ============================================================================
var PH_PROTOS = ['TCP', 'UDP', 'DNS', 'HTTP', 'TLS', 'ICMP', 'ARP'];

// Map an application protocol to its transport-layer protocol for 5-tuple grouping.
function phTransport(proto) {
  if (proto === 'TCP' || proto === 'TLS' || proto === 'HTTP') return 'TCP';
  if (proto === 'UDP' || proto === 'DNS') return 'UDP';
  return proto;
}

// Group packets into bidirectional streams keyed by a normalized 5-tuple
// (transport + sorted endpoints, so A<->B and B<->A collapse into one stream).
function phBuildStreams(packets) {
  var map = {};
  packets.forEach(function(p) {
    var t = phTransport(p.protocol);
    var a = p.srcIP + ':' + p.srcPort;
    var b = p.dstIP + ':' + p.dstPort;
    var lo = a <= b ? a : b;
    var hi = a <= b ? b : a;
    var key = t + '|' + lo + '|' + hi;
    var s = map[key] || (map[key] = {
      key: key, transport: t, epA: lo, epB: hi,
      packets: [], bytes: 0, startTs: p.ts, endTs: p.ts,
      protocols: [], client: null, server: null
    });
    // The source of the first packet seen is treated as the client (initiator).
    if (s.client === null) { s.client = a; s.server = b; }
    s.packets.push(p);
    s.bytes += p.length || 0;
    if (p.ts < s.startTs) s.startTs = p.ts;
    if (p.ts > s.endTs) s.endTs = p.ts;
    if (s.protocols.indexOf(p.protocol) === -1) s.protocols.push(p.protocol);
  });
  return Object.keys(map).map(function(k) { return map[k]; });
}

// Small inline bar meter using site tokens.
function phMeter(pct, color) {
  var w = Math.max(0, Math.min(100, pct || 0));
  return '<span class="ph-meter"><span class="ph-meter-fill" style="width:' + w.toFixed(1) + '%;background:' + (color || '#06b6d4') + '"></span></span>';
}

// Parse a single Wireshark-style filter term into a predicate.
function phParseTerm(term) {
  var m = term.match(/^(\S+)\s*(==|!=)\s*(.+)$/);
  if (m) {
    var field = m[1].toLowerCase();
    var neg = m[2] === '!=';
    var val = m[3].trim().replace(/^["']|["']$/g, '');
    var test, n;
    switch (field) {
      case 'ip.addr': case 'addr':
        test = function(p) { return p.srcIP === val || p.dstIP === val; }; break;
      case 'ip.src': case 'src':
        test = function(p) { return p.srcIP === val; }; break;
      case 'ip.dst': case 'dst':
        test = function(p) { return p.dstIP === val; }; break;
      case 'tcp.port':
        n = parseInt(val, 10);
        if (isNaN(n)) return { ok: false, error: 'Invalid port number "' + val + '"' };
        test = function(p) { return phTransport(p.protocol) === 'TCP' && (p.srcPort === n || p.dstPort === n); }; break;
      case 'udp.port':
        n = parseInt(val, 10);
        if (isNaN(n)) return { ok: false, error: 'Invalid port number "' + val + '"' };
        test = function(p) { return phTransport(p.protocol) === 'UDP' && (p.srcPort === n || p.dstPort === n); }; break;
      case 'port':
        n = parseInt(val, 10);
        if (isNaN(n)) return { ok: false, error: 'Invalid port number "' + val + '"' };
        test = function(p) { return p.srcPort === n || p.dstPort === n; }; break;
      case 'protocol': case 'proto': case 'ip.proto':
        test = function(p) { return p.protocol.toLowerCase() === val.toLowerCase(); }; break;
      default:
        return { ok: false, error: 'Unknown field "' + field + '"' };
    }
    return { ok: true, fn: neg ? function(p) { return !test(p); } : test };
  }
  // Bare protocol name, e.g. DNS / TLS.
  if (PH_PROTOS.indexOf(term.toUpperCase()) >= 0) {
    var up = term.toUpperCase();
    return { ok: true, fn: function(p) { return p.protocol === up; } };
  }
  return { ok: false, error: 'Cannot parse "' + term + '"' };
}

// Parse a full filter expression (terms joined by && or the word "and").
function phParseFilter(expr) {
  expr = (expr || '').trim();
  if (!expr) return { ok: true, fn: function() { return true; }, empty: true };
  var parts = expr.split(/\s*(?:&&|\band\b)\s*/i).map(function(s) { return s.trim(); }).filter(Boolean);
  if (parts.length === 0) return { ok: true, fn: function() { return true; }, empty: true };
  var preds = [];
  for (var i = 0; i < parts.length; i++) {
    var pr = phParseTerm(parts[i]);
    if (!pr.ok) return pr;
    preds.push(pr.fn);
  }
  return { ok: true, fn: function(p) { return preds.every(function(f) { return f(p); }); } };
}

// Trigger a client-side file download via Blob + object URL (no network).
function phDownload(filename, content, mime) {
  try {
    var blob = new Blob([content], { type: mime || 'application/octet-stream' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window._phantomTimers = window._phantomTimers || [];
    window._phantomTimers.push(setTimeout(function() { URL.revokeObjectURL(url); }, 2000));
  } catch (e) { /* ignore */ }
}

// ============================================================================
// OPERATIONAL MODES — tab catalog tagged by posture (SCOUTING/DEFENSIVE/OFFENSIVE)
// ============================================================================
// A tab with no `modes` array is mode-agnostic (shows in every posture). The
// core/tool-modes switcher filters this list to the active posture.
var PH_TABS = [
  { id: 'dashboard', label: 'Dashboard' },                                        // agnostic overview
  { id: 'capture', label: 'Capture' },                                            // agnostic — load packets in any posture
  { id: 'recon', label: 'Network Recon', modes: ['scouting'] },                   // NEW scouting panel
  { id: 'flows', label: 'Flow Analysis', modes: ['scouting', 'defensive'] },
  { id: 'stats', label: 'Statistics', modes: ['scouting', 'defensive'] },
  { id: 'trafficstats', label: 'Traffic Stats', modes: ['scouting', 'defensive'] },
  { id: 'dissector', label: 'Protocol Dissector', modes: ['defensive'] },
  { id: 'anomaly', label: 'Anomaly Detection', modes: ['defensive', 'offensive'] },
  { id: 'dns', label: 'DNS Inspector', modes: ['defensive'] },
  { id: 'tls', label: 'TLS / SSL', modes: ['defensive'] },
  { id: 'stream', label: 'Follow Stream', modes: ['defensive'] },
  { id: 'filter', label: 'Display Filter', modes: ['defensive'] },
  { id: 'ioc', label: 'IOC Export', modes: ['defensive'] },
  { id: 'attacksim', label: 'Attack Simulation', modes: ['offensive'] },          // NEW offensive panel
];

// Well-known service ports for recon service enumeration + exposure grading.
// exposure: 'plaintext' (data in the clear), 'exposed' (high-value remote svc),
// 'suspicious' (attacker infra), 'encrypted' (protected).
var PH_SERVICE_PORTS = {
  21: { name: 'FTP', exposure: 'plaintext' },
  22: { name: 'SSH', exposure: 'encrypted' },
  23: { name: 'Telnet', exposure: 'plaintext' },
  25: { name: 'SMTP', exposure: 'plaintext' },
  53: { name: 'DNS', exposure: 'plaintext' },
  80: { name: 'HTTP', exposure: 'plaintext' },
  110: { name: 'POP3', exposure: 'plaintext' },
  123: { name: 'NTP', exposure: 'plaintext' },
  137: { name: 'NetBIOS-NS', exposure: 'plaintext' },
  139: { name: 'NetBIOS-SSN', exposure: 'exposed' },
  143: { name: 'IMAP', exposure: 'plaintext' },
  443: { name: 'HTTPS / TLS', exposure: 'encrypted' },
  445: { name: 'SMB', exposure: 'exposed' },
  3306: { name: 'MySQL', exposure: 'exposed' },
  3389: { name: 'RDP', exposure: 'exposed' },
  4444: { name: 'Shell / C2', exposure: 'suspicious' },
  5432: { name: 'PostgreSQL', exposure: 'exposed' },
  8080: { name: 'HTTP-Alt', exposure: 'plaintext' },
  8443: { name: 'HTTPS-Alt', exposure: 'encrypted' },
};

function phServiceInfo(port) {
  return PH_SERVICE_PORTS[port] || null;
}

// ============================================================================
// OFFENSIVE — simulated attack scenarios (adversary emulation for blue-team
// testing only). Every play generates an illustrative, hardcoded packet
// sequence and a verdict for whether PHANTOM's own defensive views would catch
// it. SIMULATION ONLY: no packet crafting, no network calls.
// ============================================================================
var PH_ATTACK_PLAYS = [
  {
    id: 'portscan',
    name: 'TCP SYN Port Scan',
    tactic: 'Reconnaissance / Service Discovery',
    summary: 'Rapid half-open SYN probes across many ports on one host to enumerate open services without completing handshakes.',
    chain: [
      'Attacker selects a target host on the segment',
      'Emit SYN packets to a sweep of common service ports',
      'Open ports answer SYN,ACK; closed ports answer RST',
      'Never complete the handshake (stealth / half-open scan)',
      'Map the responses into an open-service inventory',
    ],
    verdict: 'DETECTED',
    control: 'Flow Analysis + Anomaly Detection',
    detectNote: 'One source fanning out to many ports on a single host in a tight window is a textbook horizontal scan. Flow Analysis shows the fan-out and the lopsided half-open ratio; an IDS rule fires on SYN volume per source.',
    gen: function(target) {
      var atk = '10.0.0.66';
      var ports = [21, 22, 23, 80, 139, 443, 445, 3306, 3389, 8080];
      var open = { 22: 1, 80: 1, 443: 1, 445: 1 };
      var seq = [];
      var t = 0;
      ports.forEach(function(port, i) {
        t += 0.0012 + i * 0.0004;
        seq.push({ ts: t, src: atk + ':' + (40000 + i), dst: target + ':' + port, proto: 'TCP', len: 74, flags: 'SYN', info: 'Probe ' + port + ' [SYN]' });
        t += 0.0006;
        if (open[port]) seq.push({ ts: t, src: target + ':' + port, dst: atk + ':' + (40000 + i), proto: 'TCP', len: 74, flags: 'SYN,ACK', info: 'Port ' + port + ' OPEN [SYN,ACK]' });
        else seq.push({ ts: t, src: target + ':' + port, dst: atk + ':' + (40000 + i), proto: 'TCP', len: 54, flags: 'RST,ACK', info: 'Port ' + port + ' closed [RST,ACK]' });
      });
      return seq;
    },
  },
  {
    id: 'arpspoof',
    name: 'ARP Spoof / MITM',
    tactic: 'Adversary-in-the-Middle',
    summary: 'Poison the victim and gateway ARP caches so all traffic is relayed through the attacker for interception.',
    chain: [
      'Attacker sends forged ARP replies to the victim ("I am the gateway")',
      'Attacker sends forged ARP replies to the gateway ("I am the victim")',
      'Both caches now map the peer IP to the attacker MAC',
      'Victim traffic is relayed through the attacker (interception)',
      'Attacker forwards packets to keep the path alive (MITM)',
    ],
    verdict: 'PARTIAL',
    control: 'Protocol Dissector (L2 visibility gap)',
    detectNote: 'PHANTOM dissects layer 3 and above; ARP lives at layer 2 and is largely invisible in this IP-centric capture. Detection depends on correlating a single MAC suddenly claiming two IPs, or one IP flipping MACs — a genuine visibility gap to close with dedicated ARP monitoring.',
    gen: function(target) {
      var atkMac = 'aa:bb:cc:00:11:66';
      var gw = '10.0.0.1';
      return [
        { ts: 0.0000, src: atkMac + ' (' + target + ')', dst: gw, proto: 'ARP', len: 42, flags: '', info: 'Gratuitous ARP: ' + target + ' is-at ' + atkMac + ' (spoofed)' },
        { ts: 0.0100, src: atkMac + ' (' + gw + ')', dst: target, proto: 'ARP', len: 42, flags: '', info: 'Gratuitous ARP: ' + gw + ' is-at ' + atkMac + ' (spoofed)' },
        { ts: 0.5200, src: target + ':49300', dst: '93.184.216.34:443', proto: 'TLS', len: 583, flags: 'PSH,ACK', info: 'Victim traffic now transiting attacker MAC' },
        { ts: 0.5240, src: atkMac + ' relay', dst: '93.184.216.34:443', proto: 'TLS', len: 583, flags: 'PSH,ACK', info: 'Attacker forwards packet (interception)' },
        { ts: 1.0300, src: atkMac + ' (' + gw + ')', dst: target, proto: 'ARP', len: 42, flags: '', info: 'Re-assert poisoned mapping (keep-alive)' },
      ];
    },
  },
  {
    id: 'dnsexfil',
    name: 'DNS Exfiltration',
    tactic: 'Exfiltration Over Alternative Protocol',
    summary: 'Smuggle stolen data out as encoded labels inside DNS queries to an attacker-controlled authoritative server.',
    chain: [
      'Compromised host chunks and base32/base64-encodes the target data',
      'Each chunk becomes a subdomain label of an attacker domain',
      'Host issues TXT/A queries; the recursive resolver forwards them',
      'Attacker name server reconstructs the data from the labels',
      'Traffic blends into normally-permitted DNS',
    ],
    verdict: 'DETECTED',
    control: 'DNS Inspector + Anomaly Detection',
    detectNote: 'Abnormally long, high-entropy subdomain labels and a burst of TXT queries to a single low-reputation domain trip the DNS Tunneling rule already present in Anomaly Detection; DNS Inspector surfaces the encoded labels directly.',
    gen: function(target) {
      var labels = ['aGVsbG8gd29ybGQ', 'c2VjcmV0ZmlsZQ', 'cGFzc3dvcmRz', 'ZXhmaWxjaHVuaw'];
      var seq = [];
      var t = 0;
      labels.forEach(function(lab, i) {
        t += 0.12 + i * 0.03;
        seq.push({ ts: t, src: target + ':' + (51300 + i), dst: '8.8.8.8:53', proto: 'DNS', len: 90 + lab.length, flags: '', info: 'Query TXT ' + lab + '.c2.evil.com' });
        t += 0.02;
        seq.push({ ts: t, src: '8.8.8.8:53', dst: target + ':' + (51300 + i), proto: 'DNS', len: 70, flags: '', info: 'Response TXT (chunk ' + (i + 1) + '/' + labels.length + ' acked)' });
      });
      return seq;
    },
  },
  {
    id: 'c2beacon',
    name: 'C2 Beacon (Cobalt Strike)',
    tactic: 'Command & Control',
    summary: 'Implant checks in with its controller on a fixed interval over TLS, awaiting tasking.',
    chain: [
      'Implant establishes a TLS channel to the C2 server',
      'Beacon home on a regular interval (with small jitter)',
      'Each check-in is a short, near-identical encrypted request',
      'Controller replies with tasking or an empty ack',
      'Pattern repeats indefinitely (low and slow)',
    ],
    verdict: 'DETECTED',
    control: 'TLS / SSL (JA3) + Flow Analysis',
    detectNote: 'The TLS/SSL view fingerprints the client handshake as JA3 e35f5f2b6d25675d54afec5d54fa5b96 = Cobalt Strike Beacon (Critical). The metronome-like flow timing to one external host is a classic beacon signature in Flow Analysis.',
    gen: function(target) {
      var c2 = '198.51.100.44';
      var seq = [];
      var base = 0;
      seq.push({ ts: 0, src: target + ':49400', dst: c2 + ':443', proto: 'TLS', len: 517, flags: 'PSH,ACK', info: 'Client Hello (JA3: Cobalt Strike Beacon)' });
      for (var i = 0; i < 4; i++) {
        base += 60.0 + (i % 2 ? 0.8 : -0.6); // ~60s interval with jitter
        seq.push({ ts: base, src: target + ':' + (49400 + i), dst: c2 + ':443', proto: 'TLS', len: 226 + (i % 3), flags: 'PSH,ACK', info: 'Beacon check-in #' + (i + 1) + ' (encrypted)' });
        seq.push({ ts: base + 0.03, src: c2 + ':443', dst: target + ':' + (49400 + i), proto: 'TLS', len: 118, flags: 'PSH,ACK', info: 'C2 tasking / ack (encrypted)' });
      }
      return seq;
    },
  },
  {
    id: 'synflood',
    name: 'SYN Flood (DoS)',
    tactic: 'Resource Exhaustion / Denial of Service',
    summary: 'Flood a service with spoofed-source SYNs to exhaust its half-open connection table.',
    chain: [
      'Attacker generates SYNs with randomized spoofed source IPs',
      'Target allocates a half-open connection per SYN and replies SYN,ACK',
      'The spoofed sources never send the final ACK',
      'The backlog fills; legitimate handshakes are refused',
      'Service availability degrades or collapses',
    ],
    verdict: 'DETECTED',
    control: 'Statistics + Traffic Stats',
    detectNote: 'A sharp spike in SYN packets to one port with an extreme SYN-to-ACK imbalance and many one-packet sources is unmistakable. Statistics and Traffic Stats surface the volume and the half-open ratio.',
    gen: function(target) {
      var seq = [];
      var t = 0;
      for (var i = 0; i < 10; i++) {
        var spoof = '203.0.113.' + (10 + i * 7 % 240);
        t += 0.0003;
        seq.push({ ts: t, src: spoof + ':' + (1024 + i * 111), dst: target + ':80', proto: 'TCP', len: 60, flags: 'SYN', info: 'Spoofed SYN (no ACK will follow)' });
        if (i < 3) { t += 0.0002; seq.push({ ts: t, src: target + ':80', dst: spoof + ':' + (1024 + i * 111), proto: 'TCP', len: 60, flags: 'SYN,ACK', info: 'Half-open allocated (backlog+1)' }); }
      }
      return seq;
    },
  },
];

function phVerdictBadge(v) {
  var map = { DETECTED: 'LOW', PARTIAL: 'MEDIUM', MISSED: 'CRITICAL' };
  var label = { DETECTED: 'DETECTED & CONTAINED', PARTIAL: 'PARTIALLY DETECTED', MISSED: 'MISSED — CONTROL GAP' };
  return '<span class="ph-badge ph-sev-' + (map[v] || 'INFO') + '">' + esc(label[v] || v) + '</span>';
}

// ============================================================================
// MAIN RENDER
// ============================================================================
var _phInterval = null;

export function renderPhantom(main) {
  var activeTab = 'dashboard';
  var packets = [];
  var selectedPkt = null;
  var selectedFlow = null;
  var selectedStream = null;
  var filterExpr = '';
  var autoRefresh = false;
  var currentMode = getToolMode('phantom');
  // Where the loaded packets came from: null (none), { demo: true } or
  // { demo: false, name, size, linktype, truncated, skipped } for a pcap import.
  var dataSource = null;
  var importMsg = '';

  function loadDemo() {
    packets = SAMPLE_PACKETS.slice();
    dataSource = { demo: true };
    importMsg = '';
    selectedPkt = null;
    selectedFlow = null;
    selectedStream = null;
    render();
  }

  function isImported() { return !!(dataSource && !dataSource.demo); }

  function sourceBanner() {
    if (!packets.length || !dataSource) return '';
    if (dataSource.demo) {
      return '<div class="ph-src-banner demo"><b>Demo data</b> - these ' + packets.length + ' packets are a built-in sample capture, not traffic from your network. Import a classic .pcap file to analyze real traffic.</div>';
    }
    return '<div class="ph-src-banner real"><b>Imported capture</b> - ' + esc(dataSource.name) + ' (' + fmtBytes(dataSource.size) + ', ' + packets.length + ' packets' +
      (dataSource.skipped ? ', ' + dataSource.skipped + ' unreadable frames skipped' : '') +
      (dataSource.truncated ? ', file truncated or over the ' + PH_PCAP_MAX_PACKETS + '-packet limit' : '') +
      '). Parsed locally in your browser; the file is not uploaded.</div>';
  }

  function render() {
    var visTabs = filterTabsByMode(PH_TABS, currentMode);
    // If the active tab isn't in the current posture, fall back to the first visible one.
    if (!visTabs.some(function(t) { return t.id === activeTab; })) {
      activeTab = (visTabs[0] && visTabs[0].id) || 'dashboard';
    }

    main.innerHTML =
      '<style>' +
      '.ph-wrap{font-family:var(--font-body,system-ui,sans-serif);position:relative}' +
      '.ph-header{display:flex;align-items:center;gap:16px;padding:16px 0;border-bottom:2px solid #06b6d4}' +
      '.ph-title{font-size:1.5rem;font-weight:800;letter-spacing:.08em;color:#06b6d4;margin:0}' +
      '.ph-sub{color:var(--mut);font-size:.72rem;letter-spacing:.04em;text-transform:uppercase}' +
      '.ph-dot{width:8px;height:8px;border-radius:50%;background:#22c55e;box-shadow:0 0 8px #22c55e;animation:ph-pulse 2s ease-in-out infinite}' +
      '@keyframes ph-pulse{0%,100%{opacity:1}50%{opacity:.4}}' +
      '.ph-tabs{display:flex;gap:2px;overflow-x:auto;padding:10px 0 0;border-bottom:none;scrollbar-width:none}' +
      '.ph-tabs::-webkit-scrollbar{display:none}' +
      '.ph-tab{background:transparent;border:none;border-bottom:2px solid transparent;color:var(--mut);padding:8px 14px;font-size:.7rem;font-weight:600;letter-spacing:.03em;text-transform:uppercase;cursor:pointer;transition:all .15s;font-family:inherit;white-space:nowrap;flex-shrink:0}' +
      '.ph-tab:hover{color:var(--txt);background:rgba(6,182,212,.05)}' +
      '.ph-tab.on{color:#06b6d4;border-bottom-color:#06b6d4}' +
      '.ph-src-banner{margin-top:10px;padding:8px 12px;border-radius:6px;font-size:.74rem;line-height:1.45;border:1px solid var(--line);color:var(--txt)}' +
      '.ph-src-banner.demo{border-left:3px solid #eab308;background:rgba(234,179,8,.08)}' +
      '.ph-src-banner.real{border-left:3px solid #22c55e;background:rgba(34,197,94,.08)}' +
      '.ph-demo-tag{display:inline-block;padding:1px 6px;border-radius:4px;background:rgba(234,179,8,.18);color:#a16207;font-size:.62rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;margin-left:6px}' +
      '.ph-panel{background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden;margin-bottom:12px}' +
      '.ph-panel-h{padding:10px 14px;border-bottom:1px solid var(--line);background:rgba(0,0,0,.06);font-size:.7rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--mut);display:flex;align-items:center;gap:8px}' +
      '.ph-panel-body{padding:14px}' +
      '.ph-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-bottom:16px}' +
      '.ph-stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;text-align:center}' +
      '.ph-stat-n{font-size:1.8rem;font-weight:800;color:var(--txt);font-variant-numeric:tabular-nums}' +
      '.ph-stat-l{font-size:.68rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);margin-top:2px}' +
      '.ph-table{width:100%;border-collapse:collapse;font-size:.78rem}' +
      '.ph-table th{text-align:left;font-weight:700;font-size:.65rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);padding:8px 10px;border-bottom:2px solid var(--line);position:sticky;top:0;background:var(--card)}' +
      '.ph-table td{padding:6px 10px;border-bottom:1px solid var(--line);color:var(--txt);vertical-align:top;font-variant-numeric:tabular-nums}' +
      '.ph-table tr.ph-row-sel td{background:rgba(6,182,212,.1);border-color:rgba(6,182,212,.2)}' +
      '.ph-table tr[data-pkt]:hover td{background:rgba(6,182,212,.04);cursor:pointer}' +
      '.ph-proto{display:inline-block;padding:1px 6px;border-radius:4px;font-size:.68rem;font-weight:700;letter-spacing:.02em}' +
      '.ph-scroll{max-height:420px;overflow-y:auto;scrollbar-width:thin}' +
      '.ph-hex{font-family:var(--font-mono,"JetBrains Mono",monospace);font-size:.72rem;line-height:1.65;background:var(--card2,#0a0e16);color:#94a3b8;padding:14px;border-radius:6px;overflow-x:auto;white-space:pre;border:1px solid var(--line)}' +
      '.ph-btn{background:#06b6d4;color:#fff;border:none;border-radius:6px;padding:6px 14px;font-size:.76rem;font-weight:600;cursor:pointer;font-family:inherit;transition:background .15s}' +
      '.ph-btn:hover{background:#0891b2}' +
      '.ph-btn.ghost{background:transparent;color:var(--txt);border:1px solid var(--line)}' +
      '.ph-btn.ghost:hover{border-color:#06b6d4;color:#06b6d4}' +
      '.ph-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:700;letter-spacing:.02em}' +
      '.ph-sev-CRITICAL{background:#fef2f2;color:#991b1b}.ph-sev-HIGH{background:#fff7ed;color:#9a3412}.ph-sev-MEDIUM{background:#fefce8;color:#854d0e}.ph-sev-LOW{background:#f0fdf4;color:#166534}.ph-sev-INFO{background:#eff6ff;color:#1e40af}' +
      '.ph-alert{border:1px solid var(--line);border-radius:8px;padding:14px;margin-bottom:10px;background:var(--card)}' +
      '.ph-alert-head{display:flex;align-items:center;gap:10px;margin-bottom:6px}' +
      '.ph-alert-type{font-weight:700;font-size:.85rem;color:var(--txt)}' +
      '.ph-alert-desc{font-size:.8rem;color:var(--txt);margin-bottom:6px;line-height:1.5}' +
      '.ph-alert-ev{font-size:.72rem;color:var(--mut);font-family:var(--font-mono,monospace);margin-bottom:6px;padding:8px;background:var(--card2,rgba(0,0,0,.1));border-radius:4px}' +
      '.ph-alert-rec{font-size:.76rem;color:var(--txt);padding:8px;background:rgba(6,182,212,.06);border-radius:4px;border-left:3px solid #06b6d4}' +
      '.ph-tree{padding:0;margin:0;list-style:none}' +
      '.ph-tree-node{margin-bottom:2px}' +
      '.ph-tree-head{display:flex;align-items:center;gap:6px;padding:6px 10px;border-radius:4px;cursor:pointer;font-size:.78rem;font-weight:600;user-select:none}' +
      '.ph-tree-head:hover{background:rgba(255,255,255,.03)}' +
      '.ph-tree-arrow{font-size:.6rem;color:var(--mut);transition:transform .15s;display:inline-block;width:12px}' +
      '.ph-tree-arrow.open{transform:rotate(90deg)}' +
      '.ph-tree-children{margin-left:20px;padding-left:12px;border-left:1px solid var(--line)}' +
      '.ph-tree-field{display:flex;gap:12px;padding:3px 10px;font-size:.74rem}' +
      '.ph-tree-key{color:var(--mut);min-width:140px;flex-shrink:0}' +
      '.ph-tree-val{color:var(--txt);font-family:var(--font-mono,monospace)}' +
      '.ph-bar{height:20px;border-radius:4px;display:flex;overflow:hidden;margin:8px 0}' +
      '.ph-bar-seg{height:100%;display:flex;align-items:center;justify-content:center;font-size:.58rem;font-weight:700;color:#fff;min-width:30px;transition:width .3s}' +
      '.ph-hist-row{display:flex;align-items:center;gap:8px;margin-bottom:4px}' +
      '.ph-hist-label{font-size:.72rem;color:var(--mut);min-width:80px;text-align:right}' +
      '.ph-hist-bar{height:18px;border-radius:3px;background:#06b6d4;transition:width .3s}' +
      '.ph-hist-n{font-size:.68rem;color:var(--mut);min-width:30px}' +
      '.ph-matrix{display:grid;gap:2px;font-size:.62rem}' +
      '.ph-matrix-cell{padding:4px;text-align:center;border-radius:2px;font-variant-numeric:tabular-nums}' +
      '.ph-file-input{display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap}' +
      '.ph-empty{text-align:center;padding:40px 20px;color:var(--mut);font-size:.85rem}' +
      '.ph-flow-dir{color:#06b6d4;font-weight:700;font-size:.68rem}' +
      '.ph-chip{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:10px;font-size:.65rem;font-weight:600;background:rgba(6,182,212,.1);color:#06b6d4;border:1px solid rgba(6,182,212,.2)}' +
      '.ph-meter{display:inline-block;vertical-align:middle;width:90px;height:8px;border-radius:4px;background:var(--line);overflow:hidden;margin-right:6px}' +
      '.ph-meter-fill{display:block;height:100%;border-radius:4px;background:#06b6d4}' +
      '.ph-stream-view{display:flex;flex-direction:column;gap:6px}' +
      '.ph-stream-line{padding:6px 10px;border-radius:5px;border-left:3px solid var(--line);background:var(--card2,rgba(0,0,0,.1))}' +
      '.ph-stream-line.ph-dir-cs{border-left-color:#06b6d4}' +
      '.ph-stream-line.ph-dir-sc{border-left-color:#a855f7}' +
      '.ph-dir-cs{color:#06b6d4}.ph-dir-sc{color:#a855f7}' +
      '.ph-stream-dir{font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em}' +
      '.ph-stream-meta{font-size:.62rem;color:var(--mut);margin-left:8px;font-family:var(--font-mono,monospace)}' +
      '.ph-stream-body{font-family:var(--font-mono,monospace);font-size:.72rem;color:var(--txt);margin-top:3px;word-break:break-all}' +
      '.ph-hint{font-size:.7rem;color:#ef4444;margin-top:6px;min-height:14px}' +
      '</style>' +
      '<div class="ph-wrap">' +
        '<div class="ph-header" style="justify-content:space-between">' +
          '<div style="display:flex;align-items:center;gap:16px">' +
            '<div class="ph-dot"></div>' +
            '<div><div class="ph-title">PHANTOM</div><div class="ph-sub">Packet Handler, Analyzer, Network Topology &amp; Operations Monitor</div></div>' +
          '</div>' +
          '<div id="ph-modebar"></div>' +
        '</div>' +
        '<div class="ph-sub" id="ph-modenote" style="padding:8px 0 0;text-transform:none;letter-spacing:0"></div>' +
        sourceBanner() +
        '<div class="ph-tabs">' +
          visTabs.map(function(t) {
            return '<button class="ph-tab' + (activeTab === t.id ? ' on' : '') + '" data-t="' + t.id + '">' + esc(t.label) + '</button>';
          }).join('') +
        '</div>' +
        '<div id="ph-content" style="margin-top:12px"></div>' +
      '</div>';

    main.querySelector('.ph-tabs').onclick = function(e) {
      var b = e.target.closest('.ph-tab');
      if (b) { activeTab = b.dataset.t; render(); }
    };

    // Operational-mode switcher: filters tabs to the active posture and retints
    // the console. Persists the last-used mode per tool via core/store.
    mountModeSwitcher({
      toolId: 'phantom',
      tabs: PH_TABS,
      mount: main.querySelector('#ph-modebar'),
      host: main.querySelector('.ph-wrap'),
      note: main.querySelector('#ph-modenote'),
      onChange: function(modeId) {
        if (modeId === currentMode) return; // mount-time / same-posture re-fire: no-op
        currentMode = modeId;
        var vt = filterTabsByMode(PH_TABS, currentMode);
        activeTab = (vt[0] && vt[0].id) || 'dashboard';
        render();
      },
    });

    var content = main.querySelector('#ph-content');
    if (activeTab === 'dashboard') renderDashboard(content);
    else if (activeTab === 'capture') renderCapture(content);
    else if (activeTab === 'recon') renderRecon(content);
    else if (activeTab === 'attacksim') renderAttackSim(content);
    else if (activeTab === 'dissector') renderDissector(content);
    else if (activeTab === 'flows') renderFlows(content);
    else if (activeTab === 'anomaly') renderAnomaly(content);
    else if (activeTab === 'dns') renderDNS(content);
    else if (activeTab === 'tls') renderTLS(content);
    else if (activeTab === 'stats') renderStats(content);
    else if (activeTab === 'stream') renderStream(content);
    else if (activeTab === 'trafficstats') renderTrafficStats(content);
    else if (activeTab === 'filter') renderFilter(content);
    else if (activeTab === 'ioc') renderIOC(content);
  }

  // ========================================================================
  // TAB 1: DASHBOARD
  // ========================================================================
  function renderDashboard(c) {
    var conns = [];
    var states = ['ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT', 'FIN_WAIT', 'LISTENING'];
    var protos = ['TCP', 'UDP', 'HTTP', 'TLS', 'DNS', 'ICMP'];
    for (var i = 0; i < 30; i++) {
      var proto = protos[Math.floor(Math.random() * protos.length)];
      conns.push({
        srcIP: '10.0.0.' + (Math.floor(Math.random() * 50) + 1),
        dstIP: [
          '93.184.216.34', '140.82.121.5', '172.217.14.99', '104.16.85.20',
          '185.199.108.153', '151.101.1.140', '13.107.42.14', '198.51.100.44'
        ][Math.floor(Math.random() * 8)],
        port: [80, 443, 53, 22, 8080, 3389, 445, 8443, 3306, 5432][Math.floor(Math.random() * 10)],
        protocol: proto,
        bytes: Math.floor(Math.random() * 500000) + 100,
        state: states[Math.floor(Math.random() * states.length)],
      });
    }

    var protoCounts = {};
    conns.forEach(function(cn) { protoCounts[cn.protocol] = (protoCounts[cn.protocol] || 0) + 1; });
    var total = conns.length;

    var topTalkers = {};
    conns.forEach(function(cn) {
      topTalkers[cn.srcIP] = topTalkers[cn.srcIP] || { packets: 0, bytes: 0, proto: {} };
      topTalkers[cn.srcIP].packets++;
      topTalkers[cn.srcIP].bytes += cn.bytes;
      topTalkers[cn.srcIP].proto[cn.protocol] = true;
    });
    var talkerArr = Object.entries(topTalkers).map(function(e) {
      return { ip: e[0], packets: e[1].packets, bytes: e[1].bytes, protocols: Object.keys(e[1].proto).join(', ') };
    }).sort(function(a, b) { return b.bytes - a.bytes; }).slice(0, 10);

    var bwMbps = (Math.random() * 80 + 20).toFixed(1);

    c.innerHTML =
      '<div class="ph-src-banner demo" style="margin:0 0 12px"><b>Demo data</b> - this dashboard shows randomly generated sample connections. A browser page cannot see your machine\'s live connections; import a .pcap in the Capture tab to analyze real traffic.</div>' +
      '<div class="ph-grid">' +
        '<div class="ph-stat"><div class="ph-stat-n">' + conns.length + '</div><div class="ph-stat-l">Active Connections</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + Object.keys(protoCounts).length + '</div><div class="ph-stat-l">Protocols Detected</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + fmtBytes(conns.reduce(function(s, cn) { return s + cn.bytes; }, 0)) + '</div><div class="ph-stat-l">Total Data Transfer</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + bwMbps + ' Mbps</div><div class="ph-stat-l">Bandwidth (simulated)</div></div>' +
      '</div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Protocol Distribution</div><div class="ph-panel-body">' +
        '<div class="ph-bar">' +
          Object.entries(protoCounts).map(function(e) {
            var pct = (e[1] / total * 100);
            var col = protoColor(e[0]);
            return '<div class="ph-bar-seg" style="width:' + pct + '%;background:' + col.text + '" title="' + esc(e[0]) + ': ' + e[1] + ' (' + pct.toFixed(0) + '%)">' + esc(e[0]) + '</div>';
          }).join('') +
        '</div>' +
        '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:8px">' +
          Object.entries(protoCounts).map(function(e) {
            var col = protoColor(e[0]);
            return '<span style="font-size:.72rem;color:var(--txt);display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;border-radius:2px;background:' + col.text + '"></span>' + esc(e[0]) + ': ' + e[1] + '</span>';
          }).join('') +
        '</div>' +
      '</div></div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Active Connections<span class="ph-demo-tag">Demo data</span></div><div class="ph-panel-body">' +
        '<div class="ph-scroll">' +
          '<table class="ph-table"><thead><tr><th>#</th><th>Source</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Bytes</th><th>State</th></tr></thead><tbody>' +
          conns.map(function(cn, idx) {
            var col = protoColor(cn.protocol);
            var stateColor = cn.state === 'ESTABLISHED' ? '#22c55e' : cn.state === 'SYN_SENT' ? '#eab308' : cn.state === 'CLOSE_WAIT' ? '#ef4444' : 'var(--mut)';
            return '<tr><td>' + (idx + 1) + '</td><td>' + esc(cn.srcIP) + '</td><td>' + esc(cn.dstIP) + '</td><td>' + cn.port + '</td>' +
              '<td><span class="ph-proto" style="background:' + col.bg + ';color:' + col.text + '">' + esc(cn.protocol) + '</span></td>' +
              '<td>' + fmtBytes(cn.bytes) + '</td>' +
              '<td style="color:' + stateColor + ';font-weight:600;font-size:.7rem">' + esc(cn.state) + '</td></tr>';
          }).join('') +
          '</tbody></table>' +
        '</div>' +
      '</div></div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Top Talkers<span class="ph-demo-tag">Demo data</span></div><div class="ph-panel-body">' +
        '<table class="ph-table"><thead><tr><th>#</th><th>IP Address</th><th>Packets</th><th>Bytes</th><th>Protocols</th></tr></thead><tbody>' +
        talkerArr.map(function(t, i) {
          return '<tr><td>' + (i + 1) + '</td><td style="font-family:var(--font-mono,monospace)">' + esc(t.ip) + '</td><td>' + t.packets + '</td><td>' + fmtBytes(t.bytes) + '</td><td>' + esc(t.protocols) + '</td></tr>';
        }).join('') +
        '</tbody></table>' +
      '</div></div>';
  }

  // ========================================================================
  // TAB 2: CAPTURE
  // ========================================================================
  function renderCapture(c) {
    c.innerHTML =
      '<div class="ph-file-input">' +
        '<button class="ph-btn" id="ph-demo-btn">Load Demo Capture (50 packets)</button>' +
        '<label class="ph-btn ghost" style="cursor:pointer" title="Classic libpcap format (.pcap). pcapng is not supported.">Import PCAP <input type="file" accept=".pcap,.cap,.dmp,.pcapng" id="ph-pcap-input" style="display:none"></label>' +
        '<span style="font-size:.72rem;color:var(--mut)" id="ph-pkt-count">' + (importMsg ? esc(importMsg) : packets.length ? packets.length + ' packets loaded' + (dataSource && dataSource.demo ? ' (demo data)' : '') : 'No packets loaded') + '</span>' +
        (packets.length ? '<button class="ph-btn ghost" id="ph-hosts-graph" title="' + (isImported() ? 'Hosts from the imported capture are tagged pcap-import' : 'Demo capture data is tagged simulated') + '">Send hosts to Security Graph</button>' : '') +
      '</div>' +
      (packets.length === 0 ?
        '<div class="ph-empty">No capture loaded. Click "Load Demo Capture" to explore sample network traffic, or import a classic .pcap file (parsed locally in your browser).</div>' :
        '<div style="margin-bottom:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
          '<input id="ph-filter" type="text" placeholder="Filter by IP, protocol, or keyword..." style="flex:1;min-width:200px;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--txt);font-size:.78rem;font-family:inherit">' +
          '<select id="ph-proto-filter" style="padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--txt);font-size:.76rem;font-family:inherit"><option value="">All Protocols</option><option>TCP</option><option>UDP</option><option>DNS</option><option>HTTP</option><option>TLS</option><option>ICMP</option><option>ARP</option></select>' +
        '</div>' +
        '<div class="ph-panel"><div class="ph-panel-h">Packet List (<span id="ph-shown-count">' + packets.length + '</span> / ' + packets.length + ' packets)</div><div class="ph-panel-body">' +
          '<div class="ph-scroll" style="max-height:360px">' +
            '<table class="ph-table"><thead><tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody id="ph-pkt-tbody">' +
            packets.map(function(pkt) {
              var col = protoColor(pkt.protocol);
              var sel = selectedPkt && selectedPkt.id === pkt.id;
              return '<tr data-pkt="' + pkt.id + '" class="' + (sel ? 'ph-row-sel' : '') + '" style="background:' + (sel ? 'rgba(6,182,212,.08)' : '') + '">' +
                '<td>' + pkt.id + '</td><td>' + fmtTime(pkt.ts) + '</td>' +
                '<td style="font-family:var(--font-mono,monospace);font-size:.72rem">' + esc(pkt.srcIP) + ':' + pkt.srcPort + '</td>' +
                '<td style="font-family:var(--font-mono,monospace);font-size:.72rem">' + esc(pkt.dstIP) + ':' + pkt.dstPort + '</td>' +
                '<td><span class="ph-proto" style="background:' + col.bg + ';color:' + col.text + '">' + esc(pkt.protocol) + '</span></td>' +
                '<td>' + pkt.length + '</td>' +
                '<td style="font-size:.72rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(pkt.info) + '</td></tr>';
            }).join('') +
            '</tbody></table>' +
          '</div>' +
        '</div></div>' +
        (selectedPkt ?
          '<div class="ph-panel"><div class="ph-panel-h">Hex Dump - Packet #' + selectedPkt.id + ' (' + esc(selectedPkt.protocol) + ')</div><div class="ph-panel-body">' +
            '<div class="ph-hex">' + esc(genHexDump(selectedPkt)) + '</div>' +
          '</div></div>' : ''
        )
      );

    var demoBtn = c.querySelector('#ph-demo-btn');
    if (demoBtn) demoBtn.onclick = loadDemo;
    var hostsGraphBtn = c.querySelector('#ph-hosts-graph');
    if (hostsGraphBtn) hostsGraphBtn.onclick = function() { phSendHosts(hostsGraphBtn, packets, isImported()); };

    var pcapInput = c.querySelector('#ph-pcap-input');
    if (pcapInput) pcapInput.onchange = function(e) {
      var file = e.target.files[0];
      if (!file) return;
      var cnt = c.querySelector('#ph-pkt-count');
      function fail(msg) {
        importMsg = file.name + ': ' + msg;
        if (cnt) { cnt.textContent = importMsg; cnt.style.color = '#ef4444'; }
      }
      if (file.size > 200 * 1048576) { fail('file is larger than 200 MB; split it first (e.g. editcap -c 20000).'); return; }
      if (cnt) cnt.textContent = 'Parsing ' + file.name + '...';
      var reader = new FileReader();
      reader.onerror = function() { fail('could not read the file.'); };
      reader.onload = function(ev) {
        var res;
        try { res = phParsePcap(ev.target.result); }
        catch (err) { fail(err.message); return; }
        if (!res.packets.length) { fail('no packets found in the capture.'); return; }
        packets = res.packets;
        dataSource = { demo: false, name: file.name, size: file.size, linktype: res.linktype, truncated: res.truncated, skipped: res.skipped };
        importMsg = '';
        selectedPkt = null; selectedFlow = null; selectedStream = null;
        render();
      };
      reader.readAsArrayBuffer(file);
    };

    var tbody = c.querySelector('#ph-pkt-tbody');
    if (tbody) tbody.onclick = function(e) {
      var row = e.target.closest('tr[data-pkt]');
      if (row) {
        var id = parseInt(row.dataset.pkt);
        selectedPkt = packets.find(function(p) { return p.id === id; }) || null;
        render();
      }
    };

    function applyFilter() {
      var q = (c.querySelector('#ph-filter')?.value || '').toLowerCase();
      var proto = c.querySelector('#ph-proto-filter')?.value || '';
      var rows = c.querySelectorAll('#ph-pkt-tbody tr[data-pkt]');
      var shown = 0;
      rows.forEach(function(row) {
        var text = row.textContent.toLowerCase();
        var pktProto = row.querySelector('.ph-proto')?.textContent || '';
        var matchQ = !q || text.indexOf(q) >= 0;
        var matchP = !proto || pktProto === proto;
        row.hidden = !(matchQ && matchP);
        if (!row.hidden) shown++;
      });
      var cnt = c.querySelector('#ph-shown-count');
      if (cnt) cnt.textContent = shown;
    }
    var filterInput = c.querySelector('#ph-filter');
    if (filterInput) filterInput.oninput = applyFilter;
    var protoFilter = c.querySelector('#ph-proto-filter');
    if (protoFilter) protoFilter.onchange = applyFilter;
  }

  // ========================================================================
  // TAB 3: PROTOCOL DISSECTOR
  // ========================================================================
  function renderDissector(c) {
    if (packets.length === 0) {
      c.innerHTML = '<div class="ph-empty">No capture loaded. Go to the Capture tab to load packets first.</div>';
      return;
    }

    var pkt = selectedPkt || packets[0];

    function layerHTML(name, color, fields) {
      return '<li class="ph-tree-node">' +
        '<div class="ph-tree-head" style="background:' + color + '20;border-left:3px solid ' + color + '" onclick="this.nextElementSibling.hidden=!this.nextElementSibling.hidden;this.querySelector(\'.ph-tree-arrow\').classList.toggle(\'open\')">' +
          '<span class="ph-tree-arrow open">&#9654;</span>' +
          '<span style="color:' + color + ';font-weight:700">' + esc(name) + '</span>' +
        '</div>' +
        '<div class="ph-tree-children">' +
          fields.map(function(f) {
            return '<div class="ph-tree-field"><span class="ph-tree-key">' + esc(f[0]) + '</span><span class="ph-tree-val">' + esc(f[1]) + '</span></div>';
          }).join('') +
        '</div>' +
      '</li>';
    }

    var layers = [];
    var real = !!pkt.imported;
    var isV6 = pkt.ipVersion === 6;
    var ethName = { 0x0800: 'IPv4', 0x86dd: 'IPv6', 0x0806: 'ARP' };
    var l3 = pkt.protocol === 'ARP' ? 'ARP' : (real && !pkt.ipVersion) ? '' : (isV6 ? 'IPv6' : 'IPv4');
    var l4name = pkt.ipProto === 58 ? 'ICMPv6' : pkt.protocol;
    var stackTail = (l3 ? l3 + (pkt.protocol !== 'ARP' && pkt.protocol !== l3 ? ':' + l4name : '') : pkt.protocol);
    var linkName = !real || pkt.linktype === 1 ? 'Ethernet' : pkt.linktype === 113 ? 'Linux cooked (SLL)' : pkt.linktype === 0 ? 'Loopback' : 'Raw IP';
    layers.push(layerHTML('Frame', '#64748b', [
      ['Frame Number', String(pkt.id)],
      ['Frame Length', pkt.length + ' bytes'],
    ].concat(real ? [['Captured Length', pkt.capLength + ' bytes'], ['Arrival Time', new Date(pkt.absTs * 1000).toISOString()]] : []).concat([
      ['Time Since First Frame', fmtTime(pkt.ts) + ' seconds'],
      ['Protocols in Frame', (linkName === 'Raw IP' ? '' : linkName.split(' ')[0] + ':') + stackTail],
    ])));

    if (!real || pkt.linktype === 1) {
      var et = real ? pkt.ethType : 0x0800;
      layers.push(layerHTML('Ethernet II', '#8b5cf6', [
        ['Source MAC', pkt.srcMAC],
        ['Destination MAC', pkt.dstMAC],
      ].concat(pkt.vlan != null ? [['802.1Q VLAN ID', String(pkt.vlan)]] : []).concat([
        ['Type', '0x' + (et || 0).toString(16).padStart(4, '0') + (ethName[et] ? ' (' + ethName[et] + ')' : '')],
      ])));
    } else if (real) {
      layers.push(layerHTML(linkName, '#8b5cf6', [['Link Type', String(pkt.linktype)], ['Protocol', '0x' + (pkt.ethType || 0).toString(16).padStart(4, '0') + (ethName[pkt.ethType] ? ' (' + ethName[pkt.ethType] + ')' : '')]]));
    }

    var ipProtoLabel = pkt.protocol === 'TCP' || pkt.protocol === 'HTTP' || pkt.protocol === 'TLS' ? '6 (TCP)' : pkt.protocol === 'UDP' || pkt.protocol === 'DNS' ? '17 (UDP)' : pkt.ipProto === 58 ? '58 (ICMPv6)' : pkt.protocol === 'ICMP' ? '1 (ICMP)' : pkt.ipProto != null ? String(pkt.ipProto) : 'Unknown';
    if (!real || pkt.ipVersion === 4) {
      layers.push(layerHTML('Internet Protocol v4', '#3b82f6', [
        ['Version', '4'],
        ['Header Length', real ? pkt.ipHeaderLen + ' bytes (' + (pkt.ipHeaderLen / 4) + ')' : '20 bytes (5)'],
        ['Total Length', (real ? pkt.ipTotalLen : pkt.length) + ' bytes'],
        ['TTL', String(pkt.ttl)],
        ['Protocol', ipProtoLabel],
        ['Source Address', pkt.srcIP],
        ['Destination Address', pkt.dstIP],
      ]));
    } else if (isV6) {
      layers.push(layerHTML('Internet Protocol v6', '#3b82f6', [
        ['Version', '6'],
        ['Hop Limit', String(pkt.ttl)],
        ['Next Header', ipProtoLabel],
        ['Source Address', pkt.srcIP],
        ['Destination Address', pkt.dstIP],
      ]));
    } else if (pkt.protocol === 'ARP') {
      layers.push(layerHTML('Address Resolution Protocol', '#3b82f6', [
        ['Summary', pkt.info],
        ['Sender IP', pkt.srcIP],
        ['Target IP', pkt.dstIP],
      ]));
    }

    if (pkt.protocol === 'TCP' || pkt.protocol === 'HTTP' || pkt.protocol === 'TLS' || (real && pkt.ipProto === 6 && pkt.window != null)) {
      layers.push(layerHTML('Transmission Control Protocol', '#06b6d4', [
        ['Source Port', String(pkt.srcPort)],
        ['Destination Port', String(pkt.dstPort)],
        ['Flags', pkt.flags || (real ? '(none)' : 'ACK')],
        ['Window Size', real ? String(pkt.window) : '65535'],
        ['Sequence Number', real ? String(pkt.seq) + ' (raw)' : pkt.info.match(/Seq=(\d+)/) ? pkt.info.match(/Seq=(\d+)/)[1] : '0 (relative)'],
      ].concat(real ? [['Acknowledgment Number', String(pkt.ack) + ' (raw)'], ['Checksum', pkt.checksum]] : [])));
    } else if (pkt.protocol === 'UDP' || pkt.protocol === 'DNS') {
      layers.push(layerHTML('User Datagram Protocol', '#22c55e', [
        ['Source Port', String(pkt.srcPort)],
        ['Destination Port', String(pkt.dstPort)],
        ['Length', real ? String(pkt.udpLength) + ' bytes' : String(pkt.length - 42) + ' bytes'],
        ['Checksum', real ? pkt.checksum : 'n/a (demo data)'],
      ]));
    } else if (pkt.protocol === 'ICMP') {
      layers.push(layerHTML(pkt.ipProto === 58 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol', '#f97316', real ? [
        ['Type', String(pkt.icmpType)],
        ['Code', String(pkt.icmpCode)],
        ['Checksum', pkt.checksum],
        ['Summary', pkt.info],
      ] : [
        ['Type', pkt.info.indexOf('request') >= 0 ? '8 (Echo Request)' : '0 (Echo Reply)'],
        ['Code', '0'],
        ['Identifier', pkt.info.match(/id=(0x[0-9a-f]+)/) ? pkt.info.match(/id=(0x[0-9a-f]+)/)[1] : '0x0000'],
        ['Sequence', pkt.info.match(/seq=(\d+)/) ? pkt.info.match(/seq=(\d+)/)[1] : '0'],
      ]));
    }

    if (real && (pkt.protocol === 'HTTP' || pkt.protocol === 'DNS' || pkt.protocol === 'TLS')) {
      // Imported packets: show only what was actually decoded from the bytes.
      var ph = pkt.payload || '';
      if (pkt.protocol === 'HTTP') {
        layers.push(layerHTML('Hypertext Transfer Protocol', '#f97316', [['First Line', pkt.info]]));
      } else if (pkt.protocol === 'DNS') {
        var dnsOff = pkt.ipProto === 6 ? 4 : 0; // DNS over TCP has a 2-byte length prefix
        layers.push(layerHTML('Domain Name System', '#eab308', [
          ['Transaction ID', '0x' + ph.slice(dnsOff, dnsOff + 4)],
          ['Type', pkt.info.indexOf('Response') === 0 ? 'Response' : 'Query'],
          ['Summary', pkt.info],
        ]));
      } else {
        var ctByte = parseInt(ph.slice(0, 2), 16);
        var ctNames = { 20: 'Change Cipher Spec (20)', 21: 'Alert (21)', 22: 'Handshake (22)', 23: 'Application Data (23)' };
        layers.push(layerHTML('Transport Layer Security', '#a855f7', [
          ['Content Type', ctNames[ctByte] || String(ctByte)],
          ['Record Version', '0x' + ph.slice(2, 6)],
          ['Record Length', String(parseInt(ph.slice(6, 10), 16) || 0) + ' bytes'],
          ['Summary', pkt.info],
        ]));
      }
    } else if (pkt.protocol === 'HTTP') {
      var isReq = pkt.info.indexOf('GET') >= 0 || pkt.info.indexOf('POST') >= 0;
      layers.push(layerHTML('Hypertext Transfer Protocol', '#f97316', isReq ? [
        ['Method', pkt.info.match(/(GET|POST|PUT|DELETE)/)?.[1] || 'GET'],
        ['Request URI', pkt.info.match(/(GET|POST|PUT|DELETE) ([^ ]+)/)?.[2] || '/'],
        ['Version', 'HTTP/1.1'],
        ['Host', pkt.dstIP],
      ] : [
        ['Status Code', pkt.info.match(/(\d{3})/)?.[1] || '200'],
        ['Status Phrase', pkt.info.match(/\d{3} ([^(]+)/)?.[1]?.trim() || 'OK'],
        ['Content-Type', pkt.info.match(/\(([^)]+)\)/)?.[1] || 'text/html'],
      ]));
    } else if (pkt.protocol === 'DNS') {
      var isQuery = pkt.info.indexOf('Query') >= 0;
      layers.push(layerHTML('Domain Name System', '#eab308', isQuery ? [
        ['Transaction ID', '0x' + (pkt.payload || '').slice(0, 4)],
        ['Type', 'Standard Query'],
        ['Query Name', pkt.info.replace('Query ', '').replace(/^[A-Z]+ /, '')],
        ['Query Type', pkt.info.match(/Query (A|AAAA|MX|TXT|CNAME|NS|SOA)/)?.[1] || 'A'],
      ] : [
        ['Transaction ID', '0x' + (pkt.payload || '').slice(0, 4)],
        ['Type', 'Standard Response'],
        ['Answers', pkt.info.replace('Response ', '')],
      ]));
    } else if (pkt.protocol === 'TLS') {
      var isHello = pkt.info.indexOf('Client Hello') >= 0;
      layers.push(layerHTML('Transport Layer Security', '#a855f7', isHello ? [
        ['Content Type', 'Handshake (22)'],
        ['Version', 'TLS 1.2 (0x0303)'],
        ['Handshake Type', 'Client Hello'],
        ['Server Name', pkt.info.replace('Client Hello - ', '')],
        ['Cipher Suites Length', '34'],
      ] : pkt.info.indexOf('Server Hello') >= 0 ? [
        ['Content Type', 'Handshake (22)'],
        ['Version', 'TLS 1.3 (0x0304)'],
        ['Handshake Type', 'Server Hello, Certificate, Server Hello Done'],
        ['Cipher Suite', 'TLS_AES_256_GCM_SHA384 (0x1302)'],
      ] : [
        ['Content Type', 'Application Data (23)'],
        ['Version', 'TLS 1.3'],
        ['Encrypted Length', String(pkt.length - 40) + ' bytes'],
      ]));
    }

    c.innerHTML =
      '<div style="display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap">' +
        '<span style="font-size:.78rem;color:var(--mut)">Select packet:</span>' +
        '<select id="ph-pkt-sel" style="padding:4px 8px;border:1px solid var(--line);border-radius:4px;background:var(--card);color:var(--txt);font-size:.76rem;font-family:inherit;max-width:500px">' +
          packets.map(function(p) {
            return '<option value="' + p.id + '"' + (p.id === pkt.id ? ' selected' : '') + '>#' + p.id + ' ' + esc(p.protocol) + ' ' + esc(p.srcIP) + ' -> ' + esc(p.dstIP) + ' ' + esc(p.info.slice(0, 50)) + '</option>';
          }).join('') +
        '</select>' +
      '</div>' +
      '<div class="ph-panel"><div class="ph-panel-h">Protocol Dissection - Packet #' + pkt.id + '</div><div class="ph-panel-body">' +
        '<ul class="ph-tree">' + layers.join('') + '</ul>' +
      '</div></div>' +
      '<div class="ph-panel"><div class="ph-panel-h">Raw Data</div><div class="ph-panel-body">' +
        '<div class="ph-hex">' + esc(genHexDump(pkt)) + '</div>' +
      '</div></div>';

    c.querySelector('#ph-pkt-sel').onchange = function(e) {
      var id = parseInt(e.target.value);
      selectedPkt = packets.find(function(p) { return p.id === id; }) || null;
      render();
    };
  }

  // ========================================================================
  // TAB 4: FLOW ANALYSIS
  // ========================================================================
  function renderFlows(c) {
    if (packets.length === 0) {
      c.innerHTML = '<div class="ph-empty">No capture loaded. Go to the Capture tab first.</div>';
      return;
    }

    var flows = {};
    packets.forEach(function(pkt) {
      if (pkt.protocol === 'ICMP') return;
      var key1 = pkt.srcIP + ':' + pkt.srcPort + '-' + pkt.dstIP + ':' + pkt.dstPort;
      var key2 = pkt.dstIP + ':' + pkt.dstPort + '-' + pkt.srcIP + ':' + pkt.srcPort;
      var fkey = flows[key1] ? key1 : flows[key2] ? key2 : key1;
      if (!flows[fkey]) flows[fkey] = { src: pkt.srcIP + ':' + pkt.srcPort, dst: pkt.dstIP + ':' + pkt.dstPort, packets: [], bytes: 0, startTs: pkt.ts, endTs: pkt.ts, protocol: pkt.protocol };
      flows[fkey].packets.push(pkt.id);
      flows[fkey].bytes += pkt.length;
      flows[fkey].endTs = Math.max(flows[fkey].endTs, pkt.ts);
    });

    var flowArr = Object.entries(flows).map(function(e, idx) {
      var f = e[1];
      var hasSyn = packets.some(function(p) { return f.packets.indexOf(p.id) >= 0 && p.flags && p.flags.indexOf('SYN') >= 0; });
      var hasFin = packets.some(function(p) { return f.packets.indexOf(p.id) >= 0 && p.flags && p.flags.indexOf('FIN') >= 0; });
      var state = hasFin ? 'CLOSED' : hasSyn ? 'ESTABLISHED' : 'ACTIVE';
      return { id: idx + 1, key: e[0], src: f.src, dst: f.dst, pkts: f.packets.length, bytes: f.bytes, duration: (f.endTs - f.startTs).toFixed(3), state: state, protocol: f.protocol, packetIds: f.packets };
    });

    c.innerHTML =
      '<div class="ph-panel"><div class="ph-panel-h">TCP/UDP Flows (' + flowArr.length + ' conversations)</div><div class="ph-panel-body">' +
        '<div class="ph-scroll">' +
          '<table class="ph-table"><thead><tr><th>Flow</th><th>Source</th><th></th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Duration</th><th>State</th></tr></thead><tbody>' +
          flowArr.map(function(f) {
            var sel = selectedFlow && selectedFlow.id === f.id;
            var stateColor = f.state === 'ESTABLISHED' ? '#22c55e' : f.state === 'CLOSED' ? '#ef4444' : '#eab308';
            var col = protoColor(f.protocol);
            return '<tr data-flow="' + f.id + '" style="cursor:pointer;' + (sel ? 'background:rgba(6,182,212,.08)' : '') + '">' +
              '<td>' + f.id + '</td>' +
              '<td style="font-family:var(--font-mono,monospace);font-size:.7rem">' + esc(f.src) + '</td>' +
              '<td class="ph-flow-dir">--></td>' +
              '<td style="font-family:var(--font-mono,monospace);font-size:.7rem">' + esc(f.dst) + '</td>' +
              '<td><span class="ph-proto" style="background:' + col.bg + ';color:' + col.text + '">' + esc(f.protocol) + '</span></td>' +
              '<td>' + f.pkts + '</td><td>' + fmtBytes(f.bytes) + '</td><td>' + f.duration + 's</td>' +
              '<td style="color:' + stateColor + ';font-weight:600;font-size:.7rem">' + esc(f.state) + '</td></tr>';
          }).join('') +
          '</tbody></table>' +
        '</div>' +
      '</div></div>' +

      (selectedFlow ?
        '<div class="ph-panel"><div class="ph-panel-h">Flow #' + selectedFlow.id + ' Packets (' + selectedFlow.packetIds.length + ')</div><div class="ph-panel-body">' +
          '<table class="ph-table"><thead><tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Length</th><th>Flags</th><th>Info</th></tr></thead><tbody>' +
          selectedFlow.packetIds.map(function(pid) {
            var p = packets.find(function(pk) { return pk.id === pid; });
            if (!p) return '';
            return '<tr><td>' + p.id + '</td><td>' + fmtTime(p.ts) + '</td><td style="font-family:var(--font-mono,monospace);font-size:.7rem">' + esc(p.srcIP) + ':' + p.srcPort + '</td><td style="font-family:var(--font-mono,monospace);font-size:.7rem">' + esc(p.dstIP) + ':' + p.dstPort + '</td><td>' + p.length + '</td><td>' + esc(p.flags || '-') + '</td><td style="font-size:.72rem">' + esc(p.info) + '</td></tr>';
          }).join('') +
          '</tbody></table>' +
        '</div></div>' : ''
      );

    var tbody = c.querySelector('tbody');
    if (tbody) tbody.onclick = function(e) {
      var row = e.target.closest('tr[data-flow]');
      if (row) {
        var id = parseInt(row.dataset.flow);
        selectedFlow = flowArr.find(function(f) { return f.id === id; }) || null;
        render();
      }
    };
  }

  // ========================================================================
  // TAB 5: ANOMALY DETECTION
  // ========================================================================
  function renderAnomaly(c) {
    var anomalies = SAMPLE_ANOMALIES;
    if (packets.length > 0) {
      var shellPkts = packets.filter(function(p) { return p.info.indexOf('reverse shell') >= 0 || p.info.indexOf('/bin/sh') >= 0; });
      var dnsTunnel = packets.filter(function(p) { return p.protocol === 'DNS' && p.info.length > 40 && (p.info.indexOf('TXT') >= 0 || p.info.indexOf('.c2.') >= 0); });
    }

    var sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    anomalies.forEach(function(a) { sevCounts[a.severity]++; });

    c.innerHTML =
      '<div class="ph-grid">' +
        '<div class="ph-stat"><div class="ph-stat-n" style="color:#ef4444">' + sevCounts.CRITICAL + '</div><div class="ph-stat-l">Critical</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n" style="color:#f97316">' + sevCounts.HIGH + '</div><div class="ph-stat-l">High</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n" style="color:#eab308">' + sevCounts.MEDIUM + '</div><div class="ph-stat-l">Medium</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n" style="color:#22c55e">' + sevCounts.LOW + '</div><div class="ph-stat-l">Low / Info</div></div>' +
      '</div>' +
      '<div class="ph-src-banner demo" style="margin:0 0 12px"><b>Demo data</b> - the findings below are built-in sample anomalies. They are not computed from ' + (isImported() ? 'your imported capture' : 'the loaded packets') + '.</div>' +
      '<div style="margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap">' + (packets.length === 0 ? '<button class="ph-btn" id="ph-run-anomaly">Load Demo Capture</button>' : '') +
        '<button class="ph-btn ghost" id="ph-anomaly-graph" title="Demo anomaly data is tagged simulated">Send ' + anomalies.length + ' anomalies to Security Graph</button></div>' +
      anomalies.map(function(a) {
        return '<div class="ph-alert">' +
          '<div class="ph-alert-head">' +
            '<span class="ph-badge ph-sev-' + a.severity + '">' + esc(a.severity) + '</span>' +
            '<span class="ph-alert-type">' + esc(a.type) + '</span>' +
          '</div>' +
          '<div class="ph-alert-desc">' + esc(a.description) + '</div>' +
          '<div class="ph-alert-ev">' + esc(a.evidence) + '</div>' +
          '<div class="ph-alert-rec">' + esc(a.recommendation) + '</div>' +
        '</div>';
      }).join('');

    var anomGraphBtn = c.querySelector('#ph-anomaly-graph');
    if (anomGraphBtn) anomGraphBtn.onclick = function() { phSendAnomalies(anomGraphBtn, anomalies); };
    var runBtn = c.querySelector('#ph-run-anomaly');
    if (runBtn) runBtn.onclick = function() {
      if (packets.length === 0) { loadDemo(); }
      render();
    };
  }

  // ========================================================================
  // TAB 6: DNS INSPECTOR
  // ========================================================================
  function renderDNS(c) {
    var dnsPkts = packets.filter(function(p) { return p.protocol === 'DNS'; });
    if (dnsPkts.length === 0 && packets.length === 0) {
      c.innerHTML = '<div class="ph-empty">No DNS packets found. Load a capture first.</div>';
      return;
    }
    if (dnsPkts.length === 0) {
      c.innerHTML = '<div class="ph-empty">No DNS packets in current capture.</div>';
      return;
    }

    var queries = dnsPkts.filter(function(p) { return p.info.indexOf('Query') >= 0; });
    var responses = dnsPkts.filter(function(p) { return p.info.indexOf('Response') >= 0; });

    var typeCounts = {};
    queries.forEach(function(q) {
      var type = q.info.match(/Query (A|AAAA|MX|TXT|CNAME|NS|SOA|PTR)/);
      var t = type ? type[1] : 'OTHER';
      typeCounts[t] = (typeCounts[t] || 0) + 1;
    });

    var domainCounts = {};
    queries.forEach(function(q) {
      var domain = q.info.replace(/Query [A-Z]+ /, '');
      domainCounts[domain] = (domainCounts[domain] || 0) + 1;
    });
    var topDomains = Object.entries(domainCounts).sort(function(a, b) { return b[1] - a[1]; }).slice(0, 10);

    var dgaCandidates = queries.filter(function(q) {
      var domain = q.info.replace(/Query [A-Z]+ /, '');
      var parts = domain.split('.');
      var label = parts[0];
      return label.length > 12 && entropy(label) > 3.5;
    });

    c.innerHTML =
      '<div class="ph-grid">' +
        '<div class="ph-stat"><div class="ph-stat-n">' + queries.length + '</div><div class="ph-stat-l">DNS Queries</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + responses.length + '</div><div class="ph-stat-l">DNS Responses</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + Object.keys(domainCounts).length + '</div><div class="ph-stat-l">Unique Domains</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n' + (dgaCandidates.length > 0 ? '" style="color:#ef4444' : '') + '">' + dgaCandidates.length + '</div><div class="ph-stat-l">DGA Suspects</div></div>' +
      '</div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Query Type Distribution</div><div class="ph-panel-body">' +
        '<div class="ph-bar">' +
          Object.entries(typeCounts).map(function(e) {
            var colors = { A: '#3b82f6', AAAA: '#8b5cf6', MX: '#22c55e', TXT: '#eab308', CNAME: '#06b6d4', NS: '#f97316', OTHER: '#64748b' };
            var pct = (e[1] / queries.length * 100);
            return '<div class="ph-bar-seg" style="width:' + pct + '%;background:' + (colors[e[0]] || '#64748b') + '">' + esc(e[0]) + ' ' + e[1] + '</div>';
          }).join('') +
        '</div>' +
      '</div></div>' +

      (dgaCandidates.length > 0 ?
        '<div class="ph-panel" style="border-color:#ef4444"><div class="ph-panel-h" style="color:#ef4444">[ALERT] Potential DGA Domains Detected</div><div class="ph-panel-body">' +
          '<table class="ph-table"><thead><tr><th>Query</th><th>Domain</th><th>Label Length</th><th>Entropy</th><th>Risk</th></tr></thead><tbody>' +
          dgaCandidates.map(function(q) {
            var domain = q.info.replace(/Query [A-Z]+ /, '');
            var label = domain.split('.')[0];
            var ent = entropy(label).toFixed(2);
            return '<tr><td>' + esc(q.info.match(/Query ([A-Z]+)/)?.[1] || 'A') + '</td><td style="font-family:var(--font-mono,monospace);font-size:.72rem;color:#ef4444">' + esc(domain) + '</td><td>' + label.length + '</td><td>' + ent + '</td><td><span class="ph-badge ph-sev-HIGH">HIGH</span></td></tr>';
          }).join('') +
          '</tbody></table>' +
        '</div></div>' : ''
      ) +

      '<div class="ph-panel"><div class="ph-panel-h">DNS Query Log</div><div class="ph-panel-body">' +
        '<div class="ph-scroll">' +
          '<table class="ph-table"><thead><tr><th>Time</th><th>Type</th><th>Query / Response</th><th>Server</th></tr></thead><tbody>' +
          dnsPkts.map(function(p) {
            var isQ = p.info.indexOf('Query') >= 0;
            return '<tr><td>' + fmtTime(p.ts) + '</td>' +
              '<td><span class="ph-chip">' + (isQ ? 'Q' : 'R') + '</span></td>' +
              '<td style="font-size:.74rem">' + esc(p.info) + '</td>' +
              '<td style="font-family:var(--font-mono,monospace);font-size:.72rem">' + (isQ ? esc(p.dstIP) : esc(p.srcIP)) + '</td></tr>';
          }).join('') +
          '</tbody></table>' +
        '</div>' +
      '</div></div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Top Queried Domains</div><div class="ph-panel-body">' +
        topDomains.map(function(d) {
          var maxCount = topDomains[0][1];
          var pct = (d[1] / maxCount * 100);
          return '<div class="ph-hist-row"><span class="ph-hist-label">' + esc(d[0]) + '</span><div style="flex:1"><div class="ph-hist-bar" style="width:' + pct + '%"></div></div><span class="ph-hist-n">' + d[1] + '</span></div>';
        }).join('') +
      '</div></div>';
  }

  // ========================================================================
  // TAB 7: TLS/SSL
  // ========================================================================
  function renderTLS(c) {
    var tlsPkts = packets.filter(function(p) { return p.protocol === 'TLS'; });

    c.innerHTML =
      '<div class="ph-src-banner demo" style="margin:0 0 12px"><b>Demo data</b> - only the TLS packet count comes from the loaded capture. The certificates below are built-in samples; the cipher suite and JA3 tables are reference lists.</div>' +
      '<div class="ph-grid">' +
        '<div class="ph-stat"><div class="ph-stat-n">' + tlsPkts.length + '</div><div class="ph-stat-l">TLS Packets</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + SAMPLE_CERTS.length + '</div><div class="ph-stat-l">Sample Certificates</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + JA3_DB.length + '</div><div class="ph-stat-l">Reference JA3 Hashes</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + SAMPLE_CERTS.filter(function(cert) { return cert.keySize < 1024 || cert.sigAlg.indexOf('MD5') >= 0 || cert.sigAlg.indexOf('SHA1') >= 0; }).length + '</div><div class="ph-stat-l" style="color:#ef4444">Weak (sample certs)</div></div>' +
      '</div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Certificate Chain Analysis<span class="ph-demo-tag">Demo data</span></div><div class="ph-panel-body">' +
        '<div class="ph-scroll">' +
          '<table class="ph-table"><thead><tr><th>Subject</th><th>Issuer</th><th>Valid From</th><th>Valid To</th><th>Key Size</th><th>Signature</th><th>Status</th></tr></thead><tbody>' +
          SAMPLE_CERTS.map(function(cert) {
            var now = new Date();
            var expired = new Date(cert.validTo) < now;
            var weak = cert.keySize < 1024 || cert.sigAlg.indexOf('MD5') >= 0 || cert.sigAlg.indexOf('SHA1') >= 0;
            var selfSigned = cert.subject === cert.issuer || cert.issuer.indexOf(cert.subject.replace('CN=', '')) >= 0;
            var status = expired ? 'EXPIRED' : weak ? 'WEAK' : selfSigned ? 'SELF-SIGNED' : 'VALID';
            var statusColor = status === 'VALID' ? '#22c55e' : status === 'WEAK' || status === 'SELF-SIGNED' ? '#eab308' : '#ef4444';
            return '<tr><td style="font-family:var(--font-mono,monospace);font-size:.72rem">' + esc(cert.subject) + '</td>' +
              '<td style="font-size:.72rem">' + esc(cert.issuer) + '</td>' +
              '<td>' + esc(cert.validFrom) + '</td><td>' + esc(cert.validTo) + '</td>' +
              '<td>' + cert.keySize + '</td><td style="font-size:.72rem">' + esc(cert.sigAlg) + '</td>' +
              '<td style="color:' + statusColor + ';font-weight:700;font-size:.7rem">' + status + '</td></tr>';
          }).join('') +
          '</tbody></table>' +
        '</div>' +
      '</div></div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Cipher Suite Reference</div><div class="ph-panel-body">' +
        '<table class="ph-table"><thead><tr><th>Cipher Suite</th><th>Protocol</th><th>Key Exchange</th><th>Encryption</th><th>Rating</th></tr></thead><tbody>' +
          '<tr><td>TLS_AES_256_GCM_SHA384</td><td>TLS 1.3</td><td>ECDHE</td><td>AES-256-GCM</td><td style="color:#22c55e;font-weight:700">STRONG</td></tr>' +
          '<tr><td>TLS_CHACHA20_POLY1305_SHA256</td><td>TLS 1.3</td><td>ECDHE</td><td>ChaCha20-Poly1305</td><td style="color:#22c55e;font-weight:700">STRONG</td></tr>' +
          '<tr><td>TLS_AES_128_GCM_SHA256</td><td>TLS 1.3</td><td>ECDHE</td><td>AES-128-GCM</td><td style="color:#22c55e;font-weight:700">STRONG</td></tr>' +
          '<tr><td>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</td><td>TLS 1.2</td><td>ECDHE-RSA</td><td>AES-256-GCM</td><td style="color:#22c55e;font-weight:700">STRONG</td></tr>' +
          '<tr><td>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256</td><td>TLS 1.2</td><td>ECDHE-RSA</td><td>AES-128-CBC</td><td style="color:#eab308;font-weight:700">MODERATE</td></tr>' +
          '<tr><td>TLS_RSA_WITH_AES_128_CBC_SHA</td><td>TLS 1.2</td><td>RSA</td><td>AES-128-CBC</td><td style="color:#eab308;font-weight:700">WEAK PFS</td></tr>' +
          '<tr><td>TLS_RSA_WITH_RC4_128_SHA</td><td>TLS 1.0</td><td>RSA</td><td>RC4-128</td><td style="color:#ef4444;font-weight:700">INSECURE</td></tr>' +
          '<tr><td>TLS_RSA_WITH_3DES_EDE_CBC_SHA</td><td>TLS 1.0</td><td>RSA</td><td>3DES-CBC</td><td style="color:#ef4444;font-weight:700">INSECURE</td></tr>' +
        '</tbody></table>' +
      '</div></div>' +

      '<div class="ph-panel"><div class="ph-panel-h">JA3 Fingerprint Database</div><div class="ph-panel-body">' +
        '<table class="ph-table"><thead><tr><th>JA3 Hash</th><th>Identified Client</th><th>Confidence</th></tr></thead><tbody>' +
        JA3_DB.map(function(j) {
          var confColor = j.confidence === 'Critical' ? '#ef4444' : j.confidence === 'High' ? '#22c55e' : '#eab308';
          return '<tr><td style="font-family:var(--font-mono,monospace);font-size:.7rem">' + esc(j.hash) + '</td>' +
            '<td' + (j.confidence === 'Critical' ? ' style="color:#ef4444;font-weight:700"' : '') + '>' + esc(j.client) + '</td>' +
            '<td style="color:' + confColor + ';font-weight:600">' + esc(j.confidence) + '</td></tr>';
        }).join('') +
        '</tbody></table>' +
      '</div></div>';
  }

  // ========================================================================
  // TAB 8: STATISTICS
  // ========================================================================
  function renderStats(c) {
    if (packets.length === 0) {
      c.innerHTML = '<div class="ph-empty">No capture loaded. Go to the Capture tab first.</div>';
      return;
    }

    var sizeBuckets = [0, 0, 0, 0, 0, 0, 0];
    var sizeLabels = ['0-64', '64-128', '128-256', '256-512', '512-1024', '1024-1500', '1500+'];
    packets.forEach(function(p) {
      if (p.length < 64) sizeBuckets[0]++;
      else if (p.length < 128) sizeBuckets[1]++;
      else if (p.length < 256) sizeBuckets[2]++;
      else if (p.length < 512) sizeBuckets[3]++;
      else if (p.length < 1024) sizeBuckets[4]++;
      else if (p.length < 1500) sizeBuckets[5]++;
      else sizeBuckets[6]++;
    });
    var maxBucket = Math.max.apply(null, sizeBuckets) || 1;

    var protoCounts = {};
    var protoBytes = {};
    packets.forEach(function(p) {
      protoCounts[p.protocol] = (protoCounts[p.protocol] || 0) + 1;
      protoBytes[p.protocol] = (protoBytes[p.protocol] || 0) + p.length;
    });

    var endpoints = {};
    packets.forEach(function(p) {
      if (!endpoints[p.srcIP]) endpoints[p.srcIP] = { sent: 0, recv: 0, bytesSent: 0, bytesRecv: 0 };
      if (!endpoints[p.dstIP]) endpoints[p.dstIP] = { sent: 0, recv: 0, bytesSent: 0, bytesRecv: 0 };
      endpoints[p.srcIP].sent++;
      endpoints[p.srcIP].bytesSent += p.length;
      endpoints[p.dstIP].recv++;
      endpoints[p.dstIP].bytesRecv += p.length;
    });
    var endpointArr = Object.entries(endpoints).map(function(e) {
      return { ip: e[0], sent: e[1].sent, recv: e[1].recv, bytesSent: e[1].bytesSent, bytesRecv: e[1].bytesRecv };
    }).sort(function(a, b) { return (b.sent + b.recv) - (a.sent + a.recv); });

    var ips = [];
    var ipSet = {};
    packets.forEach(function(p) { ipSet[p.srcIP] = true; ipSet[p.dstIP] = true; });
    ips = Object.keys(ipSet).sort().slice(0, 8);
    var matrix = {};
    packets.forEach(function(p) {
      var key = p.srcIP + '|' + p.dstIP;
      matrix[key] = (matrix[key] || 0) + p.length;
    });

    c.innerHTML =
      '<div class="ph-panel"><div class="ph-panel-h">Packet Size Distribution</div><div class="ph-panel-body">' +
        sizeLabels.map(function(label, i) {
          var pct = (sizeBuckets[i] / maxBucket * 100);
          return '<div class="ph-hist-row"><span class="ph-hist-label">' + label + ' B</span><div style="flex:1"><div class="ph-hist-bar" style="width:' + pct + '%"></div></div><span class="ph-hist-n">' + sizeBuckets[i] + '</span></div>';
        }).join('') +
      '</div></div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Protocol Hierarchy</div><div class="ph-panel-body">' +
        '<table class="ph-table"><thead><tr><th>Protocol</th><th>Packets</th><th>Bytes</th><th>% Packets</th><th>% Bytes</th></tr></thead><tbody>' +
        Object.entries(protoCounts).sort(function(a, b) { return b[1] - a[1]; }).map(function(e) {
          var totalPkts = packets.length;
          var totalBytes = packets.reduce(function(s, p) { return s + p.length; }, 0);
          var col = protoColor(e[0]);
          return '<tr><td><span class="ph-proto" style="background:' + col.bg + ';color:' + col.text + '">' + esc(e[0]) + '</span></td>' +
            '<td>' + e[1] + '</td><td>' + fmtBytes(protoBytes[e[0]] || 0) + '</td>' +
            '<td>' + (e[1] / totalPkts * 100).toFixed(1) + '%</td>' +
            '<td>' + ((protoBytes[e[0]] || 0) / totalBytes * 100).toFixed(1) + '%</td></tr>';
        }).join('') +
        '</tbody></table>' +
      '</div></div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Endpoints</div><div class="ph-panel-body">' +
        '<div class="ph-scroll">' +
          '<table class="ph-table"><thead><tr><th>IP Address</th><th>Packets Sent</th><th>Packets Recv</th><th>Bytes Sent</th><th>Bytes Recv</th></tr></thead><tbody>' +
          endpointArr.map(function(ep) {
            return '<tr><td style="font-family:var(--font-mono,monospace)">' + esc(ep.ip) + '</td>' +
              '<td>' + ep.sent + '</td><td>' + ep.recv + '</td>' +
              '<td>' + fmtBytes(ep.bytesSent) + '</td><td>' + fmtBytes(ep.bytesRecv) + '</td></tr>';
          }).join('') +
          '</tbody></table>' +
        '</div>' +
      '</div></div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Conversation Matrix (bytes transferred)</div><div class="ph-panel-body">' +
        '<div style="overflow-x:auto">' +
          '<table class="ph-table" style="font-size:.62rem"><thead><tr><th></th>' +
          ips.map(function(ip) { return '<th style="writing-mode:vertical-lr;transform:rotate(180deg);padding:4px;max-width:24px">' + esc(ip) + '</th>'; }).join('') +
          '</tr></thead><tbody>' +
          ips.map(function(srcIP) {
            return '<tr><td style="font-family:var(--font-mono,monospace);font-weight:600;white-space:nowrap">' + esc(srcIP) + '</td>' +
              ips.map(function(dstIP) {
                var val = matrix[srcIP + '|' + dstIP] || 0;
                var maxVal = Math.max.apply(null, Object.values(matrix)) || 1;
                var intensity = val > 0 ? Math.max(0.08, val / maxVal * 0.6) : 0;
                return '<td style="text-align:center;background:rgba(6,182,212,' + intensity + ');padding:4px;border-radius:2px">' + (val > 0 ? fmtBytes(val) : '-') + '</td>';
              }).join('') +
            '</tr>';
          }).join('') +
          '</tbody></table>' +
        '</div>' +
      '</div></div>';
  }

  // ========================================================================
  // TAB 9: FOLLOW STREAM
  // ========================================================================
  function renderStream(c) {
    if (packets.length === 0) {
      c.innerHTML = '<div class="ph-empty">No capture loaded. Go to the Capture tab first.</div>';
      return;
    }
    var streams = phBuildStreams(packets).sort(function(a, b) { return b.bytes - a.bytes; });
    var sel = selectedStream ? (streams.find(function(s) { return s.key === selectedStream; }) || null) : null;

    var listRows = streams.map(function(s, i) {
      var on = sel && sel.key === s.key;
      var dur = (s.endTs - s.startTs).toFixed(3);
      return '<tr data-stream="' + esc(s.key) + '" style="cursor:pointer;' + (on ? 'background:rgba(6,182,212,.08)' : '') + '">' +
        '<td>' + (i + 1) + '</td>' +
        '<td style="font-family:var(--font-mono,monospace);font-size:.7rem">' + esc(s.epA) + '</td>' +
        '<td class="ph-flow-dir">&lt;--&gt;</td>' +
        '<td style="font-family:var(--font-mono,monospace);font-size:.7rem">' + esc(s.epB) + '</td>' +
        '<td>' + esc(s.transport) + '</td>' +
        '<td style="font-size:.7rem">' + esc(s.protocols.join(', ')) + '</td>' +
        '<td>' + s.packets.length + '</td>' +
        '<td>' + fmtBytes(s.bytes) + '</td>' +
        '<td>' + dur + 's</td></tr>';
    }).join('');

    var detail = '';
    if (sel) {
      var ordered = sel.packets.slice().sort(function(a, b) { return a.ts - b.ts; });
      var tbl = ordered.map(function(p) {
        var isCS = (p.srcIP + ':' + p.srcPort) === sel.client;
        return '<tr><td>' + p.id + '</td><td>' + fmtTime(p.ts) + '</td>' +
          '<td class="' + (isCS ? 'ph-dir-cs' : 'ph-dir-sc') + '" style="font-weight:700;font-size:.68rem">' + (isCS ? 'C-&gt;S' : 'S-&gt;C') + '</td>' +
          '<td style="font-family:var(--font-mono,monospace);font-size:.7rem">' + esc(p.srcIP) + ':' + p.srcPort + '</td>' +
          '<td style="font-family:var(--font-mono,monospace);font-size:.7rem">' + esc(p.dstIP) + ':' + p.dstPort + '</td>' +
          '<td>' + esc(p.protocol) + '</td><td>' + p.length + '</td>' +
          '<td style="font-size:.72rem">' + esc(p.info) + '</td></tr>';
      }).join('');
      var lines = ordered.map(function(p) {
        var isCS = (p.srcIP + ':' + p.srcPort) === sel.client;
        var arrow = isCS ? 'client -&gt; server' : 'server -&gt; client';
        var cls = isCS ? 'ph-dir-cs' : 'ph-dir-sc';
        var body = esc(p.info) + (p.payload ? '  [' + esc(p.payload.slice(0, 48)) + (p.payload.length > 48 ? '...' : '') + ']' : '');
        return '<div class="ph-stream-line ' + cls + '"><span class="ph-stream-dir">' + arrow + '</span>' +
          '<span class="ph-stream-meta">#' + p.id + ' t=' + fmtTime(p.ts) + ' ' + esc(p.protocol) + ' ' + p.length + 'B</span>' +
          '<div class="ph-stream-body">' + body + '</div></div>';
      }).join('');
      detail =
        '<div class="ph-panel"><div class="ph-panel-h">Stream Packets - ' + esc(sel.client) + ' (client) &lt;--&gt; ' + esc(sel.server) + ' (server)</div><div class="ph-panel-body">' +
          '<div class="ph-scroll"><table class="ph-table"><thead><tr><th>#</th><th>Time</th><th>Dir</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody>' + tbl + '</tbody></table></div>' +
        '</div></div>' +
        '<div class="ph-panel"><div class="ph-panel-h">Reassembled Conversation (' + ordered.length + ' segments)</div><div class="ph-panel-body">' +
          '<div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:10px;font-size:.7rem">' +
            '<span class="ph-dir-cs" style="font-weight:700">client -&gt; server</span>' +
            '<span class="ph-dir-sc" style="font-weight:700">server -&gt; client</span>' +
          '</div>' +
          '<div class="ph-stream-view">' + lines + '</div>' +
        '</div></div>';
    }

    c.innerHTML =
      '<div class="ph-panel"><div class="ph-panel-h">Conversations (' + streams.length + ' streams) - select one to follow</div><div class="ph-panel-body">' +
        '<div class="ph-scroll"><table class="ph-table"><thead><tr><th>#</th><th>Endpoint A</th><th></th><th>Endpoint B</th><th>Transport</th><th>Protocols</th><th>Packets</th><th>Bytes</th><th>Duration</th></tr></thead><tbody>' + listRows + '</tbody></table></div>' +
      '</div></div>' + detail;

    var tb = c.querySelector('tbody');
    if (tb) tb.onclick = function(e) {
      var row = e.target.closest('tr[data-stream]');
      if (row) { selectedStream = row.dataset.stream; render(); }
    };
  }

  // ========================================================================
  // TAB 10: TRAFFIC STATS
  // ========================================================================
  function renderTrafficStats(c) {
    if (packets.length === 0) {
      c.innerHTML = '<div class="ph-empty">No capture loaded. Go to the Capture tab first.</div>';
      return;
    }
    var totalPkts = packets.length;
    var totalBytes = packets.reduce(function(s, p) { return s + (p.length || 0); }, 0) || 1;

    // (a) Protocol hierarchy
    var pc = {}, pb = {};
    packets.forEach(function(p) {
      pc[p.protocol] = (pc[p.protocol] || 0) + 1;
      pb[p.protocol] = (pb[p.protocol] || 0) + (p.length || 0);
    });
    var protoRows = Object.keys(pc).sort(function(a, b) { return pb[b] - pb[a]; }).map(function(k) {
      var col = protoColor(k);
      var bytePct = pb[k] / totalBytes * 100;
      var pktPct = pc[k] / totalPkts * 100;
      return '<tr><td><span class="ph-proto" style="background:' + col.bg + ';color:' + col.text + '">' + esc(k) + '</span></td>' +
        '<td>' + pc[k] + '</td><td>' + fmtBytes(pb[k]) + '</td>' +
        '<td>' + pktPct.toFixed(1) + '%</td>' +
        '<td style="min-width:150px">' + phMeter(bytePct, col.text) + '<span style="font-size:.66rem;color:var(--mut)">' + bytePct.toFixed(1) + '%</span></td></tr>';
    }).join('');

    // (b) Top talkers (per IP, sent + received)
    var tk = {};
    packets.forEach(function(p) {
      [p.srcIP, p.dstIP].forEach(function(ip) {
        var t = tk[ip] || (tk[ip] = { packets: 0, bytes: 0 });
        t.packets++; t.bytes += (p.length || 0);
      });
    });
    var talkers = Object.keys(tk).map(function(ip) { return { ip: ip, packets: tk[ip].packets, bytes: tk[ip].bytes }; })
      .sort(function(a, b) { return b.bytes - a.bytes; });
    var maxTalk = talkers.reduce(function(m, t) { return Math.max(m, t.bytes); }, 1);
    var talkerRows = talkers.map(function(t, i) {
      return '<tr><td>' + (i + 1) + '</td><td style="font-family:var(--font-mono,monospace)">' + esc(t.ip) + (phIsPrivate(t.ip) ? ' <span class="ph-chip">internal</span>' : '') + '</td>' +
        '<td>' + t.packets + '</td><td>' + fmtBytes(t.bytes) + '</td>' +
        '<td style="min-width:170px">' + phMeter(t.bytes / maxTalk * 100) + '</td></tr>';
    }).join('');

    // (c) Conversations (per 5-tuple)
    var streams = phBuildStreams(packets).sort(function(a, b) { return b.bytes - a.bytes; });
    var maxConv = streams.reduce(function(m, s) { return Math.max(m, s.bytes); }, 1);
    var convRows = streams.map(function(s) {
      return '<tr><td style="font-family:var(--font-mono,monospace);font-size:.7rem">' + esc(s.epA) + ' &lt;--&gt; ' + esc(s.epB) + '</td>' +
        '<td style="font-size:.7rem">' + esc(s.protocols.join(', ')) + '</td>' +
        '<td>' + s.packets.length + '</td>' +
        '<td>' + fmtBytes(s.bytes) + '</td>' +
        '<td>' + (s.endTs - s.startTs).toFixed(3) + 's</td>' +
        '<td style="min-width:150px">' + phMeter(s.bytes / maxConv * 100) + '</td></tr>';
    }).join('');

    c.innerHTML =
      '<div class="ph-grid">' +
        '<div class="ph-stat"><div class="ph-stat-n">' + totalPkts + '</div><div class="ph-stat-l">Packets</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + fmtBytes(totalBytes) + '</div><div class="ph-stat-l">Total Bytes</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + Object.keys(pc).length + '</div><div class="ph-stat-l">Protocols</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + streams.length + '</div><div class="ph-stat-l">Conversations</div></div>' +
      '</div>' +
      '<div class="ph-panel"><div class="ph-panel-h">Protocol Hierarchy</div><div class="ph-panel-body">' +
        '<table class="ph-table"><thead><tr><th>Protocol</th><th>Packets</th><th>Bytes</th><th>% Packets</th><th>% of Traffic (bytes)</th></tr></thead><tbody>' + protoRows + '</tbody></table>' +
      '</div></div>' +
      '<div class="ph-panel"><div class="ph-panel-h">Top Talkers</div><div class="ph-panel-body"><div class="ph-scroll">' +
        '<table class="ph-table"><thead><tr><th>#</th><th>IP Address</th><th>Packets (tx+rx)</th><th>Bytes</th><th>Share</th></tr></thead><tbody>' + talkerRows + '</tbody></table>' +
      '</div></div></div>' +
      '<div class="ph-panel"><div class="ph-panel-h">Conversations (per 5-tuple)</div><div class="ph-panel-body"><div class="ph-scroll">' +
        '<table class="ph-table"><thead><tr><th>Endpoints</th><th>Protocols</th><th>Packets</th><th>Bytes</th><th>Duration</th><th>Share</th></tr></thead><tbody>' + convRows + '</tbody></table>' +
      '</div></div></div>';
  }

  // ========================================================================
  // TAB 11: DISPLAY FILTER
  // ========================================================================
  function renderFilter(c) {
    if (packets.length === 0) {
      c.innerHTML = '<div class="ph-empty">No capture loaded. Go to the Capture tab first.</div>';
      return;
    }
    var rowsHTML = packets.map(function(pkt) {
      var col = protoColor(pkt.protocol);
      return '<tr data-fpkt="' + pkt.id + '">' +
        '<td>' + pkt.id + '</td><td>' + fmtTime(pkt.ts) + '</td>' +
        '<td style="font-family:var(--font-mono,monospace);font-size:.72rem">' + esc(pkt.srcIP) + ':' + pkt.srcPort + '</td>' +
        '<td style="font-family:var(--font-mono,monospace);font-size:.72rem">' + esc(pkt.dstIP) + ':' + pkt.dstPort + '</td>' +
        '<td><span class="ph-proto" style="background:' + col.bg + ';color:' + col.text + '">' + esc(pkt.protocol) + '</span></td>' +
        '<td>' + pkt.length + '</td>' +
        '<td style="font-size:.72rem;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(pkt.info) + '</td></tr>';
    }).join('');

    c.innerHTML =
      '<div class="ph-panel"><div class="ph-panel-h">Display Filter</div><div class="ph-panel-body">' +
        '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
          '<input id="ph-dfilter" type="text" spellcheck="false" placeholder="e.g. ip.addr == 10.0.0.5 &amp;&amp; protocol == DNS" value="' + esc(filterExpr) + '" style="flex:1;min-width:260px;padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--txt);font-size:.78rem;font-family:var(--font-mono,monospace)">' +
          '<button class="ph-btn ghost" id="ph-dfilter-clear">Clear</button>' +
          '<span id="ph-dfilter-count" style="font-size:.72rem;color:var(--mut)"></span>' +
        '</div>' +
        '<div id="ph-dfilter-hint" class="ph-hint"></div>' +
        '<div style="font-size:.68rem;color:var(--mut);margin-top:4px">Fields: ip.addr, ip.src, ip.dst, tcp.port, udp.port, port, protocol - operators == != - combine with &amp;&amp; or and - bare protocol name e.g. DNS</div>' +
      '</div></div>' +
      '<div class="ph-panel"><div class="ph-panel-h">Filtered Packets</div><div class="ph-panel-body"><div class="ph-scroll" style="max-height:420px">' +
        '<table class="ph-table"><thead><tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody id="ph-dfilter-body">' + rowsHTML + '</tbody></table>' +
      '</div></div></div>';

    var input = c.querySelector('#ph-dfilter');
    var hint = c.querySelector('#ph-dfilter-hint');
    var countEl = c.querySelector('#ph-dfilter-count');
    var rows = c.querySelectorAll('#ph-dfilter-body tr[data-fpkt]');

    function apply() {
      filterExpr = input.value;
      var res = phParseFilter(filterExpr);
      if (!res.ok) {
        hint.textContent = res.error;
        countEl.textContent = '';
        return;
      }
      hint.textContent = '';
      var shown = 0;
      rows.forEach(function(row) {
        var id = parseInt(row.dataset.fpkt, 10);
        var p = packets.find(function(pk) { return pk.id === id; });
        var ok = p ? res.fn(p) : false;
        row.hidden = !ok;
        if (ok) shown++;
      });
      countEl.textContent = 'showing ' + shown + ' of ' + packets.length + ' packets';
    }
    if (input) input.oninput = apply;
    var clr = c.querySelector('#ph-dfilter-clear');
    if (clr) clr.onclick = function() { input.value = ''; filterExpr = ''; apply(); input.focus(); };
    apply();
  }

  // ========================================================================
  // TAB 12: IOC EXPORT
  // ========================================================================
  function renderIOC(c) {
    if (packets.length === 0) {
      c.innerHTML = '<div class="ph-empty">No capture loaded. Go to the Capture tab first.</div>';
      return;
    }
    var ipSet = {}, domSet = {};
    packets.forEach(function(p) {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(p.srcIP)) ipSet[p.srcIP] = true;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(p.dstIP)) ipSet[p.dstIP] = true;
      var matches = (p.info || '').match(PH_DOMAIN_RE) || [];
      matches.forEach(function(d) {
        d = d.toLowerCase();
        if (/^\d+(\.\d+)+$/.test(d)) return; // skip IP-like tokens
        domSet[d] = true;
      });
    });
    var ips = Object.keys(ipSet).sort();
    var domains = Object.keys(domSet).sort();

    var imported = isImported();
    var iocData = { source: 'PHANTOM', generated: new Date().toISOString(), ips: ips, domains: domains };
    if (imported) iocData.capture = dataSource.name; else iocData.simulated = true;

    var graphBtn = '<button class="ph-btn ghost" id="ph-ioc-graph" title="Sends extracted IOCs to the Security Graph tool (tagged ' + (imported ? 'pcap-import' : 'simulated') + ')">Send to Security Graph</button>';

    c.innerHTML =
      '<div class="ph-grid">' +
        '<div class="ph-stat"><div class="ph-stat-n">' + ips.length + '</div><div class="ph-stat-l">Unique IPs</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + domains.length + '</div><div class="ph-stat-l">Domains / DNS Names</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + (ips.length + domains.length) + '</div><div class="ph-stat-l">Total Indicators</div></div>' +
      '</div>' +
      '<div style="margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap">' +
        '<button class="ph-btn" id="ph-ioc-json">Export JSON</button>' +
        '<button class="ph-btn" id="ph-ioc-csv">Export CSV</button>' +
        graphBtn +
      '</div>' +
      '<div class="ph-panel"><div class="ph-panel-h">IP Indicators (' + ips.length + ')</div><div class="ph-panel-body"><div class="ph-scroll" style="max-height:300px">' +
        '<table class="ph-table"><thead><tr><th>#</th><th>IP Address</th><th>Scope</th></tr></thead><tbody>' +
        ips.map(function(ip, i) {
          return '<tr><td>' + (i + 1) + '</td><td style="font-family:var(--font-mono,monospace)">' + esc(ip) + '</td><td>' + (phIsPrivate(ip) ? '<span class="ph-chip">internal</span>' : 'external') + '</td></tr>';
        }).join('') +
        '</tbody></table>' +
      '</div></div></div>' +
      '<div class="ph-panel"><div class="ph-panel-h">Domain Indicators (' + domains.length + ')</div><div class="ph-panel-body"><div class="ph-scroll" style="max-height:300px">' +
        (domains.length ?
          '<table class="ph-table"><thead><tr><th>#</th><th>Domain / DNS Name</th></tr></thead><tbody>' +
          domains.map(function(d, i) {
            return '<tr><td>' + (i + 1) + '</td><td style="font-family:var(--font-mono,monospace);font-size:.74rem">' + esc(d) + '</td></tr>';
          }).join('') +
          '</tbody></table>' :
          '<div class="ph-empty">No domains extracted from capture.</div>') +
      '</div></div></div>';

    var jsonBtn = c.querySelector('#ph-ioc-json');
    if (jsonBtn) jsonBtn.onclick = function() {
      phDownload('phantom-iocs.json', JSON.stringify(iocData, null, 2), 'application/json');
    };
    var csvBtn = c.querySelector('#ph-ioc-csv');
    if (csvBtn) csvBtn.onclick = function() {
      var lines = ['type,indicator'];
      ips.forEach(function(ip) { lines.push('ip,' + ip); });
      domains.forEach(function(d) { lines.push('domain,' + d); });
      phDownload('phantom-iocs.csv', lines.join('\n'), 'text/csv');
    };
    var gbtn = c.querySelector('#ph-ioc-graph');
    if (gbtn) gbtn.onclick = function() {
      // Uses the same dynamic-import graph-bridge pattern as phSendHosts/phSendAnomalies.
      phSendGraph(gbtn, function(gb) {
        var items = ips.map(function(ip) { return phHostItem(ip, { source: 'IOC export' }, imported); })
          .concat(domains.map(function(d) {
            var data = imported ? { source: 'IOC export (pcap import)' } : { simulated: true, source: 'IOC export' };
            return { type: 'DOMAIN', name: d, data: data, opts: { tags: ['phantom', 'ioc', imported ? 'pcap-import' : 'simulated'] } };
          }));
        var r = gb.sendToGraph('PHANTOM', items, undefined, true);
        r.summary = (ips.length + domains.length) + ' IOCs, ' + r.created + ' added';
        return r;
      }, imported ? 'tagged pcap-import' : 'tagged simulated');
    };
  }

  // ========================================================================
  // TAB (SCOUTING): NETWORK RECON — passive asset & service enumeration
  // ========================================================================
  // Real analysis over the loaded capture: discover hosts/talkers, enumerate
  // the services each host offers, build an asset+service inventory and flag
  // exposed / plaintext services. This is the map an attacker builds first.
  function renderRecon(c) {
    if (packets.length === 0) {
      c.innerHTML =
        '<div class="ph-empty">No capture loaded. Reconnaissance is built from captured traffic.' +
        '<div style="margin-top:12px"><button class="ph-btn" id="ph-recon-demo">Load Demo Capture (50 packets)</button></div></div>';
      var db = c.querySelector('#ph-recon-demo');
      if (db) db.onclick = loadDemo;
      return;
    }

    // --- Host inventory ---------------------------------------------------
    var hosts = {}; // ip -> { sent, recv, bytes, protocols:{}, ports:{} }
    function host(ip) {
      return hosts[ip] || (hosts[ip] = { sent: 0, recv: 0, bytes: 0, protocols: {}, ports: {} });
    }
    // --- Service inventory ------------------------------------------------
    var services = {}; // ip|port -> { ip, port, proto, count, info }
    function noteService(ip, port, proto) {
      var info = phServiceInfo(port);
      if (!info) return;
      var key = ip + '|' + port;
      var s = services[key] || (services[key] = { ip: ip, port: port, proto: proto, name: info.name, exposure: info.exposure, count: 0 });
      s.count++;
      host(ip).ports[port] = info.name;
    }

    packets.forEach(function(p) {
      var validSrc = /^\d{1,3}(\.\d{1,3}){3}$/.test(p.srcIP);
      var validDst = /^\d{1,3}(\.\d{1,3}){3}$/.test(p.dstIP);
      if (validSrc) { var hs = host(p.srcIP); hs.sent++; hs.bytes += p.length || 0; hs.protocols[p.protocol] = true; }
      if (validDst) { var hd = host(p.dstIP); hd.recv++; hd.bytes += p.length || 0; hd.protocols[p.protocol] = true; }
      // The endpoint bound to a well-known service port is offering that service.
      if (validDst && phServiceInfo(p.dstPort)) noteService(p.dstIP, p.dstPort, phTransport(p.protocol));
      if (validSrc && phServiceInfo(p.srcPort)) noteService(p.srcIP, p.srcPort, phTransport(p.protocol));
    });

    var hostArr = Object.keys(hosts).map(function(ip) {
      var h = hosts[ip];
      return { ip: ip, internal: phIsPrivate(ip), sent: h.sent, recv: h.recv, bytes: h.bytes,
        protocols: Object.keys(h.protocols).join(', '), ports: Object.keys(h.ports).map(Number).sort(function(a, b) { return a - b; }) };
    }).sort(function(a, b) { return b.bytes - a.bytes; });

    var svcArr = Object.keys(services).map(function(k) { return services[k]; })
      .sort(function(a, b) { return b.count - a.count; });

    var internalCount = hostArr.filter(function(h) { return h.internal; }).length;
    var riskyCount = svcArr.filter(function(s) { return s.exposure !== 'encrypted'; }).length;

    var expBadge = {
      plaintext: '<span class="ph-badge ph-sev-MEDIUM">PLAINTEXT</span>',
      exposed: '<span class="ph-badge ph-sev-HIGH">EXPOSED</span>',
      suspicious: '<span class="ph-badge ph-sev-CRITICAL">SUSPICIOUS</span>',
      encrypted: '<span class="ph-badge ph-sev-LOW">ENCRYPTED</span>',
    };

    c.innerHTML =
      '<div class="ph-grid">' +
        '<div class="ph-stat"><div class="ph-stat-n">' + hostArr.length + '</div><div class="ph-stat-l">Hosts Discovered</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + internalCount + ' / ' + (hostArr.length - internalCount) + '</div><div class="ph-stat-l">Internal / External</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n">' + svcArr.length + '</div><div class="ph-stat-l">Services Observed</div></div>' +
        '<div class="ph-stat"><div class="ph-stat-n" style="color:' + (riskyCount ? '#f97316' : '#22c55e') + '">' + riskyCount + '</div><div class="ph-stat-l">Unencrypted / Exposed</div></div>' +
      '</div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Passive Reconnaissance</div><div class="ph-panel-body">' +
        '<div style="font-size:.78rem;color:var(--txt);line-height:1.5">This is the asset and service picture an adversary assembles <b>before</b> acting, reconstructed purely from observed traffic &mdash; no active scanning. Close the exposed and plaintext services first.</div>' +
      '</div></div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Host Inventory (asset map)</div><div class="ph-panel-body"><div class="ph-scroll" style="max-height:320px">' +
        '<table class="ph-table"><thead><tr><th>Host</th><th>Scope</th><th>Sent</th><th>Recv</th><th>Bytes</th><th>Protocols</th><th>Offered Ports</th></tr></thead><tbody>' +
        hostArr.map(function(h) {
          return '<tr><td style="font-family:var(--font-mono,monospace)">' + esc(h.ip) + '</td>' +
            '<td>' + (h.internal ? '<span class="ph-chip">internal</span>' : 'external') + '</td>' +
            '<td>' + h.sent + '</td><td>' + h.recv + '</td><td>' + fmtBytes(h.bytes) + '</td>' +
            '<td style="font-size:.72rem">' + esc(h.protocols) + '</td>' +
            '<td style="font-family:var(--font-mono,monospace);font-size:.72rem">' + (h.ports.length ? esc(h.ports.join(', ')) : '&mdash;') + '</td></tr>';
        }).join('') +
        '</tbody></table>' +
      '</div></div></div>' +

      '<div class="ph-panel"><div class="ph-panel-h">Observed Services (attack surface)</div><div class="ph-panel-body"><div class="ph-scroll" style="max-height:320px">' +
        (svcArr.length ?
          '<table class="ph-table"><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Transport</th><th>Exposure</th><th>Observed</th></tr></thead><tbody>' +
          svcArr.map(function(s) {
            return '<tr><td style="font-family:var(--font-mono,monospace)">' + esc(s.ip) + '</td>' +
              '<td style="font-family:var(--font-mono,monospace)">' + s.port + '</td>' +
              '<td>' + esc(s.name) + '</td><td>' + esc(s.proto) + '</td>' +
              '<td>' + (expBadge[s.exposure] || esc(s.exposure)) + '</td>' +
              '<td>' + s.count + ' pkt' + (s.count === 1 ? '' : 's') + '</td></tr>';
          }).join('') +
          '</tbody></table>' :
          '<div class="ph-empty">No well-known services observed in this capture.</div>') +
      '</div></div></div>';
  }

  // ========================================================================
  // TAB (OFFENSIVE): ATTACK SIMULATION — adversary emulation (blue-team only)
  // ========================================================================
  // SIMULATION ONLY. Pick a network attack technique and "run" it: PHANTOM
  // generates an illustrative packet sequence / attack chain and a verdict for
  // whether its own defensive views would catch it. No packet crafting, no
  // network activity of any kind.
  function renderAttackSim(c) {
    var selPlay = renderAttackSim._play || PH_ATTACK_PLAYS[0].id;
    // Target list: prefer real internal hosts from the capture, else a default.
    var targets = [];
    packets.forEach(function(p) {
      if (phIsPrivate(p.dstIP) && targets.indexOf(p.dstIP) === -1) targets.push(p.dstIP);
      if (phIsPrivate(p.srcIP) && targets.indexOf(p.srcIP) === -1) targets.push(p.srcIP);
    });
    if (targets.length === 0) targets = ['10.0.0.5'];
    var selTarget = renderAttackSim._target && targets.indexOf(renderAttackSim._target) >= 0 ? renderAttackSim._target : targets[0];

    c.innerHTML =
      '<div class="ph-panel" style="border-color:#ef4444"><div class="ph-panel-h" style="color:#ef4444">Adversary Emulation &mdash; Simulation Only</div><div class="ph-panel-body">' +
        '<div style="font-size:.78rem;color:var(--txt);line-height:1.5"><b style="color:#ef4444">SIMULATION ONLY.</b> Choose a technique and run it to see an illustrative, generated packet sequence and whether PHANTOM\'s own defensive views would catch it. No packets are crafted and nothing touches the network &mdash; this exercises the blue-side detections, nothing more.</div>' +
        '<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;margin-top:12px">' +
          '<div style="flex:1;min-width:220px"><div class="ph-stat-l" style="margin-bottom:4px;text-align:left">Technique</div>' +
            '<select id="ph-as-play" style="width:100%;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--txt);font-size:.78rem;font-family:inherit">' +
            PH_ATTACK_PLAYS.map(function(p) { return '<option value="' + p.id + '"' + (p.id === selPlay ? ' selected' : '') + '>' + esc(p.name) + '</option>'; }).join('') +
            '</select></div>' +
          '<div style="flex:1;min-width:180px"><div class="ph-stat-l" style="margin-bottom:4px;text-align:left">Target host</div>' +
            '<select id="ph-as-target" style="width:100%;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--txt);font-size:.78rem;font-family:inherit">' +
            targets.map(function(t) { return '<option value="' + esc(t) + '"' + (t === selTarget ? ' selected' : '') + '>' + esc(t) + '</option>'; }).join('') +
            '</select></div>' +
          '<button class="ph-btn" id="ph-as-run" style="background:#ef4444">Run Simulation</button>' +
        '</div>' +
      '</div></div>' +
      '<div id="ph-as-out"></div>';

    var out = c.querySelector('#ph-as-out');
    var playSel = c.querySelector('#ph-as-play');
    var tgtSel = c.querySelector('#ph-as-target');
    playSel.onchange = function() { renderAttackSim._play = playSel.value; };
    tgtSel.onchange = function() { renderAttackSim._target = tgtSel.value; };

    function run() {
      var play = PH_ATTACK_PLAYS.find(function(p) { return p.id === playSel.value; }) || PH_ATTACK_PLAYS[0];
      var target = tgtSel.value;
      renderAttackSim._play = play.id;
      renderAttackSim._target = target;
      var seq = play.gen(target);
      var verdictNote = play.verdict === 'MISSED'
        ? 'This technique would likely evade the current controls. Prioritize closing the named gap.'
        : play.verdict === 'PARTIAL'
        ? 'Partial coverage: the attack leaves traces but may not be fully caught. Tune or extend the named control.'
        : 'PHANTOM\'s defensive views would catch and contain this technique. Keep the detection exercised.';

      out.innerHTML =
        '<div class="ph-panel"><div class="ph-panel-h">' + esc(play.name) + ' &mdash; ' + esc(play.tactic) + '</div><div class="ph-panel-body">' +
          '<div class="ph-alert-desc">' + esc(play.summary) + '</div>' +
          '<div class="ph-stat-l" style="text-align:left;margin:10px 0 4px">Simulated attack chain</div>' +
          '<ol style="margin:0;padding-left:20px;font-size:.78rem;line-height:1.7;color:var(--txt)">' +
            play.chain.map(function(s) { return '<li>' + esc(s) + '</li>'; }).join('') +
          '</ol>' +
        '</div></div>' +

        '<div class="ph-panel"><div class="ph-panel-h">Simulated Packet Sequence <span class="ph-chip" style="background:rgba(239,68,68,.1);color:#ef4444;border-color:rgba(239,68,68,.2)">generated</span></div><div class="ph-panel-body"><div class="ph-scroll" style="max-height:340px">' +
          '<table class="ph-table"><thead><tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody>' +
          seq.map(function(p, i) {
            var col = protoColor(p.proto);
            return '<tr><td>' + (i + 1) + '</td><td>' + fmtTime(p.ts) + '</td>' +
              '<td style="font-family:var(--font-mono,monospace);font-size:.72rem">' + esc(p.src) + '</td>' +
              '<td style="font-family:var(--font-mono,monospace);font-size:.72rem">' + esc(p.dst) + '</td>' +
              '<td><span class="ph-proto" style="background:' + col.bg + ';color:' + col.text + '">' + esc(p.proto) + '</span></td>' +
              '<td>' + p.len + (p.flags ? ' <span style="color:var(--mut);font-size:.66rem">' + esc(p.flags) + '</span>' : '') + '</td>' +
              '<td style="font-size:.72rem">' + esc(p.info) + '</td></tr>';
          }).join('') +
          '</tbody></table>' +
        '</div></div></div>' +

        '<div class="ph-panel"><div class="ph-panel-h">Detection Verdict</div><div class="ph-panel-body">' +
          '<div class="ph-alert-head">' + phVerdictBadge(play.verdict) + '<span class="ph-alert-type">Would PHANTOM catch it?</span></div>' +
          '<div style="font-size:.74rem;color:var(--mut);margin-bottom:6px">Blue-side control tested: <b style="color:var(--txt)">' + esc(play.control) + '</b></div>' +
          '<div class="ph-alert-ev">' + esc(play.detectNote) + '</div>' +
          '<div class="ph-alert-rec">' + esc(verdictNote) + '</div>' +
        '</div></div>';
    }

    c.querySelector('#ph-as-run').onclick = run;
    run();
  }

  render();
}

export function cleanupPhantom() {
  if (window._phantomTimers && window._phantomTimers.length) {
    window._phantomTimers.forEach(function(t) { clearTimeout(t); clearInterval(t); });
    window._phantomTimers = [];
  }
  if (_phInterval) { clearInterval(_phInterval); _phInterval = null; }
}
