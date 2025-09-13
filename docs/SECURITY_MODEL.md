# Amoskys Security Model

## Executive Summary

Amoskys implements a **defense-in-depth security architecture** with multiple layers of protection. The security model assumes breach mentality and implements zero-trust principles throughout the system.

## Security Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Defense in Depth                        │
├─────────────────────────────────────────────────────────────┤
│ Layer 5: Application Security (Ed25519 Message Signing)    │
│ Layer 4: Transport Security (mTLS with Certificate Auth)   │
│ Layer 3: Network Security (gRPC with TLS 1.3)            │
│ Layer 2: Host Security (Process Isolation, WAL Integrity) │
│ Layer 1: Infrastructure (Container Security, Host Hardening)│
└─────────────────────────────────────────────────────────────┘
```

## Transport Layer Security (mTLS)

### TLS Configuration

#### Cipher Suites (TLS 1.3)
```
Primary: TLS_AES_256_GCM_SHA384
Fallback: TLS_CHACHA20_POLY1305_SHA256
Legacy Support: TLS_AES_128_GCM_SHA256
```

#### Certificate Management
```
Certificate Authority (CA):
├── ca.crt (Root Certificate)
├── ca.key (Private Key - RSA 4096-bit)
│
Server Certificates:
├── server.crt (EventBus Server Certificate)
├── server.key (Private Key - RSA 4096-bit)
│
Client Certificates:
├── agent.crt (Agent Client Certificate)
└── agent.key (Private Key - RSA 4096-bit)
```

#### Certificate Generation Process
```bash
# 1. Generate CA private key
openssl genrsa -out ca.key 4096

# 2. Generate CA certificate
openssl req -new -x509 -key ca.key -sha256 -subj "/C=US/ST=Security/L=Amoskys/O=Amoskys/CN=Amoskys CA" -days 3650 -out ca.crt

# 3. Generate server private key
openssl genrsa -out server.key 4096

# 4. Generate server certificate signing request
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=Security/L=Amoskys/O=Amoskys/CN=infraspectre-eventbus"

# 5. Generate server certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extensions v3_req -extfile server.ext
```

#### Certificate Validation
- **Chain of Trust**: All certificates validated against CA
- **Hostname Verification**: Server certificates include SAN extensions
- **Certificate Revocation**: CRL and OCSP checking supported
- **Key Pinning**: Client certificates pinned to specific agents

### mTLS Handshake Flow

```
Agent                           EventBus
  │                               │
  │ 1. ClientHello               │
  ├──────────────────────────────>│
  │                               │
  │ 2. ServerHello + ServerCert   │
  │<──────────────────────────────┤
  │                               │
  │ 3. ClientCert + ClientKeyExch │
  ├──────────────────────────────>│
  │                               │
  │ 4. Finished                   │
  │<──────────────────────────────┤
  │                               │
  │ 5. Encrypted Application Data │
  │<─────────────────────────────>│
```

## Application Layer Security (Ed25519)

### Ed25519 Digital Signatures

#### Key Generation
```python
# Generate Ed25519 keypair
from cryptography.hazmat.primitives.asymmetric import ed25519

private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Serialize keys
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
```

#### Message Signing Process
```python
def sign_message(message: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Sign message with Ed25519 private key"""
    canonical_message = canonicalize_message(message)
    signature = private_key.sign(canonical_message)
    return signature

def verify_signature(message: bytes, signature: bytes, public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verify Ed25519 signature"""
    canonical_message = canonicalize_message(message)
    try:
        public_key.verify(signature, canonical_message)
        return True
    except InvalidSignature:
        return False
```

#### Canonical Message Format
```python
def canonicalize_message(envelope: pb.Envelope) -> bytes:
    """Create canonical representation for signing"""
    canonical = pb.Envelope()
    canonical.source_agent = envelope.source_agent
    canonical.event_id = envelope.event_id  
    canonical.timestamp_ns = envelope.timestamp_ns
    canonical.flow_event.CopyFrom(envelope.flow_event)
    # Note: signature field is excluded from canonical form
    return canonical.SerializeToString()
```

### Trust Map Management

#### Trust Map Structure
```yaml
# config/trust_map.yaml
trust_map:
  agents:
    "agent-001":
      public_key: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA..."
      certificate_fingerprint: "sha256:a1b2c3d4..."
      authorized_operations: ["publish_events", "health_check"]
      valid_until: "2025-12-31T23:59:59Z"
    
    "agent-002":
      public_key: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA..."
      certificate_fingerprint: "sha256:e5f6g7h8..."
      authorized_operations: ["publish_events"]
      valid_until: "2025-12-31T23:59:59Z"
```

#### Trust Verification Process
```python
def verify_agent_trust(agent_id: str, certificate: x509.Certificate, public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verify agent is in trust map and credentials match"""
    trust_entry = trust_map.get_agent(agent_id)
    if not trust_entry:
        return False
    
    # Verify certificate fingerprint
    cert_fingerprint = certificate.fingerprint(hashes.SHA256())
    if cert_fingerprint != trust_entry.certificate_fingerprint:
        return False
    
    # Verify public key matches
    if public_key.public_bytes() != trust_entry.public_key:
        return False
    
    # Verify not expired
    if datetime.now() > trust_entry.valid_until:
        return False
    
    return True
```

## Cryptographic Primitives

### Algorithm Selection Rationale

#### Ed25519 Digital Signatures
- **Security**: 128-bit security level, equivalent to 3072-bit RSA
- **Performance**: 20x faster than RSA-2048 signatures
- **Size**: 64-byte signatures vs 256-byte RSA signatures
- **Deterministic**: No random number generation during signing
- **Side-Channel Resistant**: Constant-time implementation

#### ChaCha20-Poly1305 (TLS 1.3)
- **Security**: 256-bit key, authenticated encryption
- **Performance**: Optimized for software implementation
- **Resistance**: Strong against timing attacks
- **Standardization**: RFC 8439, widely supported

#### Curve25519 (ECDH)
- **Security**: 128-bit security level
- **Performance**: Fast key agreement
- **Safety**: Safe curves, resistant to invalid curve attacks
- **Standards**: RFC 7748, FIPS 140-2 validated

### Key Management

#### Key Lifecycle
```
Key Generation → Storage → Usage → Rotation → Revocation → Destruction
```

#### Key Storage Security
```python
# Production key storage (HSM recommended)
class SecureKeyStore:
    def store_private_key(self, key_id: str, private_key: bytes, passphrase: str):
        """Store private key with encryption"""
        encrypted_key = encrypt_key(private_key, passphrase)
        hsm.store_key(key_id, encrypted_key)
    
    def load_private_key(self, key_id: str, passphrase: str) -> ed25519.Ed25519PrivateKey:
        """Load and decrypt private key"""
        encrypted_key = hsm.load_key(key_id)
        private_key_bytes = decrypt_key(encrypted_key, passphrase)
        return ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
```

#### Key Rotation Strategy
- **Frequency**: Annual rotation for long-term keys
- **Emergency**: Immediate rotation on compromise
- **Overlap**: 30-day overlap period for smooth transition
- **Automation**: Automated rotation with certificate management

## Write-Ahead Log (WAL) Security

### WAL Integrity Protection

#### Database Encryption
```python
# SQLite encryption with SQLCipher
import sqlite3

def create_encrypted_wal(wal_path: str, encryption_key: bytes):
    """Create encrypted WAL database"""
    conn = sqlite3.connect(wal_path)
    
    # Enable encryption (requires SQLCipher)
    conn.execute(f"PRAGMA key = '{encryption_key.hex()}'")
    
    # Enable WAL mode with integrity checks
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA integrity_check")
    
    return conn
```

#### Data Integrity Verification
```python
def verify_wal_integrity(wal_path: str) -> bool:
    """Verify WAL database integrity"""
    conn = sqlite3.connect(wal_path)
    
    # Check database integrity
    result = conn.execute("PRAGMA integrity_check").fetchone()
    if result[0] != "ok":
        return False
    
    # Verify checksums for critical data
    events = conn.execute("SELECT event_data, checksum FROM events").fetchall()
    for event_data, stored_checksum in events:
        calculated_checksum = sha256(event_data).hexdigest()
        if calculated_checksum != stored_checksum:
            return False
    
    return True
```

### WAL Access Control

#### File Permissions
```bash
# Restrict WAL file access
chmod 600 /data/wal/flowagent.db
chown infraspectre:infraspectre /data/wal/flowagent.db

# Set directory permissions
chmod 700 /data/wal/
chown infraspectre:infraspectre /data/wal/
```

#### Process Isolation
```python
# Drop privileges after startup
import pwd, grp, os

def drop_privileges(username: str):
    """Drop to non-privileged user"""
    user_info = pwd.getpwnam(username)
    os.setgroups([])
    os.setgid(user_info.pw_gid)
    os.setuid(user_info.pw_uid)
```

## Network Security

### gRPC Security Configuration

#### Server Configuration
```python
# EventBus server with mTLS
import grpc
from grpc import ssl_channel_credentials, ssl_server_credentials

def create_secure_server():
    """Create gRPC server with mTLS"""
    with open('certs/server.key', 'rb') as f:
        private_key = f.read()
    with open('certs/server.crt', 'rb') as f:
        certificate_chain = f.read()
    with open('certs/ca.crt', 'rb') as f:
        root_certificates = f.read()
    
    server_credentials = ssl_server_credentials(
        [(private_key, certificate_chain)],
        root_certificates=root_certificates,
        require_client_auth=True  # Mutual TLS
    )
    
    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    server.add_secure_port('[::]:50051', server_credentials)
    return server
```

#### Client Configuration
```python
def create_secure_channel(server_address: str):
    """Create gRPC client with mTLS"""
    with open('certs/agent.key', 'rb') as f:
        private_key = f.read()
    with open('certs/agent.crt', 'rb') as f:
        certificate_chain = f.read()
    with open('certs/ca.crt', 'rb') as f:
        root_certificates = f.read()
    
    credentials = ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain
    )
    
    channel = grpc.secure_channel(server_address, credentials)
    return channel
```

### Network Hardening

#### Firewall Rules
```bash
# Allow only necessary ports
iptables -A INPUT -p tcp --dport 50051 -j ACCEPT  # EventBus gRPC
iptables -A INPUT -p tcp --dport 9100 -j ACCEPT   # EventBus metrics
iptables -A INPUT -p tcp --dport 9101 -j ACCEPT   # Agent metrics
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT   # EventBus health
iptables -A INPUT -p tcp --dport 8081 -j ACCEPT   # Agent health

# Drop all other traffic
iptables -A INPUT -j DROP
```

#### DDoS Protection
```python
# Rate limiting in gRPC interceptor
class RateLimitInterceptor(grpc.ServerInterceptor):
    def __init__(self, max_requests_per_minute: int = 1000):
        self.rate_limiter = RateLimiter(max_requests_per_minute)
    
    def intercept_service(self, continuation, handler_call_details):
        client_ip = self.get_client_ip(handler_call_details)
        
        if not self.rate_limiter.allow_request(client_ip):
            context = grpc.ServicerContext()
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded")
        
        return continuation(handler_call_details)
```

## Container Security

### Docker Security Hardening

#### Dockerfile Security Best Practices
```dockerfile
# Use minimal base images
FROM python:3.11-slim

# Create non-root user
RUN useradd -r -u 10001 -s /usr/sbin/nologin infraspectre

# Set proper file permissions
COPY --chown=infraspectre:infraspectre src/ /app/src/
COPY --chown=infraspectre:infraspectre config/ /app/config/

# Drop privileges
USER infraspectre:infraspectre

# Use security profiles
LABEL seccomp="seccomp-python-net.json"
```

#### Container Runtime Security
```bash
# Run with security constraints
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt seccomp=seccomp-python-net.json \
  --security-opt no-new-privileges \
  infraspectre/eventbus
```

### Kubernetes Security

#### Pod Security Standards
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: infraspectre-eventbus
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: eventbus
    image: infraspectre/eventbus:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]
```

## Threat Model

### Assets Protected
1. **Network Flow Data**: Sensitive network intelligence
2. **Agent Communications**: Command and control channels
3. **Cryptographic Keys**: Private keys and certificates
4. **Configuration Data**: System configuration and trust maps
5. **WAL Data**: Persistent event storage

### Threat Actors
1. **External Attackers**: Internet-based threat actors
2. **Insider Threats**: Malicious or compromised internal users
3. **Advanced Persistent Threats**: Nation-state actors
4. **Supply Chain Attacks**: Compromised dependencies

### Attack Vectors

#### Network Attacks
- **Man-in-the-Middle**: Mitigated by mTLS + certificate pinning
- **Replay Attacks**: Mitigated by Ed25519 signatures + timestamps
- **DDoS**: Mitigated by rate limiting + connection limits
- **Protocol Downgrade**: Mitigated by TLS 1.3 minimum version

#### Application Attacks
- **Message Forgery**: Mitigated by Ed25519 signatures
- **Injection Attacks**: Mitigated by protobuf validation
- **Privilege Escalation**: Mitigated by principle of least privilege
- **Data Tampering**: Mitigated by cryptographic integrity checks

#### Infrastructure Attacks
- **Container Escape**: Mitigated by security profiles + readonly filesystem
- **Host Compromise**: Mitigated by process isolation + minimal attack surface
- **Key Extraction**: Mitigated by secure key storage + HSM integration
- **Certificate Theft**: Mitigated by short-lived certificates + rotation

## Compliance & Standards

### Standards Compliance
- **FIPS 140-2**: Cryptographic modules
- **Common Criteria**: Security evaluation
- **NIST Cybersecurity Framework**: Risk management
- **ISO 27001**: Information security management

### Audit Requirements
- **Cryptographic Operations**: All crypto operations logged
- **Access Controls**: Authentication and authorization logged
- **Data Integrity**: WAL integrity checks logged
- **Network Communications**: Connection attempts logged

### Security Testing
- **Penetration Testing**: Annual third-party testing
- **Vulnerability Scanning**: Continuous automated scanning
- **Crypto Validation**: FIPS 140-2 module validation
- **Code Review**: Security-focused code reviews

## Security Operations

### Monitoring & Alerting
```python
# Security event monitoring
class SecurityMonitor:
    def log_authentication_failure(self, agent_id: str, reason: str):
        """Log failed authentication attempts"""
        security_logger.warning(f"Authentication failure: agent={agent_id}, reason={reason}")
        
        # Alert on repeated failures
        if self.get_failure_count(agent_id) > 5:
            alertmanager.send_alert("SECURITY_BREACH", f"Multiple auth failures for {agent_id}")
    
    def log_signature_verification_failure(self, agent_id: str, message_id: str):
        """Log signature verification failures"""
        security_logger.error(f"Signature verification failed: agent={agent_id}, message={message_id}")
        alertmanager.send_alert("SECURITY_BREACH", f"Invalid signature from {agent_id}")
```

### Incident Response
1. **Detection**: Automated monitoring and alerting
2. **Analysis**: Security team investigates alerts
3. **Containment**: Isolate compromised components
4. **Eradication**: Remove threat and vulnerabilities
5. **Recovery**: Restore normal operations
6. **Lessons Learned**: Update security measures

### Security Maintenance
- **Daily**: Review security logs and alerts
- **Weekly**: Vulnerability scanning and patching
- **Monthly**: Security metrics review and testing
- **Quarterly**: Penetration testing and audit
- **Annually**: Security architecture review and updates

This security model provides comprehensive protection for Amoskys deployments across all threat vectors and compliance requirements.
