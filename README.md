# 🛡️ flutter_iot_shield

[![pub package](https://img.shields.io/pub/v/flutter_iot_shield.svg?color=blue)](https://pub.dev/packages/flutter_iot_shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)
[![Flutter Platform Support](https://img.shields.io/badge/platform-ios%20%7C%20android%20%7C%20macos%20%7C%20windows%20%7C%20linux-blue)](https://pub.dev/packages/flutter_iot_shield)
[![Dart Version Support](https://img.shields.io/badge/dart-%3E%3D3.0.0-teal)](https://dart.dev)

An enterprise-grade, lightweight security layer for Flutter applications communicating with BLE (Bluetooth Low Energy) smart devices. 

`flutter_iot_shield` shields your IoT applications by establishing encrypted secure channels, validating device identities via cryptographic attestation, enforcing replay attack protections, verifying firmware package signatures before flashing, and sanitizing BLE input channels.

---

## 🌟 Key Features

*   🔑 **Cryptographic Secure Channel**: Implements ECDH key exchange (Curve25519) and HKDF key derivation to derive unique session keys, enabling AES-256-GCM authenticated encryption.
*   🛡️ **Anti-Replay Attack Protection**: Implements a sliding window sequence-tracking algorithm to detect and discard replayed or out-of-order payloads.
*   📜 **X.509 Device Attestation**: Authenticates BLE device credentials by verifying custom challenge signatures against an X.509 certificate chain signed by your Root Certificate Authority.
*   ⚙️ **Firmware Signature Verification**: Ensures OTA firmware updates are authentic by checking Ed25519 digital signatures and enforcing anti-downgrade policies.
*   📊 **Biometric & Telemetry Validation**: Decodes, sanitizes, and verifies BLE values against configurable schemas and threshold limits (e.g. heartbeat ranges, body temperature bounds) to block bad data injection.
*   🔒 **Secure Key Storage**: Offloads local security keys and configurations safely using secure platform-specific hardware keystores (leveraging `flutter_secure_storage`).
*   🚨 **Security Monitoring & Event Bus**: Detects and broadcasts real-time anomalies (e.g. connection storms, device spoofing, packet duplication) directly to the parent app via the [SecurityEventBus](file:///Users/saifalmajd/saif/flutter_iot_shield/lib/src/monitoring/security_event_bus.dart).

---

## 📐 Architecture Overview

```mermaid
flowchart TD
    App[Consuming Flutter Application] <--> |Reads Events & Invokes| Shield[IoTShield SDK Barrel]
    
    subgraph Security Layer
        Shield <--> Session[Secure Session Manager]
        Shield <--> Anomaly[Anomaly Detector & Scan Monitor]
        Shield <--> Storage[Secure Device Storage]
        Shield <--> Validation[Health & Platform Channel Sanitizer]
        
        Session <--> Crypt[Crypto Provider: ECDH + AES-256-GCM]
        Session <--> Replay[Replay Protection: Sliding Window]
        
        Shield <--> Attest[Device Attestation Manager: X.509]
        Shield <--> Firmware[Firmware Verifier: Ed25519 + manifest]
    end
    
    App BLE[BLE Core Service] <--> |Encrypted Packets| IoT[IoT / BLE Smart Device]
```

---

## 🚀 Installation

Add `flutter_iot_shield` to your `pubspec.yaml`:

```yaml
dependencies:
  flutter_iot_shield: ^1.0.0
```

And run:
```bash
flutter pub get
```

---

## 📖 Quick Start

### 1. Initialize the Security Engine

Initialize the [IoTShield](file:///Users/saifalmajd/saif/flutter_iot_shield/lib/src/core/iot_shield.dart) singleton once in your application initialization sequence (e.g., inside `main.dart`):

```dart
import 'package:flutter/material.dart';
import 'package:flutter_iot_shield/flutter_iot_shield.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Configure your credentials and settings
  final config = IoTShieldConfig(
    appId: 'com.yourcompany.smartwatch',
    verboseLogging: true,
    // Ed25519 public key used to verify firmware OTA updates
    firmwarePublicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
  );

  await IoTShield.instance.initialize(config);

  runApp(const MyApp());
}
```

### 2. Verify and Trust a Connecting Device

Assess the risk level of an advertising BLE device before pairing:

```dart
import 'package:flutter_iot_shield/flutter_iot_shield.dart';

final trustLevel = await IoTShield.instance.verifyDevice(
  deviceId: '00:11:22:33:AA:BB',
  deviceInfo: {
    'model': 'WatchPro_X1',
    'firmwareVersion': '1.2.0',
    'bleVersion': '5.2',
  },
);

if (trustLevel == TrustLevel.suspicious) {
  // Take action: disconnect or warn the user
  print('Security warning: Connected device has been flagged as suspicious.');
}
```

### 3. Establish a Secure Pairing Session (ECDH + Attestation)

Derive shared session keys and verify the cryptographic signature challenge using the device certificate:

```dart
try {
  final session = await IoTShield.instance.pairDevice(
    '00:11:22:33:AA:BB',
    'WatchPro_X1',
    devicePublicKey: devicePublicKeyBytes,      // Raw public key bytes from device
    deviceCertificateDer: deviceCertDerBytes,    // X509 certificate DER bytes
    challengeResponse: challengeSignatureBytes,  // Device's signature over challenge
    challengeNonce: sentNonceBytes,             // Original nonce sent to device
  );
  
  print('Secure session established. Session ID: ${session.sessionId}');
} on AttestationException catch (e) {
  print('Device identity verification failed: $e');
}
```

### 4. Send and Receive Encrypted Packets

Encrypt command payloads using AES-256-GCM and protect them against replay attacks:

```dart
// 1. Encrypt outgoing command payload
final SecurePacket packet = await IoTShield.instance.encrypt(
  Uint8List.fromList([0x01, 0x02, 0x03]), // plaintext command bytes
  '00:11:22:33:AA:BB',
  command: 0x0A,
  sequence: 42, // strictly increasing sequence
);

// Transmit packet.encryptedPayload, packet.nonce (IV), and packet.mac over your BLE characteristic...

// 2. Decrypt incoming data packet from the device
try {
  final Uint8List plaintext = await IoTShield.instance.decrypt(
    receivedPacket, // parsed SecurePacket containing ciphertext, iv, and mac
    '00:11:22:33:AA:BB',
  );
  print('Decrypted bytes: $plaintext');
} on ReplayAttackException catch (e) {
  print('Security threat: Replay attack detected! $e');
}
```

### 5. Intercept Live Security Events

Subscribe to the global event stream to alert administrators of anomalous events:

```dart
IoTShield.instance.securityEvents.listen((SecurityEvent event) {
  switch (event.severity) {
    case SecuritySeverity.info:
      print('Log: ${event.message}');
      break;
    case SecuritySeverity.warning:
      print('Warning: ${event.message} - Meta: ${event.meta}');
      break;
    case SecuritySeverity.critical:
      print('🔴 CRITICAL ALERT: ${event.message}');
      // Trigger emergency lock down, log to SIEM, or disconnect device
      break;
  }
});
```

---

## 🛠️ Security Subsystems

### 🛡️ Sliding Window Replay Protection
`flutter_iot_shield` uses a tracking sliding window sequence filter. An incoming packet's sequence number must be within a safe window. Duplicate sequence numbers within the window are rejected, and sequence numbers older than the window limits are immediately dropped.

### 🛡️ Real-Time Anomaly Detection
The [AnomalyDetector](file:///Users/saifalmajd/saif/flutter_iot_shield/lib/src/monitoring/anomaly_detector.dart) monitors events locally. It triggers alerts if it detects:
- **Reconnection Storms**: Too many reconnect requests within a 2-minute window (indicates compromised hardware or intermediate relay hijack).
- **Device Impersonation**: Rapid switching of multiple devices trying to authenticate on the same client in a 1-minute window.
- **High Scan Rates**: Excessive scanning frequency indicating rogue packet sniffers.

### 🛡️ Firmware Verification
Verifies signed firmware ZIP OTA packages containing a `manifest.json` signature block using an Ed25519 verification algorithm. Prevents downgrading the watch firmware (anti-rollback) and guarantees image authenticity.

---

## 👥 Credits

This package was developed, polished, and structured for release by:

**SaifAlmajd**
*   GitHub: [@Syf-Almjd](https://github.com/Syf-Almjd)
*   Role: Creator and Lead Maintainer

Feel free to open issues or pull requests on the [GitHub Repository](https://github.com/Syf-Almjd/flutter_iot_shield) to contribute!

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](file:///Users/saifalmajd/saif/flutter_iot_shield/LICENSE) file for details.
