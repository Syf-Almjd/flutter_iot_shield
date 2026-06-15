# flutter_iot_shield

A robust, enterprise-grade IoT security layer for Flutter applications communicating with BLE (Bluetooth Low Energy) smart devices. 

Provides device attestation, cryptographic secure channels, sliding window replay protection, firmware signature verification, health data validation, and platform channel sanitization.

## Features

- 🔐 **Cryptographic Secure Channel**: ECDH key exchange (Curve25519) combined with HKDF key derivation to establish shared symmetric keys for AES-256-GCM authenticated encryption.
- 🛡️ **Anti-Replay Attack Protection**: Sliding window sequence tracking to prevent message capture and replay.
- 📜 **Device Attestation**: X.509 certificate parsing and validation over custom challenges.
- ⚙️ **Firmware Verification**: Verifies signed firmware zip packages using ECDSA signatures before updating.
- 📊 **Health Data Validation**: Rules-based sanitization and verification of telemetry data constraints.
- 🔒 **Secure Storage**: Cryptographically protected local key store utilizing platform-specific secure hardware storage (`flutter_secure_storage`).
- 🚨 **Monitoring & Anomaly Detection**: Lightweight rule engines and a real-time event bus (`SecurityEventBus`) that alerts the parent application of security threats (e.g. key-rotation required, suspicious devices, replay attacks).

---

## Installation

Add `flutter_iot_shield` to your `pubspec.yaml`:

```yaml
dependencies:
  flutter_iot_shield:
    git:
      url: https://github.com/Syf-Almjd/flutter_iot_shield.git
```

Or when published on pub.dev:

```yaml
dependencies:
  flutter_iot_shield: ^1.0.0
```

---

## Quick Start

### 1. Initialize the Shield

Initialize the `IoTShield` singleton once in your app's initialization sequence (e.g. in `main.dart`):

```dart
import 'package:flutter/material.dart';
import 'package:flutter_iot_shield/flutter_iot_shield.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Configure the security engine
  final config = IoTShieldConfig(
    appId: 'com.example.smartwatch',
    verboseLogging: true,
    firmwarePublicKey: '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
  );

  await IoTShield.instance.initialize(config);

  runApp(const MyApp());
}
```

### 2. Verify and Trust a Connecting Device

When a BLE device connects, query its device info and verify its identity:

```dart
final trustLevel = await IoTShield.instance.verifyDevice(
  deviceId: 'device-mac-address-or-uuid',
  deviceInfo: {
    'model': 'WatchPro_X1',
    'firmwareVersion': '1.2.0',
    'bleVersion': '5.2',
  },
);

if (trustLevel == TrustLevel.suspicious) {
  // Disconnect the device immediately!
  print('Security warning: Device failed trust verification.');
}
```

### 3. Establish a Secure Pairing Session

Establish an ECDH secure channel session with the device:

```dart
try {
  final session = await IoTShield.instance.pairDevice(
    'device-uuid',
    'WatchPro_X1',
    devicePublicKey: devicePublicKeyBytes,
    deviceCertificateDer: deviceCertDerBytes,
    challengeResponse: challengeSignatureBytes,
    challengeNonce: sentNonceBytes,
  );
  
  print('Secure session established. Session ID: ${session.sessionId}');
} on AttestationException catch (e) {
  print('Device attestation failed: $e');
}
```

### 4. Send and Receive Encrypted Packets

Encrypt and decrypt payloads sent to/from the BLE device:

```dart
// Encrypt outgoing command payload
final SecurePacket packet = await IoTShield.instance.encrypt(
  Uint8List.fromList([0x01, 0x02, 0x03]), // plaintext
  'device-uuid',
  command: 0x0A,
  sequence: 42,
);

// Send packet.encryptedPayload, packet.nonce (IV), and packet.mac to BLE characteristic...

// Decrypt incoming package
try {
  final Uint8List plaintext = await IoTShield.instance.decrypt(
    receivedPacket,
    'device-uuid',
  );
  print('Decrypted message: $plaintext');
} on ReplayAttackException catch (e) {
  print('Potential replay attack detected! $e');
}
```

### 5. Listen to Security Events

Subscribe to the real-time stream of security events to respond to threats:

```dart
IoTShield.instance.securityEvents.listen((SecurityEvent event) {
  if (event.severity == SecuritySeverity.critical) {
    // Alert the user, log to server, or shut down connection
    print('CRITICAL SECURITY EVENT: ${event.message} - ${event.meta}');
  }
});
```

---

## Architecture Overview

```
                     ┌──────────────────────┐
                     │     Application      │
                     └──────────┬───────────┘
                                │
                     ┌──────────▼───────────┐
                     │      IoTShield       │◀─── SecurityEventBus
                     └────┬───────────────┬─┘
                          │               │
      ┌───────────────────▼──┐         ┌──▼───────────────────┐
      │   Secure Session     │         │ Sanitization & Rules │
      │   (ECDH / AES-GCM)   │         └──────────┬───────────┘
      └─────────┬────────────┘                    │
                │                        ┌────────▼─────────┐
      ┌─────────▼────────────┐           │  Health Validator│
      │  Replay Protection   │           └──────────────────┘
      └──────────────────────┘
```

- **Cryptography**: Standard implementations using `cryptography` and `pointycastle` packages.
- **Verification**: Support for custom X.509 parsing logic designed to verify resource-constrained smart watch devices.
- **Isolation**: Clean separation between platform channel sanitization, storage, and encryption components.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
