// flutter_iot_shield/lib/src/identity/device_fingerprint.dart
//
// Generates and verifies cryptographic fingerprints for IoT devices.
// Created on first pairing, verified on every reconnection.

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../core/iot_shield_logger.dart';
import '../core/security_event.dart';

/// The trust classification assigned to a reconnecting device.
enum TrustLevel {
  /// Fingerprint matches exactly — safe to proceed.
  trusted,

  /// Firmware version changed (expected after OTA) — safe, update stored fingerprint.
  firmwareChanged,

  /// BLE identifiers changed — possible spoofing or hardware replacement.
  suspicious,

  /// No stored fingerprint exists — first pairing, create one now.
  unknown,
}

/// A cryptographic fingerprint of a paired IoT device.
class DeviceFingerprint {
  /// SHA-256 hash of device identity components.
  final String hash;

  /// BLE MAC or CoreBluetooth UUID.
  final String deviceId;

  /// Firmware version at the time of fingerprinting.
  final String firmwareVersion;

  /// Device model identifier (e.g. "PURA", "NHD13L").
  final String modelId;

  /// BLE protocol version.
  final String bleVersion;

  /// When this fingerprint was created.
  final DateTime createdAt;

  const DeviceFingerprint({
    required this.hash,
    required this.deviceId,
    required this.firmwareVersion,
    required this.modelId,
    required this.bleVersion,
    required this.createdAt,
  });

  /// Creates a fingerprint from device info map (as received from native layer).
  static Future<DeviceFingerprint> generate({
    required String deviceId,
    required String firmwareVersion,
    required String modelId,
    required String bleVersion,
    Uint8List? pairSecret,
  }) async {
    final components = [
      deviceId.trim(),
      modelId.trim(),
      bleVersion.trim(),
      if (pairSecret != null) base64Encode(pairSecret),
    ].join(':');

    final sha256 = Sha256();
    final hash = await sha256.hash(utf8.encode(components));
    final hashHex = hash.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    IoTShieldLogger.info(
      'Device fingerprint generated for $deviceId',
      meta: {'model': modelId, 'ble': bleVersion},
    );

    return DeviceFingerprint(
      hash: hashHex,
      deviceId: deviceId,
      firmwareVersion: firmwareVersion,
      modelId: modelId,
      bleVersion: bleVersion,
      createdAt: DateTime.now(),
    );
  }

  /// Verifies a [current] fingerprint against a [stored] one.
  /// Returns the appropriate [TrustLevel].
  static TrustLevel verify({
    required DeviceFingerprint stored,
    required DeviceFingerprint current,
  }) {
    // Device ID must always match
    if (stored.deviceId != current.deviceId) {
      IoTShieldLogger.alert(
        'Device ID mismatch — possible spoofing',
        meta: {
          'event': SecurityEventType.deviceFingerprintMismatch.name,
          'storedId': stored.deviceId,
          'currentId': current.deviceId,
        },
      );
      return TrustLevel.suspicious;
    }

    // Model must match
    if (stored.modelId != current.modelId) {
      IoTShieldLogger.alert(
        'Device model mismatch — possible spoofing or wrong device',
        meta: {
          'event': SecurityEventType.deviceFingerprintMismatch.name,
          'storedModel': stored.modelId,
          'currentModel': current.modelId,
        },
      );
      return TrustLevel.suspicious;
    }

    // Hash match = fully trusted
    if (stored.hash == current.hash) {
      IoTShieldLogger.info('Device fingerprint verified ✓', meta: {'deviceId': current.deviceId});
      return TrustLevel.trusted;
    }

    // Firmware changed but device ID and model match — expected after OTA
    if (stored.firmwareVersion != current.firmwareVersion) {
      IoTShieldLogger.info(
        'Firmware version changed — fingerprint will be updated',
        meta: {
          'event': SecurityEventType.deviceFingerprintCreated.name,
          'oldFw': stored.firmwareVersion,
          'newFw': current.firmwareVersion,
        },
      );
      return TrustLevel.firmwareChanged;
    }

    // Hash mismatch with same firmware — suspicious
    IoTShieldLogger.alert(
      'Fingerprint hash mismatch with unchanged firmware — suspicious device',
      meta: {'event': SecurityEventType.deviceFingerprintMismatch.name},
    );
    return TrustLevel.suspicious;
  }

  /// Serializes to a JSON-compatible map for secure storage.
  Map<String, dynamic> toJson() => {
        'hash': hash,
        'deviceId': deviceId,
        'firmwareVersion': firmwareVersion,
        'modelId': modelId,
        'bleVersion': bleVersion,
        'createdAt': createdAt.toIso8601String(),
      };

  /// Deserializes from stored JSON.
  factory DeviceFingerprint.fromJson(Map<String, dynamic> json) =>
      DeviceFingerprint(
        hash: json['hash'] as String,
        deviceId: json['deviceId'] as String,
        firmwareVersion: json['firmwareVersion'] as String,
        modelId: json['modelId'] as String,
        bleVersion: json['bleVersion'] as String? ?? '',
        createdAt: DateTime.parse(json['createdAt'] as String),
      );
}
