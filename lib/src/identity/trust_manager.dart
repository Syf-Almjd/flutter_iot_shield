// flutter_iot_shield/lib/src/identity/trust_manager.dart
//
// Manages device fingerprints and enforces trust policies on reconnection.

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../core/iot_shield_logger.dart';
import '../core/security_event.dart';
import 'device_fingerprint.dart';

/// Manages device trust state — creating, verifying, and updating fingerprints.
class TrustManager {
  static const _kFingerprintPrefix = 'iot_shield_fp_';
  final FlutterSecureStorage _storage;

  TrustManager({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(
                accessibility: KeychainAccessibility.first_unlock_this_device,
              ),
            );

  /// Verifies a reconnecting device against its stored fingerprint.
  ///
  /// On first connection ([TrustLevel.unknown]), the fingerprint is created and stored.
  /// On [TrustLevel.firmwareChanged], the fingerprint is updated automatically.
  /// On [TrustLevel.suspicious], the caller should disconnect.
  Future<TrustLevel> verifyDevice({
    required String deviceId,
    required String modelId,
    required String firmwareVersion,
    required String bleVersion,
  }) async {
    final stored = await _loadFingerprint(deviceId);

    if (stored == null) {
      // First connection — create and store fingerprint
      final fp = await DeviceFingerprint.generate(
        deviceId: deviceId,
        firmwareVersion: firmwareVersion,
        modelId: modelId,
        bleVersion: bleVersion,
      );
      await _storeFingerprint(fp);
      IoTShieldLogger.info(
        'First connection — fingerprint created for $deviceId',
        meta: {'event': SecurityEventType.deviceFingerprintCreated.name},
      );
      return TrustLevel.unknown; // First time is always allowed
    }

    final current = await DeviceFingerprint.generate(
      deviceId: deviceId,
      firmwareVersion: firmwareVersion,
      modelId: modelId,
      bleVersion: bleVersion,
    );

    final level = DeviceFingerprint.verify(stored: stored, current: current);

    if (level == TrustLevel.firmwareChanged) {
      // Update stored fingerprint to reflect new firmware
      await _storeFingerprint(current);
    }

    return level;
  }

  /// Clears the stored fingerprint for a device (called on unpair).
  Future<void> clearFingerprint(String deviceId) async {
    await _storage.delete(key: '$_kFingerprintPrefix$deviceId');
    IoTShieldLogger.info('Fingerprint cleared for device $deviceId');
  }

  /// Clears all stored fingerprints.
  Future<void> clearAll() async {
    final all = await _storage.readAll();
    for (final key in all.keys) {
      if (key.startsWith(_kFingerprintPrefix)) {
        await _storage.delete(key: key);
      }
    }
  }

  Future<DeviceFingerprint?> _loadFingerprint(String deviceId) async {
    try {
      final raw = await _storage.read(key: '$_kFingerprintPrefix$deviceId');
      if (raw == null || raw.isEmpty) return null;
      return DeviceFingerprint.fromJson(jsonDecode(raw) as Map<String, dynamic>);
    } catch (e) {
      IoTShieldLogger.warn(
        'Failed to load fingerprint for $deviceId: $e',
        meta: {'event': SecurityEventType.warning.name},
      );
      return null;
    }
  }

  Future<void> _storeFingerprint(DeviceFingerprint fp) async {
    await _storage.write(
      key: '$_kFingerprintPrefix${fp.deviceId}',
      value: jsonEncode(fp.toJson()),
    );
  }
}
