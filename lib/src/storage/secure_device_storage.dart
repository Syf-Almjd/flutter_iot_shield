// flutter_iot_shield/lib/src/storage/secure_device_storage.dart
//
// Secure storage for device identity, pairing secrets, and session metadata.
// Backed by Keychain (iOS) / EncryptedSharedPreferences (Android).

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../core/iot_shield_logger.dart';
import '../core/security_event.dart';

/// Stored identity record for a paired device.
class StoredDeviceIdentity {
  final String deviceId;
  final String deviceName;
  final String? modelId;
  final String? firmwareVersion;
  final String? bleVersion;
  final DateTime pairedAt;
  final DateTime? lastSeen;

  const StoredDeviceIdentity({
    required this.deviceId,
    required this.deviceName,
    this.modelId,
    this.firmwareVersion,
    this.bleVersion,
    required this.pairedAt,
    this.lastSeen,
  });

  Map<String, dynamic> toJson() => {
        'deviceId': deviceId,
        'deviceName': deviceName,
        'modelId': modelId,
        'firmwareVersion': firmwareVersion,
        'bleVersion': bleVersion,
        'pairedAt': pairedAt.toIso8601String(),
        'lastSeen': lastSeen?.toIso8601String(),
      };

  factory StoredDeviceIdentity.fromJson(Map<String, dynamic> j) =>
      StoredDeviceIdentity(
        deviceId: j['deviceId'] as String,
        deviceName: j['deviceName'] as String,
        modelId: j['modelId'] as String?,
        firmwareVersion: j['firmwareVersion'] as String?,
        bleVersion: j['bleVersion'] as String?,
        pairedAt: DateTime.parse(j['pairedAt'] as String),
        lastSeen: j['lastSeen'] != null
            ? DateTime.parse(j['lastSeen'] as String)
            : null,
      );
}

/// Secure key-value storage for IoT Shield data.
/// All values are stored encrypted via the platform's secure enclave.
class SecureDeviceStorage {
  static const _kDevicePrefix = 'iot_shield_dev_';
  static const _kLastActiveKey = 'iot_shield_last_active';
  static const _kMigrationDoneKey = 'iot_shield_migration_v1';

  final FlutterSecureStorage _storage;

  SecureDeviceStorage({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(
                accessibility: KeychainAccessibility.first_unlock_this_device,
              ),
            );

  // ─── Device identity ─────────────────────────────────────────────────────

  /// Stores a device identity record securely.
  Future<void> storeDeviceIdentity(StoredDeviceIdentity identity) async {
    await _storage.write(
      key: '$_kDevicePrefix${identity.deviceId}',
      value: jsonEncode(identity.toJson()),
    );
    await _markLastActive(identity.deviceId);
    IoTShieldLogger.info(
      'Device identity stored securely: ${identity.deviceId}',
      meta: {'event': SecurityEventType.storageInitialized.name},
    );
  }

  /// Reads a stored device identity by device ID.
  Future<StoredDeviceIdentity?> loadDeviceIdentity(String deviceId) async {
    try {
      final raw = await _storage.read(key: '$_kDevicePrefix$deviceId');
      if (raw == null || raw.isEmpty) return null;
      return StoredDeviceIdentity.fromJson(
          jsonDecode(raw) as Map<String, dynamic>);
    } catch (e) {
      IoTShieldLogger.warn('Failed to load device identity: $e');
      return null;
    }
  }

  /// Returns all stored device identities.
  Future<List<StoredDeviceIdentity>> loadAllDeviceIdentities() async {
    final all = await _storage.readAll();
    final result = <StoredDeviceIdentity>[];
    for (final entry in all.entries) {
      if (!entry.key.startsWith(_kDevicePrefix)) continue;
      try {
        final identity = StoredDeviceIdentity.fromJson(
            jsonDecode(entry.value) as Map<String, dynamic>);
        result.add(identity);
      } catch (_) {
        // Skip corrupted entries
      }
    }
    return result;
  }

  /// Updates the lastSeen timestamp for a device.
  Future<void> touchDevice(String deviceId) async {
    final existing = await loadDeviceIdentity(deviceId);
    if (existing == null) return;
    final updated = StoredDeviceIdentity(
      deviceId: existing.deviceId,
      deviceName: existing.deviceName,
      modelId: existing.modelId,
      firmwareVersion: existing.firmwareVersion,
      bleVersion: existing.bleVersion,
      pairedAt: existing.pairedAt,
      lastSeen: DateTime.now(),
    );
    await storeDeviceIdentity(updated);
  }

  /// Deletes a device identity record.
  Future<void> deleteDeviceIdentity(String deviceId) async {
    await _storage.delete(key: '$_kDevicePrefix$deviceId');
    final last = await getLastActiveDeviceId();
    if (last == deviceId) {
      await _storage.delete(key: _kLastActiveKey);
    }
    IoTShieldLogger.info('Device identity deleted: $deviceId');
  }

  // ─── Last active device ───────────────────────────────────────────────────

  Future<void> _markLastActive(String deviceId) async {
    await _storage.write(key: _kLastActiveKey, value: deviceId);
  }

  Future<String?> getLastActiveDeviceId() async {
    return _storage.read(key: _kLastActiveKey);
  }

  // ─── Generic secure key-value ─────────────────────────────────────────────

  Future<void> write(String key, String value) async {
    await _storage.write(key: 'iot_shield_kv_$key', value: value);
  }

  Future<String?> read(String key) async {
    return _storage.read(key: 'iot_shield_kv_$key');
  }

  Future<void> delete(String key) async {
    await _storage.delete(key: 'iot_shield_kv_$key');
  }

  // ─── Migration from SharedPreferences ────────────────────────────────────

  /// Migrates existing device data from SharedPreferences to secure storage.
  /// [prefs] should be a map of the existing SharedPreferences values.
  Future<void> migrateFromPrefs(Map<String, dynamic> prefs) async {
    final alreadyDone =
        await _storage.read(key: _kMigrationDoneKey) == 'true';
    if (alreadyDone) return;

    final deviceId = prefs['last_connected_device_id'] as String?;
    final deviceName =
        prefs['last_connected_device_name'] as String? ?? 'Unknown';

    if (deviceId != null && deviceId.isNotEmpty) {
      await storeDeviceIdentity(StoredDeviceIdentity(
        deviceId: deviceId,
        deviceName: deviceName,
        pairedAt: DateTime.now(),
      ));
      IoTShieldLogger.info(
        'Migrated device identity from SharedPreferences to secure storage',
        meta: {'event': SecurityEventType.storageMigrated.name},
      );
    }

    await _storage.write(key: _kMigrationDoneKey, value: 'true');
  }

  /// Clears all IoT Shield secure storage data.
  Future<void> clearAll() async {
    final all = await _storage.readAll();
    for (final key in all.keys) {
      if (key.startsWith('iot_shield_')) {
        await _storage.delete(key: key);
      }
    }
  }
}
