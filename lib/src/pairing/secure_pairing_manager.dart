// flutter_iot_shield/lib/src/pairing/secure_pairing_manager.dart
//
// Enhances the GTH/vendor pairing flow with:
//  - Cryptographic binding of pair codes to device identity
//  - Secure storage of pairing secrets
//  - Brute-force resistance (rate limiting)

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../core/iot_shield_logger.dart';
import '../core/security_event.dart';

/// Result of a pairing attempt.
sealed class PairingResult {
  const PairingResult();
}

class PairingSuccess extends PairingResult {
  final Uint8List pairingSecret;
  final String deviceId;
  const PairingSuccess({required this.pairingSecret, required this.deviceId});
}

class PairingMismatch extends PairingResult {
  final String reason;
  const PairingMismatch({required this.reason});
}

class PairingRateLimited extends PairingResult {
  final Duration retryAfter;
  const PairingRateLimited({required this.retryAfter});
}

/// Manages the secure pairing handshake with IoT devices.
class SecurePairingManager {
  static const _kSecretPrefix = 'iot_shield_pair_';
  static const _maxAttemptsPerWindow = 5;
  static const _rateLimitWindow = Duration(minutes: 5);

  final FlutterSecureStorage _storage;

  // Per-device attempt tracking (in-memory, clears on app restart)
  final Map<String, List<DateTime>> _attemptTimestamps = {};

  SecurePairingManager({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(
                accessibility: KeychainAccessibility.first_unlock_this_device,
              ),
            );

  /// Validates a pair code and generates a pairing secret if valid.
  ///
  /// [enteredCode] is what the user typed / was displayed on the watch.
  /// [deviceId] is the BLE identifier of the watch.
  /// [deviceSalt] is an optional device-provided salt for code derivation.
  ///
  /// In the current GTH SDK, the pair code is user-visible on the watch face.
  /// This method stores a deterministic secret derived from the code + device
  /// identity, so future connections can re-derive the same secret.
  Future<PairingResult> validateAndStore({
    required String deviceId,
    required String enteredCode,
    Uint8List? deviceSalt,
  }) async {
    // Rate limiting
    if (_isRateLimited(deviceId)) {
      final retryAfter = _retryAfter(deviceId);
      IoTShieldLogger.warn(
        'Pairing rate limit hit for $deviceId',
        meta: {'event': SecurityEventType.pairingFailed.name},
      );
      return PairingRateLimited(retryAfter: retryAfter);
    }

    _recordAttempt(deviceId);

    // Basic format check
    if (!_isValidFormat(enteredCode)) {
      IoTShieldLogger.warn(
        'Invalid pair code format for $deviceId',
        meta: {'event': SecurityEventType.pairCodeMismatch.name},
      );
      return const PairingMismatch(
        reason: 'Invalid pair code format. Please enter a 6-digit code.',
      );
    }

    // Derive a pairing secret from the code + device identity
    final secret = await _derivePairingSecret(
      deviceId: deviceId,
      pairCode: enteredCode,
      salt: deviceSalt,
    );

    // Store securely for future session key derivation
    await _storeSecret(deviceId: deviceId, secret: secret);

    IoTShieldLogger.info(
      'Pairing secret stored for $deviceId',
      meta: {'event': SecurityEventType.pairingSuccess.name},
    );

    return PairingSuccess(pairingSecret: secret, deviceId: deviceId);
  }

  /// Retrieves the stored pairing secret for a device.
  /// Returns null if no secret is stored (device not paired).
  Future<Uint8List?> loadSecret(String deviceId) async {
    try {
      final raw = await _storage.read(key: '$_kSecretPrefix$deviceId');
      if (raw == null) return null;
      return Uint8List.fromList(base64Decode(raw));
    } catch (_) {
      return null;
    }
  }

  /// Removes the stored pairing secret (called on unpair).
  Future<void> clearSecret(String deviceId) async {
    await _storage.delete(key: '$_kSecretPrefix$deviceId');
    _attemptTimestamps.remove(deviceId);
  }

  // ─── Private helpers ───────────────────────────────────────────────────────

  bool _isValidFormat(String code) =>
      code.length == 6 && RegExp(r'^\d{6}$').hasMatch(code);

  Future<Uint8List> _derivePairingSecret({
    required String deviceId,
    required String pairCode,
    Uint8List? salt,
  }) async {
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
    final inputKey = utf8.encode('$deviceId:$pairCode');
    final effectiveSalt = salt ?? utf8.encode('iot_shield_pair:$deviceId');

    final derived = await hkdf.deriveKey(
      secretKey: SecretKey(inputKey),
      nonce: effectiveSalt,
      info: utf8.encode('pair_secret_v1'),
    );
    return Uint8List.fromList(await derived.extractBytes());
  }

  Future<void> _storeSecret({
    required String deviceId,
    required Uint8List secret,
  }) async {
    await _storage.write(
      key: '$_kSecretPrefix$deviceId',
      value: base64Encode(secret),
    );
  }

  void _recordAttempt(String deviceId) {
    _attemptTimestamps.putIfAbsent(deviceId, () => []);
    _attemptTimestamps[deviceId]!.add(DateTime.now());
  }

  bool _isRateLimited(String deviceId) {
    final timestamps = _attemptTimestamps[deviceId] ?? [];
    final window = DateTime.now().subtract(_rateLimitWindow);
    final recent = timestamps.where((t) => t.isAfter(window)).toList();
    _attemptTimestamps[deviceId] = recent;
    return recent.length >= _maxAttemptsPerWindow;
  }

  Duration _retryAfter(String deviceId) {
    final timestamps = _attemptTimestamps[deviceId] ?? [];
    if (timestamps.isEmpty) return Duration.zero;
    final oldest = timestamps.reduce((a, b) => a.isBefore(b) ? a : b);
    final unlockAt = oldest.add(_rateLimitWindow);
    final remaining = unlockAt.difference(DateTime.now());
    return remaining.isNegative ? Duration.zero : remaining;
  }
}
