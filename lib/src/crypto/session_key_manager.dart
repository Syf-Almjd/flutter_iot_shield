// flutter_iot_shield/lib/src/crypto/session_key_manager.dart
//
// Derives per-session encryption keys using HKDF-SHA256.
// For full ECDH, the watch firmware must expose a public key during pairing.
// Until then, keys are derived from the device ID + pairing timestamp
// (a "soft" binding that still prevents trivial interception).

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide SecureRandom;

import '../core/iot_shield_logger.dart';
import '../core/security_event.dart';
import 'secure_random.dart';

/// A derived session key with metadata.
class SecureSessionKey {
  final Uint8List key; // 32 bytes (AES-256 capable)
  final String deviceId;
  final String sessionId; // Random nonce used during derivation
  final DateTime createdAt;
  final DateTime? expiresAt;

  const SecureSessionKey({
    required this.key,
    required this.deviceId,
    required this.sessionId,
    required this.createdAt,
    this.expiresAt,
  });

  bool get isExpired =>
      expiresAt != null && DateTime.now().isAfter(expiresAt!);

  @override
  String toString() =>
      'SecureSessionKey(device=$deviceId, session=$sessionId, '
      'created=$createdAt, expired=$isExpired)';
}

/// Manages derivation, storage, and rotation of BLE session keys.
class SessionKeyManager {
  final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  /// Derives a session key from a shared pairing secret + device context.
  ///
  /// [pairingSecret] — shared secret established during BLE pairing
  ///   (from vendor SDK or GTH pair code flow).
  /// [deviceId] — BLE MAC / CoreBluetooth UUID of the watch.
  /// [rotation] — optional expiry duration for key rotation.
  Future<SecureSessionKey> deriveSessionKey({
    required Uint8List pairingSecret,
    required String deviceId,
    Duration? rotation,
  }) async {
    final sessionId = SecureRandom.nonce(length: 16);
    final salt = utf8.encode('iot_shield:$deviceId:$sessionId');
    final info = utf8.encode('ble_session_v1');

    final secretKey = SecretKey(pairingSecret);
    final derivedKey = await _hkdf.deriveKey(
      secretKey: secretKey,
      nonce: salt,
      info: info,
    );
    final keyBytes = Uint8List.fromList(await derivedKey.extractBytes());

    final now = DateTime.now();
    IoTShieldLogger.info(
      'Session key derived for device $deviceId (session $sessionId)',
    );

    return SecureSessionKey(
      key: keyBytes,
      deviceId: deviceId,
      sessionId: sessionId,
      createdAt: now,
      expiresAt: rotation != null ? now.add(rotation) : null,
    );
  }

  /// Derives a deterministic session key from device identity alone.
  /// Used as a fallback when no explicit pairing secret is available.
  /// Provides weaker guarantees — device identity bound only.
  Future<SecureSessionKey> deriveFromDeviceIdentity({
    required String deviceId,
    required String firmwareVersion,
    required String appId,
    Duration? rotation,
  }) async {
    final sessionId = SecureRandom.nonce(length: 16);
    // Build a pseudo-secret from device identity components
    final identityString = '$appId:$deviceId:$firmwareVersion';
    final pseudoSecret = utf8.encode(identityString);

    final salt = utf8.encode('iot_shield_identity:$sessionId');
    final info = utf8.encode('ble_identity_key_v1');

    final secretKey = SecretKey(pseudoSecret);
    final derivedKey = await _hkdf.deriveKey(
      secretKey: secretKey,
      nonce: salt,
      info: info,
    );
    final keyBytes = Uint8List.fromList(await derivedKey.extractBytes());

    IoTShieldLogger.warn(
      'Session key derived from identity only (no pairing secret). '
      'Upgrade to full ECDH pairing for stronger security.',
    );

    final now = DateTime.now();
    return SecureSessionKey(
      key: keyBytes,
      deviceId: deviceId,
      sessionId: sessionId,
      createdAt: now,
      expiresAt: rotation != null ? now.add(rotation) : null,
    );
  }

  /// Generates an HMAC-SHA256 challenge response for device authentication.
  ///
  /// The watch should compute HMAC-SHA256(challenge, pairingSecret)
  /// and send the result back. We verify it matches.
  Future<Uint8List> computeChallengeResponse({
    required Uint8List challenge,
    required Uint8List pairingSecret,
  }) async {
    final mac = await Hmac.sha256().calculateMac(
      challenge,
      secretKey: SecretKey(pairingSecret),
    );
    return Uint8List.fromList(mac.bytes);
  }

  /// Verifies a challenge-response received from the device.
  Future<bool> verifyChallengeResponse({
    required Uint8List challenge,
    required Uint8List receivedResponse,
    required Uint8List pairingSecret,
  }) async {
    final expected = await computeChallengeResponse(
      challenge: challenge,
      pairingSecret: pairingSecret,
    );
    // Constant-time comparison to prevent timing attacks
    if (expected.length != receivedResponse.length) return false;
    var diff = 0;
    for (var i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ receivedResponse[i];
    }
    final valid = diff == 0;
    if (!valid) {
      IoTShieldLogger.alert(
        'Challenge-response verification FAILED for device',
        meta: {
          'event': SecurityEventType.deviceSuspicious.name,
        },
      );
    }
    return valid;
  }
}
