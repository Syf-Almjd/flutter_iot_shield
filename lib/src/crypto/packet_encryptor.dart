// flutter_iot_shield/lib/src/crypto/packet_encryptor.dart
//
// AES-256-GCM packet encryption with monotonic replay protection.
// Wraps raw BLE packet payloads before they are transmitted / after received.

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide SecureRandom;

import '../core/iot_shield_logger.dart';
import '../core/security_event.dart';
import 'session_key_manager.dart';
import 'secure_random.dart';

/// Exception thrown when a packet replay attack is detected.
class ReplayAttackException implements Exception {
  final int receivedCounter;
  final int expectedMinimum;

  const ReplayAttackException(this.receivedCounter, this.expectedMinimum);

  @override
  String toString() =>
      'ReplayAttackException: counter $receivedCounter <= expected minimum $expectedMinimum';
}

/// An encrypted packet wrapper ready for BLE transmission.
class SecurePacket {
  final int command;
  final int sequence;
  final Uint8List encryptedPayload; // AES-GCM ciphertext
  final Uint8List nonce; // 12-byte GCM nonce
  final Uint8List mac; // 16-byte GCM auth tag
  final int messageCounter; // Anti-replay monotonic counter

  const SecurePacket({
    required this.command,
    required this.sequence,
    required this.encryptedPayload,
    required this.nonce,
    required this.mac,
    required this.messageCounter,
  });

  /// Total bytes on the wire: [counter(4)] + [nonce(12)] + [mac(16)] + [ciphertext]
  int get wireSize => 4 + 12 + 16 + encryptedPayload.length;
}

/// Encrypts and decrypts BLE packet payloads using AES-256-GCM.
///
/// **Usage pattern:**
/// ```dart
/// // After pairing:
/// final encryptor = SecurePacketEncryptor(sessionKey: myKey);
///
/// // Sending:
/// final secure = await encryptor.encrypt(packet);
///
/// // Receiving:
/// final plain = await encryptor.decrypt(securePacket);
/// ```
class SecurePacketEncryptor {
  final SecureSessionKey sessionKey;
  final _algo = AesGcm.with256bits(nonceLength: 12);

  int _outboundCounter = 0;
  int _lastInboundCounter = -1;

  SecurePacketEncryptor({required this.sessionKey});

  bool get isSessionExpired => sessionKey.isExpired;

  /// Encrypts a raw payload for BLE transmission.
  ///
  /// [command] and [sequence] are used as Additional Authenticated Data (AAD)
  /// so tampering with the header is detectable.
  Future<SecurePacket> encrypt({
    required int command,
    required int sequence,
    required Uint8List payload,
  }) async {
    if (isSessionExpired) {
      throw StateError('Session key has expired. Rotate the key first.');
    }

    final counter = _outboundCounter++;
    final nonce = _buildNonce(counter);
    final aad = Uint8List.fromList([command, sequence]);

    final secretKey = SecretKey(sessionKey.key);
    final box = await _algo.encrypt(
      payload,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );

    return SecurePacket(
      command: command,
      sequence: sequence,
      encryptedPayload: Uint8List.fromList(box.cipherText),
      nonce: nonce,
      mac: Uint8List.fromList(box.mac.bytes),
      messageCounter: counter,
    );
  }

  /// Decrypts a received secure packet.
  ///
  /// Throws [ReplayAttackException] if the counter is not increasing.
  /// Throws [SecretBoxAuthenticationError] if the MAC is invalid (tampering).
  Future<Uint8List> decrypt(SecurePacket packet) async {
    // Replay protection: counter must be strictly increasing
    if (packet.messageCounter <= _lastInboundCounter) {
      IoTShieldLogger.alert(
        'Replay attack detected!',
        meta: {
          'event': SecurityEventType.replayAttackDetected.name,
          'receivedCounter': packet.messageCounter,
          'expectedMin': _lastInboundCounter + 1,
        },
      );
      throw ReplayAttackException(
        packet.messageCounter,
        _lastInboundCounter + 1,
      );
    }

    final aad = Uint8List.fromList([packet.command, packet.sequence]);
    final secretKey = SecretKey(sessionKey.key);

    final box = SecretBox(
      packet.encryptedPayload,
      nonce: packet.nonce,
      mac: Mac(packet.mac),
    );

    final plaintext = await _algo.decrypt(box, secretKey: secretKey, aad: aad);
    _lastInboundCounter = packet.messageCounter;
    return Uint8List.fromList(plaintext);
  }

  /// Resets counters — call after key rotation only.
  void resetCounters() {
    _outboundCounter = 0;
    _lastInboundCounter = -1;
  }

  /// Builds a 12-byte GCM nonce from the monotonic counter + random salt.
  /// First 4 bytes = counter (big-endian), last 8 bytes = random.
  Uint8List _buildNonce(int counter) {
    final nonce = SecureRandom.bytes(12);
    // Embed counter in first 4 bytes (big-endian)
    nonce[0] = (counter >> 24) & 0xFF;
    nonce[1] = (counter >> 16) & 0xFF;
    nonce[2] = (counter >> 8) & 0xFF;
    nonce[3] = counter & 0xFF;
    return nonce;
  }
}
