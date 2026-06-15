// flutter_iot_shield/lib/src/crypto/secure_random.dart

import 'dart:math';
import 'dart:typed_data';

/// Cryptographically secure random number generation.
class SecureRandom {
  static final Random _random = Random.secure();

  /// Generates [length] cryptographically secure random bytes.
  static Uint8List bytes(int length) {
    final result = Uint8List(length);
    for (var i = 0; i < length; i++) {
      result[i] = _random.nextInt(256);
    }
    return result;
  }

  /// Generates a random nonce of [length] bytes encoded as hex string.
  static String nonce({int length = 16}) {
    final b = bytes(length);
    return b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Generates a random integer in [0, max).
  static int nextInt(int max) => _random.nextInt(max);

  /// Generates a random 256-bit (32-byte) key as hex.
  static String key256() => nonce(length: 32);
}
