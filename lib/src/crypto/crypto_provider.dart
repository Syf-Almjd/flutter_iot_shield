// flutter_iot_shield/lib/src/crypto/crypto_provider.dart

import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Wrapped key pair for cryptographic operations.
class CryptoKeyPair {
  final Uint8List publicKey;
  final SimpleKeyPair keyPair;

  const CryptoKeyPair({required this.publicKey, required this.keyPair});
}

/// Abstract interface for executing cryptographic algorithms.
abstract class CryptoProvider {
  /// Generates a local X25519 key pair for ECDH.
  Future<CryptoKeyPair> generateECDHKeyPair();

  /// Computes X25519 shared secret bytes.
  Future<Uint8List> computeSharedSecret(
      SimpleKeyPair myKeyPair, Uint8List theirPublicKey);

  /// Performs AES-256-GCM authenticated encryption.
  Future<Uint8List> encryptAES256GCM({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List plaintext,
    required Uint8List aad,
  });

  /// Performs AES-256-GCM authenticated decryption.
  Future<Uint8List> decryptAES256GCM({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List ciphertext,
    required Uint8List aad,
    required Uint8List tag,
  });

  /// Computes an HMAC-SHA256 hash.
  Future<Uint8List> hmacSHA256(
      {required Uint8List key, required Uint8List data});

  /// Verifies an Ed25519 or ECDSA-P256 signature.
  Future<bool> verifySignature({
    required Uint8List publicKey,
    required Uint8List data,
    required Uint8List signature,
  });

  /// Generates secure random bytes.
  Uint8List randomBytes(int length);
}

/// Default implementation of CryptoProvider using package:cryptography.
class DefaultCryptoProvider implements CryptoProvider {
  final _random = Random.secure();

  @override
  Future<CryptoKeyPair> generateECDHKeyPair() async {
    final algorithm = X25519();
    final keyPair = await algorithm.newKeyPair();
    final publicKey = await keyPair.extractPublicKey();
    return CryptoKeyPair(
      publicKey: Uint8List.fromList(publicKey.bytes),
      keyPair: keyPair,
    );
  }

  @override
  Future<Uint8List> computeSharedSecret(
      SimpleKeyPair myKeyPair, Uint8List theirPublicKey) async {
    final algorithm = X25519();
    final remotePublicKey =
        SimplePublicKey(theirPublicKey, type: KeyPairType.x25519);
    final sharedSecret = await algorithm.sharedSecretKey(
      keyPair: myKeyPair,
      remotePublicKey: remotePublicKey,
    );
    final bytes = await sharedSecret.extractBytes();
    return Uint8List.fromList(bytes);
  }

  @override
  Future<Uint8List> encryptAES256GCM({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List plaintext,
    required Uint8List aad,
  }) async {
    final algorithm = AesGcm.with256bits(nonceLength: 12);
    final secretKey = SecretKey(key);
    final box = await algorithm.encrypt(
      plaintext,
      secretKey: secretKey,
      nonce: iv,
      aad: aad,
    );
    // Combine ciphertext and tag (mac)
    final result = Uint8List(box.cipherText.length + box.mac.bytes.length);
    result.setAll(0, box.cipherText);
    result.setAll(box.cipherText.length, box.mac.bytes);
    return result;
  }

  @override
  Future<Uint8List> decryptAES256GCM({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List ciphertext,
    required Uint8List aad,
    required Uint8List tag,
  }) async {
    final algorithm = AesGcm.with256bits(nonceLength: 12);
    final secretKey = SecretKey(key);
    final box = SecretBox(ciphertext, nonce: iv, mac: Mac(tag));
    final plaintext = await algorithm.decrypt(
      box,
      secretKey: secretKey,
      aad: aad,
    );
    return Uint8List.fromList(plaintext);
  }

  @override
  Future<Uint8List> hmacSHA256(
      {required Uint8List key, required Uint8List data}) async {
    final algorithm = Hmac.sha256();
    final secretKey = SecretKey(key);
    final mac = await algorithm.calculateMac(data, secretKey: secretKey);
    return Uint8List.fromList(mac.bytes);
  }

  @override
  Future<bool> verifySignature({
    required Uint8List publicKey,
    required Uint8List data,
    required Uint8List signature,
  }) async {
    try {
      final algorithm = Ed25519();
      final remotePublicKey =
          SimplePublicKey(publicKey, type: KeyPairType.ed25519);
      final sig = Signature(signature, publicKey: remotePublicKey);
      return await algorithm.verify(data, signature: sig);
    } catch (_) {
      return false;
    }
  }

  @override
  Uint8List randomBytes(int length) {
    final result = Uint8List(length);
    for (var i = 0; i < length; i++) {
      result[i] = _random.nextInt(256);
    }
    return result;
  }
}
