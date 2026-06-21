// flutter_iot_shield/test/iot_security_test.dart

import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_iot_shield/flutter_iot_shield.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('CryptoProvider & DefaultCryptoProvider', () {
    late CryptoProvider crypto;

    setUp(() {
      crypto = DefaultCryptoProvider();
    });

    test('ECDH Key Generation and Shared Secret Computation', () async {
      final keyPairA = await crypto.generateECDHKeyPair();
      final keyPairB = await crypto.generateECDHKeyPair();

      expect(keyPairA.publicKey, isNotEmpty);
      expect(keyPairB.publicKey, isNotEmpty);

      final secretA = await crypto.computeSharedSecret(
          keyPairA.keyPair, keyPairB.publicKey);
      final secretB = await crypto.computeSharedSecret(
          keyPairB.keyPair, keyPairA.publicKey);

      expect(secretA, equals(secretB));
      expect(secretA.length, 32);
    });

    test('AES-256-GCM Encrypt & Decrypt', () async {
      final key = crypto.randomBytes(32);
      final iv = crypto.randomBytes(12);
      final aad = Uint8List.fromList(utf8.encode('associated_data'));
      final plaintext =
          Uint8List.fromList(utf8.encode('Hello World! Enterprise Security.'));

      final encrypted = await crypto.encryptAES256GCM(
        key: key,
        iv: iv,
        plaintext: plaintext,
        aad: aad,
      );

      expect(encrypted, isNotEmpty);

      // AES-GCM returns ciphertext + 16 bytes authentication tag
      const tagLength = 16;
      final cipherText = encrypted.sublist(0, encrypted.length - tagLength);
      final tag = encrypted.sublist(encrypted.length - tagLength);

      final decrypted = await crypto.decryptAES256GCM(
        key: key,
        iv: iv,
        ciphertext: cipherText,
        aad: aad,
        tag: tag,
      );

      expect(decrypted, equals(plaintext));
      expect(utf8.decode(decrypted), 'Hello World! Enterprise Security.');
    });

    test('HMAC-SHA256 Computation', () async {
      final key = crypto.randomBytes(32);
      final data = Uint8List.fromList(utf8.encode('Sensitive message'));

      final hmacVal = await crypto.hmacSHA256(key: key, data: data);
      expect(hmacVal.length, 32);

      // Verify that same input generates same HMAC
      final hmacVal2 = await crypto.hmacSHA256(key: key, data: data);
      expect(hmacVal, equals(hmacVal2));
    });
  });

  group('ReplayProtection (Sliding Window)', () {
    late ReplayProtection rp;
    const deviceId = 'test-device-uuid-123';

    setUp(() {
      rp = ReplayProtection(windowSize: 10);
    });

    test('Accepts strictly increasing sequences', () {
      expect(rp.validateSequence(deviceId, 0), isTrue);
      expect(rp.validateSequence(deviceId, 1), isTrue);
      expect(rp.validateSequence(deviceId, 2), isTrue);
    });

    test('Accepts out of order packets within window', () {
      expect(rp.validateSequence(deviceId, 5), isTrue);
      expect(rp.validateSequence(deviceId, 3), isTrue); // Within window
      expect(rp.validateSequence(deviceId, 4), isTrue); // Within window
    });

    test('Rejects duplicate/replayed packets', () {
      expect(rp.validateSequence(deviceId, 5), isTrue);
      expect(rp.validateSequence(deviceId, 5), isFalse); // Replayed!
      expect(rp.validateSequence(deviceId, 3), isTrue);
      expect(rp.validateSequence(deviceId, 3), isFalse); // Replayed!
    });

    test('Rejects packets too old (outside window)', () {
      expect(rp.validateSequence(deviceId, 15),
          isTrue); // Max is now 15. Window is [6, 15]
      expect(
          rp.validateSequence(deviceId, 5), isFalse); // Too old! (<= 15 - 10)
      expect(rp.validateSequence(deviceId, 6), isTrue); // Edge of window, valid
      expect(rp.validateSequence(deviceId, 4), isFalse); // Too old!
    });
  });

  group('SecureSession lifecycle', () {
    test('Session initialization properties', () {
      final encKey = Uint8List(32);
      final authKey = Uint8List(32);
      final ivKey = Uint8List(32);
      final rotKey = Uint8List(32);

      final session = SecureSession(
        sessionId: 'session-id',
        deviceId: 'device-id',
        encryptionKey: encKey,
        authKey: authKey,
        ivKey: ivKey,
        rotationKey: rotKey,
        createdAt: DateTime.now(),
      );

      expect(session.sessionId, 'session-id');
      expect(session.deviceId, 'device-id');
      expect(session.outboundCounter, 0);
      expect(session.lastInboundCounter, -1);

      final count = session.incrementOutboundCounter();
      expect(count, 0);
      expect(session.outboundCounter, 1);
    });
  });
}
