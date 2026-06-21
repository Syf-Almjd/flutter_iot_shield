// flutter_iot_shield/lib/src/storage/secure_key_store.dart

import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Abstract secure key and certificate storage provider.
abstract class SecureKeyStore {
  Future<void> storeKey(String keyId, Uint8List key);
  Future<Uint8List?> retrieveKey(String keyId);
  Future<void> deleteKey(String keyId);
  Future<bool> containsKey(String keyId);
  Future<void> storeCertificate(String certId, String certificatePem);
  Future<String?> retrieveCertificate(String certId);
  Future<void> deleteCertificate(String certId);
}

/// Keychain/EncryptedSharedPreferences-backed secure key store.
class PlatformSecureKeyStore implements SecureKeyStore {
  final FlutterSecureStorage _storage;
  static const _keyPrefix = 'iot_sec_key_';
  static const _certPrefix = 'iot_sec_cert_';

  PlatformSecureKeyStore({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(),
              iOptions: IOSOptions(
                accessibility: KeychainAccessibility.first_unlock_this_device,
              ),
            );

  @override
  Future<void> storeKey(String keyId, Uint8List key) async {
    final encoded = base64Encode(key);
    await _storage.write(key: '$_keyPrefix$keyId', value: encoded);
  }

  @override
  Future<Uint8List?> retrieveKey(String keyId) async {
    final encoded = await _storage.read(key: '$_keyPrefix$keyId');
    if (encoded == null || encoded.isEmpty) return null;
    return base64Decode(encoded);
  }

  @override
  Future<void> deleteKey(String keyId) async {
    await _storage.delete(key: '$_keyPrefix$keyId');
  }

  @override
  Future<bool> containsKey(String keyId) async {
    final val = await _storage.read(key: '$_keyPrefix$keyId');
    return val != null && val.isNotEmpty;
  }

  @override
  Future<void> storeCertificate(String certId, String certificatePem) async {
    await _storage.write(key: '$_certPrefix$certId', value: certificatePem);
  }

  @override
  Future<String?> retrieveCertificate(String certId) async {
    return _storage.read(key: '$_certPrefix$certId');
  }

  @override
  Future<void> deleteCertificate(String certId) async {
    await _storage.delete(key: '$_certPrefix$certId');
  }
}
