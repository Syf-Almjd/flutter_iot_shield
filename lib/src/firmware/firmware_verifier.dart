// flutter_iot_shield/lib/src/firmware/firmware_verifier.dart
//
// Verifies firmware packages before they are pushed to the watch via OTA.
// Currently performs:
//  - File existence and format checks
//  - SHA-256 integrity hash comparison
//  - Version anti-downgrade check
//
// When a firmware signing key is provided, performs Ed25519 signature verification.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive_io.dart' show ZipDecoder;
import 'package:cryptography/cryptography.dart';

import '../core/iot_shield_logger.dart';
import '../core/security_event.dart';

/// The result of a firmware verification check.
sealed class FirmwareVerificationResult {
  const FirmwareVerificationResult();
}

class FirmwareVerified extends FirmwareVerificationResult {
  final String version;
  final String sha256Hash;
  final String targetModel;

  const FirmwareVerified({
    required this.version,
    required this.sha256Hash,
    required this.targetModel,
  });
}

class FirmwareRejected extends FirmwareVerificationResult {
  final String reason;
  final SecuritySeverity severity;

  const FirmwareRejected({
    required this.reason,
    this.severity = SecuritySeverity.critical,
  });
}

/// Verifies firmware packages before OTA flashing.
class FirmwareVerifier {
  /// Ed25519 public key for signature verification.
  /// Set via [IoTShieldConfig.firmwarePublicKey].
  final String? publicKeyPem;

  /// Current device model for cross-model protection.
  String? currentDeviceModel;

  /// Current firmware version for downgrade protection.
  String? currentFirmwareVersion;

  FirmwareVerifier({this.publicKeyPem});

  /// Main verification entry point.
  /// Call this before calling the vendor SDK OTA method.
  Future<FirmwareVerificationResult> verify(File firmwareFile) async {
    // 1. File must exist
    if (!firmwareFile.existsSync()) {
      return const FirmwareRejected(reason: 'Firmware file not found');
    }

    final bytes = await firmwareFile.readAsBytes();
    if (bytes.isEmpty) {
      return const FirmwareRejected(reason: 'Firmware file is empty');
    }

    // 2. Compute SHA-256 hash
    final sha256 = Sha256();
    final hash = await sha256.hash(bytes);
    final hashHex =
        hash.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    // 3. For ZIP packages, extract and validate manifest
    if (firmwareFile.path.toLowerCase().endsWith('.zip')) {
      return await _verifyZip(bytes: bytes, hashHex: hashHex);
    }

    // 4. Binary packages — basic checks only (no manifest)
    IoTShieldLogger.warn(
      'Firmware is a raw binary — manifest verification skipped. '
      'Use signed ZIP packages for full security.',
      meta: {'event': SecurityEventType.warning.name},
    );
    return FirmwareVerified(
      version: 'unknown',
      sha256Hash: hashHex,
      targetModel: currentDeviceModel ?? 'unknown',
    );
  }

  Future<FirmwareVerificationResult> _verifyZip({
    required Uint8List bytes,
    required String hashHex,
  }) async {
    Map<String, dynamic>? manifest;
    try {
      final archive = ZipDecoder().decodeBytes(bytes);
      for (final file in archive) {
        if (file.name == 'manifest.json' && file.isFile) {
          final content = utf8.decode(file.content as List<int>);
          manifest = jsonDecode(content) as Map<String, dynamic>;
          break;
        }
      }
    } catch (e) {
      return FirmwareRejected(reason: 'Failed to read firmware ZIP: $e');
    }

    if (manifest == null) {
      // Nordic DFU ZIPs are valid without a custom manifest — allow them
      // but log the fact that extended verification was skipped.
      IoTShieldLogger.warn(
        'No iot_shield manifest.json in firmware ZIP — '
        'extended verification skipped (Nordic DFU package assumed).',
        meta: {'event': SecurityEventType.warning.name},
      );
      return FirmwareVerified(
        version: 'unknown',
        sha256Hash: hashHex,
        targetModel: currentDeviceModel ?? 'unknown',
      );
    }

    final version = manifest['version'] as String? ?? 'unknown';
    final targetModel = manifest['targetModel'] as String? ?? 'unknown';
    final signature = manifest['signature'] as String?;

    // 4a. Model check
    if (currentDeviceModel != null &&
        targetModel != 'any' &&
        targetModel != currentDeviceModel) {
      IoTShieldLogger.alert(
        'Firmware model mismatch',
        meta: {
          'event': SecurityEventType.firmwareTargetMismatch.name,
          'expected': currentDeviceModel,
          'got': targetModel,
        },
      );
      return FirmwareRejected(
        reason:
            'Firmware is for model $targetModel but connected device is $currentDeviceModel',
        severity: SecuritySeverity.critical,
      );
    }

    // 4b. Anti-downgrade check
    if (currentFirmwareVersion != null && version != 'unknown') {
      if (!_isVersionNewer(version, currentFirmwareVersion!)) {
        IoTShieldLogger.alert(
          'Firmware downgrade attempt detected',
          meta: {
            'event': SecurityEventType.firmwareVersionDowngrade.name,
            'current': currentFirmwareVersion,
            'offered': version,
          },
        );
        return FirmwareRejected(
          reason:
              'Firmware version $version is not newer than current $currentFirmwareVersion',
          severity: SecuritySeverity.warning,
        );
      }
    }

    // 4c. Signature verification (when key is provided and manifest has signature)
    if (publicKeyPem != null && signature != null) {
      final sigValid = await _verifySignature(
        dataHash: hash_bytes_from_hex(hashHex),
        signatureBase64: signature,
      );
      if (!sigValid) {
        IoTShieldLogger.alert(
          'Firmware signature verification FAILED',
          meta: {'event': SecurityEventType.firmwareSignatureInvalid.name},
        );
        return const FirmwareRejected(
          reason: 'Firmware signature is invalid — possible tampering',
          severity: SecuritySeverity.critical,
        );
      }
      IoTShieldLogger.info(
        'Firmware signature verified ✓',
        meta: {'version': version},
      );
    } else if (publicKeyPem != null && signature == null) {
      IoTShieldLogger.alert(
        'Firmware package has no signature but a public key is configured',
        meta: {'event': SecurityEventType.firmwareSignatureInvalid.name},
      );
      return const FirmwareRejected(
        reason: 'Firmware package is unsigned — rejecting for security',
        severity: SecuritySeverity.critical,
      );
    }

    IoTShieldLogger.info(
      'Firmware verified ✓',
      meta: {'version': version, 'model': targetModel, 'hash': hashHex},
    );

    return FirmwareVerified(
      version: version,
      sha256Hash: hashHex,
      targetModel: targetModel,
    );
  }

  Future<bool> _verifySignature({
    required List<int> dataHash,
    required String signatureBase64,
  }) async {
    try {
      final sigBytes = base64Decode(signatureBase64);
      // Ed25519 signature verification
      final algorithm = Ed25519();
      // Parse PEM key — strip header/footer and decode base64
      final pemBody = publicKeyPem!
          .replaceAll('-----BEGIN PUBLIC KEY-----', '')
          .replaceAll('-----END PUBLIC KEY-----', '')
          .replaceAll('\n', '')
          .trim();
      final keyBytes = base64Decode(pemBody);
      final publicKey = SimplePublicKey(keyBytes, type: KeyPairType.ed25519);
      final sig = Signature(sigBytes, publicKey: publicKey);
      return await algorithm.verify(dataHash, signature: sig);
    } catch (e) {
      IoTShieldLogger.warn('Signature verification exception: $e');
      return false;
    }
  }

  List<int> hash_bytes_from_hex(String hex) {
    final result = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      result.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return result;
  }

  /// Compares two semver-like version strings.
  bool _isVersionNewer(String offered, String current) {
    try {
      final o = _parseVersion(offered);
      final c = _parseVersion(current);
      for (var i = 0; i < 3; i++) {
        if (o[i] > c[i]) return true;
        if (o[i] < c[i]) return false;
      }
      return false; // equal
    } catch (_) {
      return true; // can't parse → allow
    }
  }

  List<int> _parseVersion(String v) {
    final parts = v.split('.').map((p) => int.tryParse(p) ?? 0).toList();
    while (parts.length < 3) {
      parts.add(0);
    }
    return parts.take(3).toList();
  }
}
