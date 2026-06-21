// flutter_iot_shield/lib/src/attestation/device_attestation.dart

import 'dart:convert';
import 'dart:typed_data';
import '../crypto/crypto_provider.dart';
import '../exceptions/security_exception.dart';
import 'x509_verifier.dart';

/// The result of a cryptographic device attestation attempt.
class AttestationResult {
  /// Whether the device attestation verification succeeded.
  final bool isValid;

  /// The reason why attestation failed, or null if successful.
  final String? reason;

  /// The parsed device certificate, or null if attestation failed.
  final X509Certificate? deviceCertificate;

  /// The device public key extracted from the certificate, or null if attestation failed.
  final Uint8List? devicePublicKey;

  /// Internal constructor for creating an [AttestationResult].
  const AttestationResult._(
      this.isValid, this.reason, this.deviceCertificate, this.devicePublicKey);

  /// Creates a successful [AttestationResult] containing the [deviceCertificate] and [devicePublicKey].
  factory AttestationResult.success({
    required X509Certificate deviceCertificate,
    required Uint8List devicePublicKey,
  }) =>
      AttestationResult._(true, null, deviceCertificate, devicePublicKey);

  /// Creates a failed [AttestationResult] with a specified failure [reason].
  factory AttestationResult.failure(String reason) =>
      AttestationResult._(false, reason, null, null);
}

/// Manages X.509 device identity verification.
class DeviceAttestationManager {
  final CryptoProvider _crypto;
  X509Certificate? _rootCA;

  // Basic Certificate Revocation List (CRL) of serial numbers
  final Set<String> _crl = {};

  DeviceAttestationManager({CryptoProvider? crypto})
      : _crypto = crypto ?? DefaultCryptoProvider();

  Future<void> initialize({required String rootCaPem}) async {
    _rootCA = X509Certificate.fromPem(rootCaPem);
  }

  /// Revokes a device certificate by serial number.
  void revokeCertificate(String serialNumber) {
    _crl.add(serialNumber.toLowerCase());
  }

  /// Verifies a reconnecting device's certificate and signature challenge.
  Future<AttestationResult> attestDevice({
    required String deviceId,
    required Uint8List deviceCertificateDer,
    required Uint8List challengeResponse,
    required Uint8List challengeNonce,
  }) async {
    try {
      if (_rootCA == null) {
        return AttestationResult.failure(
            'Attestation manager not initialized with Root CA.');
      }

      // 1. Parse device certificate
      final deviceCert = X509Certificate.fromDer(deviceCertificateDer);

      // 2. Check if certificate is revoked
      if (_crl.contains(deviceCert.serialNumber.toLowerCase())) {
        return AttestationResult.failure(
            'Device certificate is revoked in CRL.');
      }

      // 3. Verify Certificate Chain (Device Cert signed by Root CA)
      final chainValid = await _crypto.verifySignature(
        publicKey: _rootCA!.publicKeyBytes,
        data: deviceCert.tbsBytes,
        signature: deviceCert.signatureBytes,
      );
      if (!chainValid) {
        return AttestationResult.failure(
            'Certificate chain verification failed.');
      }

      // 4. Verify challenge response (Device signs [challengeNonce + deviceId] using its private key)
      final expectedPayload =
          Uint8List.fromList([...challengeNonce, ...utf8.encode(deviceId)]);
      final sigValid = await _crypto.verifySignature(
        publicKey: deviceCert.publicKeyBytes,
        data: expectedPayload,
        signature: challengeResponse,
      );
      if (!sigValid) {
        return AttestationResult.failure(
            'Challenge signature verification failed.');
      }

      return AttestationResult.success(
        deviceCertificate: deviceCert,
        devicePublicKey: deviceCert.publicKeyBytes,
      );
    } on IoTSecurityException catch (e) {
      return AttestationResult.failure(e.message);
    } catch (e) {
      return AttestationResult.failure(
          'Unexpected error during attestation: $e');
    }
  }
}
