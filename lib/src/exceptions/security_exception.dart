// flutter_iot_shield/lib/src/exceptions/security_exception.dart

/// Base exception for all security-related errors.
abstract class IoTSecurityException implements Exception {
  final String message;
  final String? code;
  final dynamic originalError;

  const IoTSecurityException(this.message, {this.code, this.originalError});

  @override
  String toString() => '$runtimeType: $message${code != null ? ' (Code: $code)' : ''}';
}

/// Thrown when device attestation fails.
class AttestationException extends IoTSecurityException {
  const AttestationException(super.message, {super.code, super.originalError});
}

/// Thrown when encryption or decryption fails.
class EncryptionException extends IoTSecurityException {
  const EncryptionException(super.message, {super.code, super.originalError});
}

/// Thrown when pairing fails.
class PairingFailedException extends IoTSecurityException {
  final PairingFailureReason reason;
  const PairingFailedException(super.message, {required this.reason, super.code, super.originalError});
}

/// Reasons why a pairing process might fail.
enum PairingFailureReason {
  keyExchangeFailed,
  attestationFailed,
  pairCodeRejected,
  rateLimited,
  timeout,
  unknown,
}
