// flutter_iot_shield/lib/src/core/iot_secure_channel.dart

import 'dart:typed_data';
import '../config/iot_security_config.dart';
import '../session/secure_session.dart';
import '../crypto/packet_encryptor.dart';
import '../firmware/firmware_verifier.dart';
import '../attestation/device_attestation.dart';

/// Metadata for firmware verification.
class FirmwareMetadata {
  final String currentVersion;
  final String hardwareId;

  const FirmwareMetadata({
    required this.currentVersion,
    required this.hardwareId,
  });
}

/// Abstract contract representing the production secure channel interface.
abstract class IoTSecureChannel {
  /// Initializes the security layer with settings.
  Future<void> initializeSecurity(IoTSecurityConfig config);

  /// Performs secure pairing with the device (ECDH key exchange, attestation, pair code).
  Future<SecureSession> pairDevice(
    String deviceId,
    String deviceName, {
    required Uint8List devicePublicKey,
    required Uint8List deviceCertificateDer,
    required Uint8List challengeResponse,
    required Uint8List challengeNonce,
  });

  /// Encrypts outgoing plaintext payload.
  Future<SecurePacket> encrypt(
    Uint8List plaintext,
    String deviceId, {
    required int command,
    required int sequence,
  });

  /// Decrypts incoming secured packet.
  Future<Uint8List> decrypt(SecurePacket packet, String deviceId);

  /// Verifies a firmware package structure, version, and signature.
  Future<FirmwareVerificationResult> verifyFirmware(
    Uint8List firmwareImage,
    FirmwareMetadata metadata,
  );

  /// Performs device attestation.
  Future<AttestationResult> attestDevice({
    required String deviceId,
    required Uint8List deviceCertificateDer,
    required Uint8List challengeResponse,
    required Uint8List challengeNonce,
  });

  /// Returns the active session for a device.
  SecureSession? getActiveSession(String deviceId);

  /// Triggers session key rotation.
  Future<void> rotateKeys(String deviceId);

  /// Wipes all sensitive credentials from memory.
  Future<void> dispose();
}
