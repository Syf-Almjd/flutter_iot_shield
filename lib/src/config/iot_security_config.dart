// flutter_iot_shield/lib/src/config/iot_security_config.dart

/// Key rotation policy settings.
class KeyRotationPolicy {
  final Duration rotateAfterDuration;
  final int rotateAfterPacketCount;

  const KeyRotationPolicy({
    this.rotateAfterDuration = const Duration(hours: 24),
    this.rotateAfterPacketCount = 10000,
  });
}

/// Main configuration model for IoTSecureChannel.
class IoTSecurityConfig {
  final String rootCaCertificate;
  final String firmwareSigningCa;
  final KeyRotationPolicy keyRotationPolicy;
  final int replayWindow;
  final bool enableEncryption;
  final bool enableAttestation;
  final bool enableFirmwareVerification;

  const IoTSecurityConfig({
    required this.rootCaCertificate,
    required this.firmwareSigningCa,
    this.keyRotationPolicy = const KeyRotationPolicy(),
    this.replayWindow = 100,
    this.enableEncryption = true,
    this.enableAttestation = true,
    this.enableFirmwareVerification = true,
  });
}
