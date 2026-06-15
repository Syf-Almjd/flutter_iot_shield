// flutter_iot_shield/lib/src/core/security_event.dart

/// All security events emitted by the IoT Shield layer.
enum SecurityEventType {
  // Identity events
  deviceTrusted,
  deviceSuspicious,
  deviceFingerprintCreated,
  deviceFingerprintMismatch,

  // Pairing events
  pairingStarted,
  pairingSuccess,
  pairingFailed,
  pairCodeMismatch,

  // Session events
  sessionKeyCreated,
  sessionKeyRotated,
  sessionExpired,

  // Communication events
  replayAttackDetected,
  invalidPacketRejected,
  anomalyDetected,

  // Validation events
  healthDataRejected,
  healthDataWarning,
  eventSanitized,
  eventRejected,

  // Firmware events
  firmwareVerified,
  firmwareSignatureInvalid,
  firmwareVersionDowngrade,
  firmwareTargetMismatch,
  dfuSpoofingAttempt,

  // Storage events
  storageInitialized,
  storageMigrated,

  // General
  info,
  warning,
  critical,
}

/// A security event emitted by the IoTShield layer.
class SecurityEvent {
  final SecurityEventType type;
  final String message;
  final Map<String, dynamic> metadata;
  final DateTime timestamp;
  final SecuritySeverity severity;

  const SecurityEvent({
    required this.type,
    required this.message,
    this.metadata = const {},
    required this.timestamp,
    required this.severity,
  });

  factory SecurityEvent.info(
    SecurityEventType type, {
    required String message,
    Map<String, dynamic> metadata = const {},
  }) =>
      SecurityEvent(
        type: type,
        message: message,
        metadata: metadata,
        timestamp: DateTime.now(),
        severity: SecuritySeverity.info,
      );

  factory SecurityEvent.warning(
    SecurityEventType type, {
    required String message,
    Map<String, dynamic> metadata = const {},
  }) =>
      SecurityEvent(
        type: type,
        message: message,
        metadata: metadata,
        timestamp: DateTime.now(),
        severity: SecuritySeverity.warning,
      );

  factory SecurityEvent.critical(
    SecurityEventType type, {
    required String message,
    Map<String, dynamic> metadata = const {},
  }) =>
      SecurityEvent(
        type: type,
        message: message,
        metadata: metadata,
        timestamp: DateTime.now(),
        severity: SecuritySeverity.critical,
      );

  @override
  String toString() =>
      '[IoTShield][${severity.name.toUpperCase()}] ${type.name}: $message';
}

enum SecuritySeverity { info, warning, critical }
