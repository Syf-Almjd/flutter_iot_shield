// flutter_iot_shield/lib/src/core/iot_shield_config.dart

/// Configuration for the IoT Shield layer.
/// Pass one instance to [IoTShield.initialize] at app startup.
class IoTShieldConfig {
  /// Unique identifier for this app (typically the bundle/package ID).
  final String appId;

  /// PEM-encoded Ed25519 or RSA public key used to verify firmware signatures.
  /// Embed this in your app bundle — never fetch it from the network.
  /// Set to null to disable firmware signature verification (NOT recommended).
  final String? firmwarePublicKey;

  /// Certificate SHA-256 pins per hostname for firmware download verification.
  /// Format: { 'api.example.com': ['sha256/BASE64==', ...] }
  final Map<String, List<String>> certificatePins;

  /// Additional event types the app uses beyond the built-in set.
  final Set<String> extraValidEventTypes;

  /// Health validation bounds for sensor readings.
  final HealthValidationConfig healthValidation;

  /// How often session keys are rotated (null = no rotation).
  final Duration? sessionKeyRotation;

  /// Whether to enable BLE anomaly detection (scan frequency, reconnect storms).
  final bool enableAnomalyDetection;

  /// Whether to log security events to console (disable in production).
  final bool verboseLogging;

  const IoTShieldConfig({
    required this.appId,
    this.firmwarePublicKey,
    this.certificatePins = const {},
    this.extraValidEventTypes = const {},
    this.healthValidation = const HealthValidationConfig(),
    this.sessionKeyRotation,
    this.enableAnomalyDetection = true,
    this.verboseLogging = false,
  });
}

/// Physiological bounds for health data validation.
class HealthValidationConfig {
  final (int min, int max) heartRateRange;
  final (double min, double max) spo2Range;
  final (int min, int max) hrvRange;
  final (double min, double max) stressRange;
  final (double min, double max) temperatureRange; // Celsius

  const HealthValidationConfig({
    this.heartRateRange = (20, 300),
    this.spo2Range = (50.0, 100.0),
    this.hrvRange = (0, 500),
    this.stressRange = (0.0, 100.0),
    this.temperatureRange = (30.0, 43.0),
  });
}
