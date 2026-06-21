// flutter_iot_shield/lib/flutter_iot_shield.dart
// Public barrel file — the only import needed by consuming apps.

/// A robust, enterprise-grade IoT security layer for Flutter applications.
///
/// Provides end-to-end security utilities including:
/// - Cryptographically secure BLE session keys (ECDH + AES-256-GCM)
/// - Anti-replay sliding-window sequence tracking
/// - X.509 device identity attestation
/// - Secure platform channel sanitization
/// - Firmware package verification (anti-downgrade & ECDSA signatures)
/// - Local secure credentials storage
/// - Real-time security anomaly monitoring
library;

// Core
export 'src/core/iot_shield.dart';
export 'src/core/iot_shield_config.dart';
export 'src/core/iot_shield_logger.dart';
export 'src/core/security_event.dart';
export 'src/core/iot_secure_channel.dart';

// Attestation
export 'src/attestation/device_attestation.dart';
export 'src/attestation/x509_verifier.dart';

// Crypto
export 'src/crypto/session_key_manager.dart';
export 'src/crypto/packet_encryptor.dart';
export 'src/crypto/secure_random.dart';
export 'src/crypto/crypto_provider.dart';

// Identity
export 'src/identity/device_fingerprint.dart';
export 'src/identity/trust_manager.dart';

// Pairing
export 'src/pairing/secure_pairing_manager.dart';

// Firmware
export 'src/firmware/firmware_verifier.dart';

// Validation
export 'src/validation/health_data_validator.dart';
export 'src/validation/channel_sanitizer.dart';

// Storage
export 'src/storage/secure_device_storage.dart';
export 'src/storage/secure_key_store.dart';

// Monitoring
export 'src/monitoring/anomaly_detector.dart';
export 'src/monitoring/security_event_bus.dart';

// Replay
export 'src/replay/replay_protection.dart';

// Session
export 'src/session/secure_session.dart';

// Config
export 'src/config/iot_security_config.dart';

// Exceptions
export 'src/exceptions/security_exception.dart';
