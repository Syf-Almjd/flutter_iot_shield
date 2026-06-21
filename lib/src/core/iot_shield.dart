// flutter_iot_shield/lib/src/core/iot_shield.dart
//
// Main singleton entry point for the IoT Shield package.
// Initialize once in main.dart before runApp().

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' hide SecureRandom;

import '../config/iot_security_config.dart';
import '../session/secure_session.dart';
import '../crypto/crypto_provider.dart';
import '../storage/secure_key_store.dart';
import '../replay/replay_protection.dart';
import '../attestation/device_attestation.dart';
import '../exceptions/security_exception.dart';
import 'iot_secure_channel.dart';

import '../crypto/packet_encryptor.dart';
import '../crypto/session_key_manager.dart';
import '../firmware/firmware_verifier.dart';
import '../identity/device_fingerprint.dart';
import '../identity/trust_manager.dart';
import '../monitoring/anomaly_detector.dart';
import '../monitoring/security_event_bus.dart';
import '../pairing/secure_pairing_manager.dart';
import '../storage/secure_device_storage.dart';
import '../validation/channel_sanitizer.dart';
import '../validation/health_data_validator.dart';
import 'iot_shield_config.dart';
import 'iot_shield_logger.dart';
import 'security_event.dart';

export '../identity/device_fingerprint.dart' show TrustLevel;
export '../pairing/secure_pairing_manager.dart'
    show PairingResult, PairingSuccess, PairingMismatch, PairingRateLimited;
export '../firmware/firmware_verifier.dart'
    show FirmwareVerificationResult, FirmwareVerified, FirmwareRejected;
export '../validation/health_data_validator.dart'
    show ValidationResult, ValidationSeverity;
export '../crypto/packet_encryptor.dart'
    show SecurePacketEncryptor, ReplayAttackException, SecurePacket;
export '../crypto/session_key_manager.dart' show SecureSessionKey;
export '../config/iot_security_config.dart';
export '../session/secure_session.dart';
export '../crypto/crypto_provider.dart';
export '../storage/secure_key_store.dart';
export '../replay/replay_protection.dart';
export '../attestation/device_attestation.dart';
export '../exceptions/security_exception.dart';
export 'iot_secure_channel.dart';

/// Main singleton for the IoT Shield security layer.
///
/// **Initialize once in main.dart:**
/// ```dart
/// await IoTShield.instance.initialize(IoTShieldConfig(appId: 'com.your.app'));
/// ```
class IoTShield implements IoTSecureChannel {
  static final IoTShield instance = IoTShield._();
  IoTShield._();

  IoTShieldConfig? _config;
  bool _initialized = false;

  /// Returns the active configuration used to initialize the shield.
  IoTShieldConfig get config {
    _assertInitialized();
    return _config!;
  }

  // ─── Legacy Subsystems ─────────────────────────────────────────────────────
  late final TrustManager _trustManager;
  late final SecurePairingManager _pairingManager;
  late final SessionKeyManager _sessionKeyManager;
  late final FirmwareVerifier _firmwareVerifier;
  late final HealthDataValidator _healthValidator;
  late final ChannelSanitizer _channelSanitizer;
  late final SecureDeviceStorage _storage;
  late final AnomalyDetector _anomalyDetector;

  // Active session encryptors, keyed by deviceId (Legacy)
  final Map<String, SecurePacketEncryptor> _encryptors = {};

  // ─── Enterprise Secure Channel Subsystems ──────────────────────────────────
  late final CryptoProvider _cryptoProvider;
  late final SecureKeyStore _secureKeyStore;
  late final DeviceAttestationManager _attestationManager;
  late final ReplayProtection _replayProtection;
  late final IoTSecurityConfig _securityConfig;
  final Map<String, SecureSession> _sessions = {};

  // ─── Initialization ────────────────────────────────────────────────────────

  Future<void> initialize(IoTShieldConfig config) async {
    if (_initialized) return;
    _config = config;

    IoTShieldLogger.configure(verbose: config.verboseLogging);

    _trustManager = TrustManager();
    _pairingManager = SecurePairingManager();
    _sessionKeyManager = SessionKeyManager();
    _firmwareVerifier = FirmwareVerifier(publicKeyPem: config.firmwarePublicKey)
      ..currentDeviceModel = null;
    _healthValidator =
        HealthDataValidator(config: config.healthValidation);
    _channelSanitizer = ChannelSanitizer(
      healthValidator: _healthValidator,
      extraAllowedTypes: config.extraValidEventTypes,
    );
    _storage = SecureDeviceStorage();
    _anomalyDetector = AnomalyDetector();

    // Initialize the enterprise secure channel subsystems with default settings
    _cryptoProvider = DefaultCryptoProvider();
    _secureKeyStore = PlatformSecureKeyStore();
    _attestationManager = DeviceAttestationManager(crypto: _cryptoProvider);
    _replayProtection = ReplayProtection();
    _securityConfig = IoTSecurityConfig(
      rootCaCertificate: '',
      firmwareSigningCa: '',
      enableEncryption: config.sessionKeyRotation != null,
    );

    _initialized = true;
    IoTShieldLogger.info('IoTShield initialized for app: ${config.appId}');
    SecurityEventBus.instance.emitInfo(
      SecurityEventType.storageInitialized,
      message: 'IoTShield initialized',
      meta: {'appId': config.appId},
    );
  }

  @override
  Future<void> initializeSecurity(IoTSecurityConfig config) async {
    _securityConfig = config;
    await _attestationManager.initialize(rootCaPem: config.rootCaCertificate);
  }

  void _assertInitialized() {
    if (!_initialized) {
      throw StateError(
          'IoTShield not initialized. Call IoTShield.instance.initialize() first.');
    }
  }

  // ─── Device trust ──────────────────────────────────────────────────────────

  /// Verifies a connecting device's identity.
  /// Returns [TrustLevel] — caller must disconnect on [TrustLevel.suspicious].
  Future<TrustLevel> verifyDevice({
    required String deviceId,
    required Map<String, dynamic> deviceInfo,
  }) async {
    _assertInitialized();

    final model = _extractString(deviceInfo, ['model', 'modelId', 'name']) ?? '';
    final fw =
        _extractString(deviceInfo, ['firmwareVersion', 'firmware', 'version']) ??
            '';
    final ble =
        _extractString(deviceInfo, ['bleVersion', 'ble', 'bleVer']) ?? '';

    // Update firmware verifier with current device context
    _firmwareVerifier.currentDeviceModel = model.isEmpty ? null : model;
    _firmwareVerifier.currentFirmwareVersion = fw.isEmpty ? null : fw;

    final level = await _trustManager.verifyDevice(
      deviceId: deviceId,
      modelId: model,
      firmwareVersion: fw,
      bleVersion: ble,
    );

    if (level == TrustLevel.suspicious) {
      SecurityEventBus.instance.emitCritical(
        SecurityEventType.deviceSuspicious,
        message: 'Device $deviceId failed trust verification',
        meta: {'deviceId': deviceId, 'model': model},
      );
    } else {
      SecurityEventBus.instance.emitInfo(
        SecurityEventType.deviceTrusted,
        message: 'Device $deviceId verified (${level.name})',
        meta: {'deviceId': deviceId, 'trustLevel': level.name},
      );
    }

    return level;
  }

  /// Clears stored trust data for a device (call on unpair).
  Future<void> clearDeviceTrust(String deviceId) async {
    _assertInitialized();
    await _trustManager.clearFingerprint(deviceId);
    await _pairingManager.clearSecret(deviceId);
    _encryptors.remove(deviceId);
    _sessions.remove(deviceId);
    await _storage.deleteDeviceIdentity(deviceId);
    await _secureKeyStore.deleteKey('pair_secret_$deviceId');
  }

  // ─── Legacy Pairing ────────────────────────────────────────────────────────

  /// Validates a pair code entered by the user and stores the derived secret.
  Future<PairingResult> validatePairCode({
    required String deviceId,
    required String pairCode,
  }) async {
    _assertInitialized();
    return _pairingManager.validateAndStore(
      deviceId: deviceId,
      enteredCode: pairCode,
    );
  }

  // ─── Enterprise Cryptographic Secure Channel ────────────────────────────────

  @override
  Future<SecureSession> pairDevice(
    String deviceId,
    String deviceName, {
    required Uint8List devicePublicKey,
    required Uint8List deviceCertificateDer,
    required Uint8List challengeResponse,
    required Uint8List challengeNonce,
  }) async {
    _assertInitialized();

    // 1. Generate local key pair
    final localKeyPair = await _cryptoProvider.generateECDHKeyPair();

    // 2. Compute shared secret
    final sharedSecret = await _cryptoProvider.computeSharedSecret(
      localKeyPair.keyPair,
      devicePublicKey,
    );

    // 3. Attest device identity using certificate & challenge signature
    if (_securityConfig.enableAttestation) {
      final attestation = await attestDevice(
        deviceId: deviceId,
        deviceCertificateDer: deviceCertificateDer,
        challengeResponse: challengeResponse,
        challengeNonce: challengeNonce,
      );
      if (!attestation.isValid) {
        throw AttestationException(attestation.reason ?? 'Device attestation failed.');
      }
    }

    // 4. Derive symmetric session keys from the shared secret
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 128);
    final salt = Uint8List.fromList([...challengeNonce, ...devicePublicKey]);
    final info = utf8.encode('ble_session_v1');
    final derived = await hkdf.deriveKey(
      secretKey: SecretKey(sharedSecret),
      nonce: salt,
      info: info,
    );
    final keyMaterial = await derived.extractBytes();
    final encKey = Uint8List.fromList(keyMaterial.sublist(0, 32));
    final authKey = Uint8List.fromList(keyMaterial.sublist(32, 64));
    final ivKey = Uint8List.fromList(keyMaterial.sublist(64, 96));
    final rotKey = Uint8List.fromList(keyMaterial.sublist(96, 128));

    final session = SecureSession(
      sessionId: base64Encode(challengeNonce),
      deviceId: deviceId,
      encryptionKey: encKey,
      authKey: authKey,
      ivKey: ivKey,
      rotationKey: rotKey,
      createdAt: DateTime.now(),
    );

    _sessions[deviceId] = session;

    // Store the pairing secret securely
    await _secureKeyStore.storeKey('pair_secret_$deviceId', sharedSecret);

    SecurityEventBus.instance.emitInfo(
      SecurityEventType.pairingSuccess,
      message: 'Secure pairing established for $deviceId',
      meta: {'deviceId': deviceId, 'sessionId': session.sessionId},
    );

    return session;
  }

  @override
  Future<SecurePacket> encrypt(
    Uint8List plaintext,
    String deviceId, {
    required int command,
    required int sequence,
  }) async {
    _assertInitialized();
    final session = _sessions[deviceId];
    if (session == null) {
      throw const EncryptionException('No active cryptographic session found.');
    }

    // Rotate keys if key rotation policy dictates
    if (session.outboundCounter >= _securityConfig.keyRotationPolicy.rotateAfterPacketCount ||
        session.age >= _securityConfig.keyRotationPolicy.rotateAfterDuration) {
      await rotateKeys(deviceId);
    }

    final counter = session.incrementOutboundCounter();
    
    // Generate fresh IV/nonce
    final iv = _cryptoProvider.randomBytes(12);
    // Embed monotonic counter in big-endian in first 4 bytes
    iv[0] = (counter >> 24) & 0xFF;
    iv[1] = (counter >> 16) & 0xFF;
    iv[2] = (counter >> 8) & 0xFF;
    iv[3] = counter & 0xFF;

    final aad = Uint8List.fromList([command, sequence]);
    final encryptedResult = await _cryptoProvider.encryptAES256GCM(
      key: session.encryptionKey,
      iv: iv,
      plaintext: plaintext,
      aad: aad,
    );

    // Split cipherText and tag
    const tagLength = 16;
    final ciphertextLength = encryptedResult.length - tagLength;
    final ciphertext = encryptedResult.sublist(0, ciphertextLength);
    final tag = encryptedResult.sublist(ciphertextLength);

    return SecurePacket(
      command: command,
      sequence: sequence,
      encryptedPayload: ciphertext,
      nonce: iv,
      mac: tag,
      messageCounter: counter,
    );
  }

  @override
  Future<Uint8List> decrypt(SecurePacket packet, String deviceId) async {
    _assertInitialized();
    final session = _sessions[deviceId];
    if (session == null) {
      throw const EncryptionException('No active cryptographic session found.');
    }

    // Anti-replay protection sequence check
    final validSeq = _replayProtection.validateSequence(deviceId, packet.messageCounter);
    if (!validSeq) {
      throw ReplayAttackException(packet.messageCounter, session.lastInboundCounter + 1);
    }

    final aad = Uint8List.fromList([packet.command, packet.sequence]);
    final decrypted = await _cryptoProvider.decryptAES256GCM(
      key: session.encryptionKey,
      iv: packet.nonce,
      ciphertext: packet.encryptedPayload,
      aad: aad,
      tag: packet.mac,
    );

    session.setLastInboundCounter(packet.messageCounter);
    return decrypted;
  }

  @override
  Future<FirmwareVerificationResult> verifyFirmware(
    Uint8List firmwareImage,
    FirmwareMetadata metadata,
  ) async {
    _assertInitialized();
    // Wrap firmware bytes in a temp file or adapt existing verifier
    final tempDir = Directory.systemTemp;
    final tempFile = File('${tempDir.path}/temp_fw.zip');
    await tempFile.writeAsBytes(firmwareImage);
    
    _firmwareVerifier.currentFirmwareVersion = metadata.currentVersion;
    _firmwareVerifier.currentDeviceModel = metadata.hardwareId;
    
    final result = await _firmwareVerifier.verify(tempFile);
    
    try {
      await tempFile.delete();
    } catch (_) {}

    return result;
  }

  @override
  Future<AttestationResult> attestDevice({
    required String deviceId,
    required Uint8List deviceCertificateDer,
    required Uint8List challengeResponse,
    required Uint8List challengeNonce,
  }) async {
    _assertInitialized();
    return _attestationManager.attestDevice(
      deviceId: deviceId,
      deviceCertificateDer: deviceCertificateDer,
      challengeResponse: challengeResponse,
      challengeNonce: challengeNonce,
    );
  }

  @override
  SecureSession? getActiveSession(String deviceId) => _sessions[deviceId];

  @override
  Future<void> rotateKeys(String deviceId) async {
    _assertInitialized();
    final session = _sessions[deviceId];
    if (session == null) return;

    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 128);
    final salt = utf8.encode('rotation_salt_$deviceId');
    final info = utf8.encode('key_rotation_v1');
    final derived = await hkdf.deriveKey(
      secretKey: SecretKey(session.rotationKey),
      nonce: salt,
      info: info,
    );
    final keyMaterial = await derived.extractBytes();
    final encKey = Uint8List.fromList(keyMaterial.sublist(0, 32));
    final authKey = Uint8List.fromList(keyMaterial.sublist(32, 64));
    final ivKey = Uint8List.fromList(keyMaterial.sublist(64, 96));
    final rotKey = Uint8List.fromList(keyMaterial.sublist(96, 128));

    final newSession = SecureSession(
      sessionId: session.sessionId,
      deviceId: deviceId,
      encryptionKey: encKey,
      authKey: authKey,
      ivKey: ivKey,
      rotationKey: rotKey,
      createdAt: DateTime.now(),
    );

    newSession.resetCounters();
    newSession.incrementRotationCount();
    _sessions[deviceId] = newSession;

    // Reset sequence tracking
    _replayProtection.reset(deviceId);

    SecurityEventBus.instance.emitInfo(
      SecurityEventType.sessionKeyCreated,
      message: 'Session keys rotated for $deviceId',
      meta: {'deviceId': deviceId},
    );
  }

  @override
  Future<void> dispose() async {
    _sessions.clear();
    _encryptors.clear();
  }

  // ─── Legacy Session Management ─────────────────────────────────────────────

  /// Derives and activates a session key for a device after successful pairing.
  /// After this, [encryptorFor] returns the active encryptor.
  Future<SecureSessionKey> initializeSession({
    required String deviceId,
    List<int>? linkAckPayload,
  }) async {
    _assertInitialized();

    // Try to load pairing secret — fall back to identity-based key
    final storedSecret = await _pairingManager.loadSecret(deviceId);

    final SecureSessionKey sessionKey;
    if (storedSecret != null) {
      sessionKey = await _sessionKeyManager.deriveSessionKey(
        pairingSecret: storedSecret,
        deviceId: deviceId,
        rotation: _config?.sessionKeyRotation,
      );
    } else {
      // Fallback: identity-bound key (weaker but still better than nothing)
      sessionKey = await _sessionKeyManager.deriveFromDeviceIdentity(
        deviceId: deviceId,
        firmwareVersion: _firmwareVerifier.currentFirmwareVersion ?? 'unknown',
        appId: _config?.appId ?? 'unknown',
        rotation: _config?.sessionKeyRotation,
      );
    }

    _encryptors[deviceId] = SecurePacketEncryptor(sessionKey: sessionKey);

    SecurityEventBus.instance.emitInfo(
      SecurityEventType.sessionKeyCreated,
      message: 'Session key initialized for $deviceId',
      meta: {
        'deviceId': deviceId,
        'sessionId': sessionKey.sessionId,
        'hasPairingSecret': storedSecret != null,
      },
    );

    return sessionKey;
  }

  /// Returns the active [SecurePacketEncryptor] for a device, or null if none.
  SecurePacketEncryptor? encryptorFor(String deviceId) =>
      _encryptors[deviceId];

  // ─── Event sanitization ────────────────────────────────────────────────────

  /// Sanitizes a raw platform channel event.
  Map<String, dynamic>? sanitizeEvent(dynamic rawEvent) {
    _assertInitialized();
    return _channelSanitizer.sanitize(rawEvent);
  }

  // ─── Subsystem getters ─────────────────────────────────────────────────────

  HealthDataValidator get validator {
    _assertInitialized();
    return _healthValidator;
  }

  FirmwareVerifier get firmware {
    _assertInitialized();
    return _firmwareVerifier;
  }

  SecureDeviceStorage get storage {
    _assertInitialized();
    return _storage;
  }

  AnomalyDetector get anomalyDetector {
    _assertInitialized();
    return _anomalyDetector;
  }

  Stream<SecurityEvent> get securityEvents => SecurityEventBus.instance.stream;

  // ─── Helpers ──────────────────────────────────────────────────────────────

  String? _extractString(Map<String, dynamic> map, List<String> keys) {
    for (final k in keys) {
      final v = map[k];
      if (v is String && v.isNotEmpty) return v;
    }
    return null;
  }
}
