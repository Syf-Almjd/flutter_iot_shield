// flutter_iot_shield/lib/src/validation/channel_sanitizer.dart
//
// Guards the Flutter ↔ Native platform channel boundary.
// All events emitted by the native BLE layer pass through here before
// reaching the Flutter DeviceManager / BLoC layer.

import '../core/iot_shield_logger.dart';
import '../core/security_event.dart';
import 'health_data_validator.dart';

/// Sanitizes raw events from the native platform channel.
class ChannelSanitizer {
  final HealthDataValidator _healthValidator;
  final Set<String> _allowedTypes;

  ChannelSanitizer({
    HealthDataValidator? healthValidator,
    Set<String>? extraAllowedTypes,
  })  : _healthValidator = healthValidator ?? const HealthDataValidator(),
        _allowedTypes = {..._builtInAllowedTypes, ...?extraAllowedTypes};

  /// Sanitizes a raw native event.
  ///
  /// Returns null if the event should be dropped entirely.
  /// Returns a cleaned map if the event is acceptable.
  Map<String, dynamic>? sanitize(dynamic rawEvent) {
    if (rawEvent == null) return null;
    if (rawEvent is! Map) {
      IoTShieldLogger.warn(
        'Non-map event rejected from platform channel',
        meta: {
          'event': SecurityEventType.eventRejected.name,
          'type': rawEvent.runtimeType.toString()
        },
      );
      return null;
    }

    final event = <String, dynamic>{};
    try {
      // Safe cast — iterate and only include known-safe types
      rawEvent.forEach((key, value) {
        if (key is String) {
          event[key] = value;
        }
      });
    } catch (e) {
      IoTShieldLogger.warn('Failed to cast native event: $e');
      return null;
    }

    // 1. Type must be present and whitelisted
    final type = event['type'];
    if (type == null || type is! String || type.trim().isEmpty) {
      IoTShieldLogger.warn(
        'Event missing or invalid type field — rejected',
        meta: {'event': SecurityEventType.eventRejected.name},
      );
      return null;
    }

    if (!_allowedTypes.contains(type)) {
      IoTShieldLogger.warn(
        'Unknown event type "$type" rejected',
        meta: {
          'event': SecurityEventType.eventRejected.name,
          'rejectedType': type,
        },
      );
      return null;
    }

    // 2. Sanitize identifier fields (prevent injection via BLE names/addresses)
    for (final key in _identifierFields) {
      final val = event[key];
      if (val is String) {
        event[key] = _sanitizeIdentifier(val);
      }
    }

    // 3. Sanitize health numeric fields via HealthDataValidator
    final cleaned = _healthValidator.sanitizeEventMap(event);

    // 4. Remove any unexpected string fields that are too long (injection guard)
    for (final key in cleaned.keys.toList()) {
      final val = cleaned[key];
      if (val is String && val.length > 512) {
        IoTShieldLogger.warn(
          'Oversized string field "$key" (${val.length} chars) truncated',
          meta: {'event': SecurityEventType.eventSanitized.name},
        );
        cleaned[key] = val.substring(0, 512);
      }
    }

    return cleaned;
  }

  /// Sanitizes a BLE device identifier (MAC address or UUID).
  String _sanitizeIdentifier(String raw) {
    // Allow: hex chars, colons, hyphens, underscores
    return raw.replaceAll(RegExp(r'[^a-fA-F0-9:\-_\s]'), '').trim();
  }

  // ─── Allowed event types (complete set from the smart watch app) ──────────

  static const Set<String> _builtInAllowedTypes = {
    // Discovery
    'didDiscover',
    'scanStopped',
    // Connection
    'didConnected',
    'didDisconnected',
    'connectionStateChanged',
    'deviceConnected',
    'deviceDisconnected',
    // Pairing
    'pairingSuccess',
    'pairingFailed',
    'didReceivePairCode',
    'pairingCodeRequired',
    // Link protocol
    'didLinkAck',
    'didLinkFailed',
    'linkAck',
    'linkFailed',
    // Battery
    'batteryLevel',
    'battery',
    // Live health
    'hrLive',
    'hrvLive',
    'spo2Live',
    'ecgLive',
    'stressLive',
    'tempLive',
    // Sync events
    'syncActivity',
    'syncSleep',
    'syncRegularHeartRate',
    'syncRegularSpO2',
    'syncRegularHRV',
    'syncRegularStress',
    'syncRegularTemp',
    'syncWorkout',
    'syncComplete',
    'syncFailed',
    // Device info
    'deviceInfo',
    'deviceInfoReceived',
    'deviceInfoUpdated',
    // Calibration
    'handCalibrationProgress',
    'handCalibrationCompleted',
    'handCalibrationFailed',
    'calibrationProgress',
    'calibrationComplete',
    // Firmware OTA
    'fwProgress',
    'fwComplete',
    'fwError',
    'fwState',
    'fwStart',
    'fwWarning',
    // Settings sync
    'settingsSynced',
    'settingsUpdated',
    // Notifications
    'notificationSent',
    // Find my device
    'findWatchStarted',
    'findWatchStopped',
    'findPhoneRequest',
    // Security
    'securityAlert',
    // Generic
    'error',
    'info',
  };

  static const Set<String> _identifierFields = {
    'deviceId',
    'id',
    'address',
    'name',
    'uuid',
    'macAddress',
    'identifier',
    'peripheral',
  };
}
