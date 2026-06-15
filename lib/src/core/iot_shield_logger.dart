// flutter_iot_shield/lib/src/core/iot_shield_logger.dart

import 'dart:developer' as dev;
import 'security_event.dart';

/// Internal logger for the IoT Shield layer.
/// Consumers can listen to [IoTShieldLogger.events] for structured events.
class IoTShieldLogger {
  IoTShieldLogger._();

  static bool _verbose = false;

  static void configure({required bool verbose}) {
    _verbose = verbose;
  }

  static void info(String message, {Map<String, dynamic>? meta}) {
    _log('INFO', message, meta);
  }

  static void warn(String message, {Map<String, dynamic>? meta}) {
    _log('WARN', message, meta);
  }

  static void alert(String message, {Map<String, dynamic>? meta}) {
    _log('ALERT', message, meta);
    // Always print critical alerts regardless of verbose flag
    // ignore: avoid_print
    print('[IoTShield][ALERT] $message ${meta ?? ''}');
  }

  static void _log(String level, String message, Map<String, dynamic>? meta) {
    if (_verbose) {
      dev.log(
        '[$level] $message ${meta != null ? meta.toString() : ''}',
        name: 'IoTShield',
      );
    }
  }

  static SecurityEvent buildEvent(
    SecurityEventType type, {
    required String message,
    Map<String, dynamic> metadata = const {},
    SecuritySeverity severity = SecuritySeverity.info,
  }) {
    return SecurityEvent(
      type: type,
      message: message,
      metadata: metadata,
      timestamp: DateTime.now(),
      severity: severity,
    );
  }
}
