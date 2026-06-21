// flutter_iot_shield/lib/src/monitoring/security_event_bus.dart
//
// A broadcast stream of all security events emitted by the IoT Shield layer.
// Consumers can subscribe to get real-time security alerts, log them, or
// show UI warnings.

import 'dart:async';

import '../core/security_event.dart';
import '../core/iot_shield_logger.dart';

/// Global security event bus for the IoT Shield layer.
///
/// Usage:
/// ```dart
/// SecurityEventBus.instance.stream.listen((event) {
///   if (event.severity == SecuritySeverity.critical) {
///     showSecurityAlert(event.message);
///   }
/// });
/// ```
class SecurityEventBus {
  static final SecurityEventBus instance = SecurityEventBus._();
  SecurityEventBus._();

  final StreamController<SecurityEvent> _controller =
      StreamController<SecurityEvent>.broadcast();

  /// Stream of all security events from any IoT Shield module.
  Stream<SecurityEvent> get stream => _controller.stream;

  /// Filtered stream — only critical events.
  Stream<SecurityEvent> get criticalEvents =>
      stream.where((e) => e.severity == SecuritySeverity.critical);

  /// Filtered stream — warnings and above.
  Stream<SecurityEvent> get warnings =>
      stream.where((e) => e.severity != SecuritySeverity.info);

  /// Emits a security event to all listeners.
  void emit(SecurityEvent event) {
    IoTShieldLogger.info('[EventBus] ${event.type.name}: ${event.message}');
    if (!_controller.isClosed) {
      _controller.add(event);
    }
  }

  /// Convenience emitters:

  void emitInfo(SecurityEventType type,
      {required String message, Map<String, dynamic> meta = const {}}) {
    emit(SecurityEvent.info(type, message: message, metadata: meta));
  }

  void emitWarning(SecurityEventType type,
      {required String message, Map<String, dynamic> meta = const {}}) {
    emit(SecurityEvent.warning(type, message: message, metadata: meta));
  }

  void emitCritical(SecurityEventType type,
      {required String message, Map<String, dynamic> meta = const {}}) {
    emit(SecurityEvent.critical(type, message: message, metadata: meta));
  }

  /// Closes the stream controller (call on app dispose only).
  void dispose() {
    _controller.close();
  }
}
