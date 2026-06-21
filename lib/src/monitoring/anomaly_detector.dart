// flutter_iot_shield/lib/src/monitoring/anomaly_detector.dart
//
// Detects suspicious BLE connection patterns that may indicate:
//  - Reconnection storms (compromised device or MITM relay)
//  - Excessive scan frequency (rogue scanner)
//  - Rapid device switching (impersonation attempts)

import '../core/iot_shield_logger.dart';
import '../core/security_event.dart';
import 'security_event_bus.dart';

/// A single connection event recorded by the detector.
class _ConnectionRecord {
  final String deviceId;
  final DateTime timestamp;
  final bool wasConnected; // true = connect, false = disconnect

  const _ConnectionRecord({
    required this.deviceId,
    required this.timestamp,
    required this.wasConnected,
  });
}

/// Detects anomalous BLE connection patterns.
class AnomalyDetector {
  static const _maxReconnectsPerWindow = 5;
  static const _reconnectWindow = Duration(minutes: 2);
  static const _maxSwitchesPerWindow = 3;
  static const _deviceSwitchWindow = Duration(minutes: 1);

  final List<_ConnectionRecord> _records = [];
  final SecurityEventBus _bus;

  /// Creates an [AnomalyDetector] with an optional custom [SecurityEventBus].
  ///
  /// If [bus] is not provided, it defaults to the shared [SecurityEventBus.instance].
  AnomalyDetector({SecurityEventBus? bus})
      : _bus = bus ?? SecurityEventBus.instance;

  /// Record a connection event for a device.
  void recordConnect(String deviceId) {
    _prune();
    _records.add(_ConnectionRecord(
      deviceId: deviceId,
      timestamp: DateTime.now(),
      wasConnected: true,
    ));
    _checkReconnectStorm(deviceId);
    _checkDeviceSwitching();
  }

  /// Record a disconnection event for a device.
  void recordDisconnect(String deviceId) {
    _prune();
    _records.add(_ConnectionRecord(
      deviceId: deviceId,
      timestamp: DateTime.now(),
      wasConnected: false,
    ));
  }

  // ─── Anomaly checks ───────────────────────────────────────────────────────

  void _checkReconnectStorm(String deviceId) {
    final window = DateTime.now().subtract(_reconnectWindow);
    final recent = _records
        .where((r) =>
            r.deviceId == deviceId &&
            r.wasConnected &&
            r.timestamp.isAfter(window))
        .length;

    if (recent > _maxReconnectsPerWindow) {
      IoTShieldLogger.alert(
        'Reconnect storm detected for device $deviceId '
        '($recent connects in ${_reconnectWindow.inMinutes} min)',
        meta: {'event': SecurityEventType.anomalyDetected.name},
      );
      _bus.emitWarning(
        SecurityEventType.anomalyDetected,
        message:
            'Unusual reconnect frequency for $deviceId ($recent in ${_reconnectWindow.inMinutes}min)',
        meta: {'deviceId': deviceId, 'count': recent},
      );
    }
  }

  void _checkDeviceSwitching() {
    final window = DateTime.now().subtract(_deviceSwitchWindow);
    final recentDevices = _records
        .where((r) => r.wasConnected && r.timestamp.isAfter(window))
        .map((r) => r.deviceId)
        .toSet();

    if (recentDevices.length > _maxSwitchesPerWindow) {
      IoTShieldLogger.alert(
        'Rapid device switching detected: ${recentDevices.length} different '
        'devices in ${_deviceSwitchWindow.inMinutes} min — possible impersonation',
        meta: {'event': SecurityEventType.anomalyDetected.name},
      );
      _bus.emitCritical(
        SecurityEventType.anomalyDetected,
        message:
            'Rapid device switching: ${recentDevices.length} devices in ${_deviceSwitchWindow.inMinutes}min',
        meta: {'devices': recentDevices.toList()},
      );
    }
  }

  // ─── BLE scan rate monitoring ─────────────────────────────────────────────

  int _scanEventCount = 0;
  DateTime _scanWindowStart = DateTime.now();
  static const _maxScansPerMinute = 60;

  /// Call this each time a BLE scan result is received.
  void recordScanEvent() {
    final now = DateTime.now();
    if (now.difference(_scanWindowStart) > const Duration(minutes: 1)) {
      _scanEventCount = 0;
      _scanWindowStart = now;
    }
    _scanEventCount++;
    if (_scanEventCount > _maxScansPerMinute) {
      IoTShieldLogger.warn(
        'High BLE scan rate: $_scanEventCount events/min',
        meta: {'event': SecurityEventType.anomalyDetected.name},
      );
    }
  }

  void _prune() {
    final cutoff = DateTime.now().subtract(const Duration(minutes: 10));
    _records.removeWhere((r) => r.timestamp.isBefore(cutoff));
  }

  /// Resets the detector's tracking records and counters to their initial states.
  void reset() {
    _records.clear();
    _scanEventCount = 0;
    _scanWindowStart = DateTime.now();
  }
}
