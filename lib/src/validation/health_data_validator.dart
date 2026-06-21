// flutter_iot_shield/lib/src/validation/health_data_validator.dart
//
// Validates health sensor readings for physiological plausibility.
// Rejects data that could indicate sensor spoofing, bit errors, or replay injection.

import '../core/iot_shield_config.dart';
import '../core/iot_shield_logger.dart';
import '../core/security_event.dart';

enum ValidationSeverity { ok, warning, rejected }

/// Result of a health data validation check.
class ValidationResult {
  final ValidationSeverity severity;
  final String? reason;

  const ValidationResult._(this.severity, this.reason);

  factory ValidationResult.valid() =>
      const ValidationResult._(ValidationSeverity.ok, null);

  factory ValidationResult.warning({required String reason}) =>
      ValidationResult._(ValidationSeverity.warning, reason);

  factory ValidationResult.rejected({required String reason}) =>
      ValidationResult._(ValidationSeverity.rejected, reason);

  bool get isValid => severity != ValidationSeverity.rejected;
  bool get hasWarning => severity == ValidationSeverity.warning;

  @override
  String toString() => 'ValidationResult(${severity.name}: $reason)';
}

/// Validates health data received from the BLE device.
class HealthDataValidator {
  final HealthValidationConfig _config;

  const HealthDataValidator({HealthValidationConfig? config})
      : _config = config ?? const HealthValidationConfig();

  // ─── Heart Rate ──────────────────────────────────────────────────────────

  ValidationResult validateHeartRate(int? bpm) {
    if (bpm == null) {
      return ValidationResult.rejected(reason: 'Heart rate value is null');
    }
    final (min, max) = _config.heartRateRange;
    if (bpm < min || bpm > max) {
      _logRejected(
        'Heart rate $bpm bpm outside range [$min-$max]',
        SecurityEventType.healthDataRejected,
      );
      return ValidationResult.rejected(
        reason: 'Heart rate $bpm bpm outside physiological range [$min-$max]',
      );
    }
    // Warning zone — possible sensor noise
    if (bpm < 30 || bpm > 220) {
      _logWarning('Heart rate $bpm bpm is unusual');
      return ValidationResult.warning(
        reason: 'Heart rate $bpm bpm is unusual — verify sensor contact',
      );
    }
    return ValidationResult.valid();
  }

  // ─── SpO2 ────────────────────────────────────────────────────────────────

  ValidationResult validateSpO2(double? pct) {
    if (pct == null) {
      return ValidationResult.rejected(reason: 'SpO2 value is null');
    }
    final (min, max) = _config.spo2Range;
    if (pct < min || pct > max) {
      _logRejected(
        'SpO2 ${pct.toStringAsFixed(1)}% outside range [$min-$max]',
        SecurityEventType.healthDataRejected,
      );
      return ValidationResult.rejected(
        reason:
            'SpO2 ${pct.toStringAsFixed(1)}% outside valid range [$min-$max]',
      );
    }
    if (pct < 80) {
      _logWarning('SpO2 ${pct.toStringAsFixed(1)}% critically low');
      return ValidationResult.warning(
        reason: 'SpO2 ${pct.toStringAsFixed(1)}% is critically low',
      );
    }
    return ValidationResult.valid();
  }

  // ─── HRV ─────────────────────────────────────────────────────────────────

  ValidationResult validateHrv(int? ms) {
    if (ms == null) {
      return ValidationResult.rejected(reason: 'HRV value is null');
    }
    final (min, max) = _config.hrvRange;
    if (ms < min || ms > max) {
      _logRejected(
        'HRV $ms ms outside range [$min-$max]',
        SecurityEventType.healthDataRejected,
      );
      return ValidationResult.rejected(
        reason: 'HRV $ms ms outside valid range [$min-$max]',
      );
    }
    return ValidationResult.valid();
  }

  // ─── Stress ──────────────────────────────────────────────────────────────

  ValidationResult validateStress(double? score) {
    if (score == null) {
      return ValidationResult.rejected(reason: 'Stress score is null');
    }
    final (min, max) = _config.stressRange;
    if (score < min || score > max) {
      _logRejected(
        'Stress $score outside range [$min-$max]',
        SecurityEventType.healthDataRejected,
      );
      return ValidationResult.rejected(
        reason: 'Stress score $score outside valid range [$min-$max]',
      );
    }
    return ValidationResult.valid();
  }

  // ─── Temperature ─────────────────────────────────────────────────────────

  ValidationResult validateTemperature(double? celsius) {
    if (celsius == null) {
      return ValidationResult.rejected(reason: 'Temperature value is null');
    }
    final (min, max) = _config.temperatureRange;
    if (celsius < min || celsius > max) {
      _logRejected(
        'Temperature ${celsius.toStringAsFixed(1)}°C outside range [$min-$max]',
        SecurityEventType.healthDataRejected,
      );
      return ValidationResult.rejected(
        reason:
            'Temperature ${celsius.toStringAsFixed(1)}°C outside valid range [$min-$max]',
      );
    }
    return ValidationResult.valid();
  }

  // ─── Steps ───────────────────────────────────────────────────────────────

  ValidationResult validateSteps(int? steps) {
    if (steps == null) {
      return ValidationResult.rejected(reason: 'Steps value is null');
    }
    // Max ~70,000 steps per day — cap at 200k to catch obvious bit errors
    if (steps < 0 || steps > 200000) {
      _logRejected(
        'Steps $steps outside plausible range',
        SecurityEventType.healthDataRejected,
      );
      return ValidationResult.rejected(
        reason: 'Steps count $steps is outside plausible range [0-200000]',
      );
    }
    return ValidationResult.valid();
  }

  // ─── Battery ─────────────────────────────────────────────────────────────

  ValidationResult validateBattery(int? level) {
    if (level == null) {
      return ValidationResult.rejected(reason: 'Battery level is null');
    }
    if (level < 0 || level > 100) {
      _logRejected(
        'Battery $level% outside [0-100]',
        SecurityEventType.healthDataRejected,
      );
      return ValidationResult.rejected(
        reason: 'Battery level $level% outside valid range [0-100]',
      );
    }
    return ValidationResult.valid();
  }

  // ─── Convenience: validate a full device event map ───────────────────────

  /// Validates and cleans a device event map in-place.
  /// Invalid fields are removed rather than causing an exception.
  Map<String, dynamic> sanitizeEventMap(Map<String, dynamic> event) {
    final result = Map<String, dynamic>.from(event);

    if (result.containsKey('bpm')) {
      final v = result['bpm'];
      final bpm = v is int ? v : (v is num ? v.toInt() : null);
      if (validateHeartRate(bpm).severity == ValidationSeverity.rejected) {
        result.remove('bpm');
      }
    }

    if (result.containsKey('heartRate')) {
      final v = result['heartRate'];
      final hr = v is int ? v : (v is num ? v.toInt() : null);
      if (validateHeartRate(hr).severity == ValidationSeverity.rejected) {
        result.remove('heartRate');
      }
    }

    if (result.containsKey('spo2')) {
      final v = result['spo2'];
      final spo2 = v is double ? v : (v is num ? v.toDouble() : null);
      if (validateSpO2(spo2).severity == ValidationSeverity.rejected) {
        result.remove('spo2');
      }
    }

    if (result.containsKey('hrv')) {
      final v = result['hrv'];
      final hrv = v is int ? v : (v is num ? v.toInt() : null);
      if (validateHrv(hrv).severity == ValidationSeverity.rejected) {
        result.remove('hrv');
      }
    }

    if (result.containsKey('battery') || result.containsKey('batteryLevel')) {
      final key = result.containsKey('battery') ? 'battery' : 'batteryLevel';
      final v = result[key];
      final bat = v is int ? v : (v is num ? v.toInt() : null);
      if (validateBattery(bat).severity == ValidationSeverity.rejected) {
        result.remove(key);
      }
    }

    if (result.containsKey('steps')) {
      final v = result['steps'];
      final steps = v is int ? v : (v is num ? v.toInt() : null);
      if (validateSteps(steps).severity == ValidationSeverity.rejected) {
        result.remove('steps');
      }
    }

    return result;
  }

  void _logRejected(String msg, SecurityEventType type) {
    IoTShieldLogger.warn(msg, meta: {'event': type.name});
  }

  void _logWarning(String msg) {
    IoTShieldLogger.info(msg,
        meta: {'event': SecurityEventType.healthDataWarning.name});
  }
}
