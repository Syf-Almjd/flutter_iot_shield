// flutter_iot_shield/lib/src/session/secure_session.dart

import 'dart:typed_data';

/// Active cryptographic session for a connected device.
class SecureSession {
  final String sessionId;
  final String deviceId;
  
  // Symmetric keys derived via HKDF
  final Uint8List encryptionKey;
  final Uint8List authKey;
  final Uint8List ivKey;
  final Uint8List rotationKey;
  
  final DateTime createdAt;
  DateTime lastSeen;
  
  int _outboundCounter = 0;
  int _lastInboundCounter = -1;
  int _rotationCount = 0;

  SecureSession({
    required this.sessionId,
    required this.deviceId,
    required this.encryptionKey,
    required this.authKey,
    required this.ivKey,
    required this.rotationKey,
    required this.createdAt,
  }) : lastSeen = createdAt;

  int get outboundCounter => _outboundCounter;
  int get lastInboundCounter => _lastInboundCounter;
  int get rotationCount => _rotationCount;

  int incrementOutboundCounter() {
    return _outboundCounter++;
  }

  void setLastInboundCounter(int counter) {
    _lastInboundCounter = counter;
  }

  void incrementRotationCount() {
    _rotationCount++;
  }

  void resetCounters() {
    _outboundCounter = 0;
    _lastInboundCounter = -1;
  }

  Duration get age => DateTime.now().difference(createdAt);
  int get packetCount => _outboundCounter + (_lastInboundCounter + 1);
}
