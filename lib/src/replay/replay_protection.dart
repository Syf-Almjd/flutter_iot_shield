// flutter_iot_shield/lib/src/replay/replay_protection.dart

/// Implements a sliding window replay protection algorithm (IPsec style).
class ReplayProtection {
  final int windowSize;
  
  // Track the maximum sequence number seen per device.
  final Map<String, int> _maxSeenSequences = {};
  
  // Set of received sequence numbers within the sliding window.
  final Map<String, Set<int>> _receivedInWindow = {};

  ReplayProtection({this.windowSize = 64}) {
    assert(windowSize > 0, 'Replay protection window size must be positive.');
  }

  /// Validates an incoming sequence number. Returns true if valid, false if replayed.
  bool validateSequence(String deviceId, int seq) {
    if (seq < 0) return false;

    final maxSeq = _maxSeenSequences[deviceId] ?? -1;
    final seenSet = _receivedInWindow.putIfAbsent(deviceId, () => <int>{});

    // 1. Packet is too old (behind sliding window)
    if (seq <= maxSeq - windowSize) {
      return false;
    }

    // 2. Packet lies within sliding window
    if (seq <= maxSeq) {
      if (seenSet.contains(seq)) {
        return false; // Replayed packet!
      }
      seenSet.add(seq);
      return true;
    }

    // 3. Packet is ahead of the window (slides forward)
    _maxSeenSequences[deviceId] = seq;
    seenSet.add(seq);

    // Clean up sequence numbers that fell out of the window
    seenSet.removeWhere((s) => s <= seq - windowSize);
    return true;
  }

  /// Resets the sequence tracking for a device (e.g. after key rotation).
  void reset(String deviceId) {
    _maxSeenSequences.remove(deviceId);
    _receivedInWindow.remove(deviceId);
  }
}
