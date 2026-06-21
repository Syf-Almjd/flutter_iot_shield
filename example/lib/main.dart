import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_iot_shield/flutter_iot_shield.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // 1. Initialize the IoT Shield singleton
  final config = IoTShieldConfig(
    appId: 'com.saifalmajd.iotshield.demo',
    verboseLogging: true,
    firmwarePublicKey: '-----BEGIN PUBLIC KEY-----\n'
        'MCowBQYDK2VwAyEA9F5w0m5WkR4Q4X4W4X4W4X4W4X4W4X4W4X4W4X4W4X4=\n'
        '-----END PUBLIC KEY-----',
  );
  await IoTShield.instance.initialize(config);

  runApp(const IoTSecurityDemoApp());
}

class IoTSecurityDemoApp extends StatelessWidget {
  const IoTSecurityDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'IoT Shield Security Dashboard',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0F172A), // Slate 900
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF0EA5E9), // Sky 500
          secondary: Color(0xFFA855F7), // Purple 500
          surface: Color(0xFF1E293B), // Slate 800
          error: Color(0xFFEF4444), // Red 500
        ),
        cardTheme: const CardThemeData(
          color: Color(0xFF1E293B),
          elevation: 4,
          margin: EdgeInsets.all(8),
        ),
      ),
      home: const SecurityDashboardScreen(),
    );
  }
}

class SecurityDashboardScreen extends StatefulWidget {
  const SecurityDashboardScreen({super.key});

  @override
  State<SecurityDashboardScreen> createState() => _SecurityDashboardScreenState();
}

class _SecurityDashboardScreenState extends State<SecurityDashboardScreen> {
  final List<String> _securityLogs = [];
  final AnomalyDetector _anomalyDetector = AnomalyDetector();
  // Active session variables
  SecureSession? _activeSession;
  bool _isPairing = false;
  String _deviceId = 'device-mac-00:11:22:33:aa:bb';

  // Encryption playground variables
  final TextEditingController _messageController = TextEditingController(text: 'Secret payload message');
  String _encryptedHex = '';
  String _decryptedPlaintext = '';
  SecurePacket? _lastEncryptedPacket;

  @override
  void initState() {
    super.initState();
    // Listen to the global security event bus
    IoTShield.instance.securityEvents.listen((event) {
      setState(() {
        final timestamp = DateTime.now().toIso8601String().substring(11, 19);
        _securityLogs.insert(
          0,
          '[$timestamp] [${event.severity.name.toUpperCase()}] ${event.message} ${event.metadata}',
        );
      });
    });

    _log('System initialized. IoT Shield security engine active.');
  }

  void _log(String message) {
    setState(() {
      final timestamp = DateTime.now().toIso8601String().substring(11, 19);
      _securityLogs.insert(0, '[$timestamp] [INFO] $message');
    });
  }

  // Simulator helper: Pair device (ECDH key exchange)
  Future<void> _simulatePairing() async {
    setState(() {
      _isPairing = true;
    });
    _log('Initiating ECDH handshake for device $_deviceId...');

    try {
      // Setup mock data for the handshake
      final crypto = DefaultCryptoProvider();
      // In real BLE, you would send this to the device and receive theirs.
      // We will perform local key exchange with another simulated pair.
      final deviceKeyPair = await crypto.generateECDHKeyPair();

      // Establish pairing session
      final session = await IoTShield.instance.pairDevice(
        _deviceId,
        'WatchPro_X1',
        devicePublicKey: deviceKeyPair.publicKey,
        // Since attestation requires valid DER cert validation (which needs Root CA),
        // we bypass it or provide simulated raw components.
        // For this demo we perform a direct pairing configuration:
        deviceCertificateDer: Uint8List.fromList([1, 2, 3]), // dummy cert bytes
        challengeResponse: Uint8List.fromList([4, 5, 6]), // dummy signature
        challengeNonce: Uint8List.fromList([7, 8, 9]), // dummy nonce
      );

      setState(() {
        _activeSession = session;
        _isPairing = false;
      });
      _log('✓ Secure session established! Session ID: ${session.sessionId.substring(0, 8)}...');
    } catch (e) {
      setState(() {
        _isPairing = false;
      });
      _log('❌ Pairing failed: $e');
    }
  }

  // Simulator helper: Encrypt outgoing command payload
  Future<void> _encryptMessage() async {
    if (_activeSession == null) {
      _log('⚠️ Cannot encrypt: Establish a secure session first.');
      return;
    }

    try {
      final plaintextBytes = Uint8List.fromList(utf8.encode(_messageController.text));
      final packet = await IoTShield.instance.encrypt(
        plaintextBytes,
        _deviceId,
        command: 0x0A,
        sequence: _activeSession!.outboundCounter,
      );

      setState(() {
        _lastEncryptedPacket = packet;
        _encryptedHex = packet.encryptedPayload.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
        _decryptedPlaintext = '';
      });

      _log('Packet encrypted. Seq: ${packet.sequence}, IV: ${packet.nonce.map((b) => b.toRadixString(16).padLeft(2, '0')).join().substring(0, 10)}...');
    } catch (e) {
      _log('❌ Encryption failed: $e');
    }
  }

  // Simulator helper: Decrypt payload
  Future<void> _decryptMessage() async {
    if (_lastEncryptedPacket == null) {
      _log('⚠️ Cannot decrypt: No encrypted packet available.');
      return;
    }

    try {
      final decryptedBytes = await IoTShield.instance.decrypt(
        _lastEncryptedPacket!,
        _deviceId,
      );

      setState(() {
        _decryptedPlaintext = utf8.decode(decryptedBytes);
      });
      _log('✓ Packet decrypted successfully: "$_decryptedPlaintext"');
    } catch (e) {
      _log('❌ Decryption failed: $e');
    }
  }

  // Simulator helper: Replay Attack (tries to reuse the exact same packet)
  Future<void> _simulateReplayAttack() async {
    if (_lastEncryptedPacket == null) {
      _log('⚠️ Cannot simulate replay: No encrypted packet available.');
      return;
    }

    _log('😈 Injecting replayed packet with Seq: ${_lastEncryptedPacket!.sequence}...');
    try {
      await IoTShield.instance.decrypt(
        _lastEncryptedPacket!,
        _deviceId,
      );
      _log('❌ Security flaw: Replayed packet was accepted!');
    } catch (e) {
      _log('✓ Replay protection successful: Blocked duplicate packet! Error: $e');
    }
  }

  // Simulator helper: Trigger Anomaly Reconnect Storm
  void _simulateReconnectStorm() {
    _log('⚡ Simulating rapid reconnect storm (5 reconnects in 1 second)...');
    for (int i = 0; i < 6; i++) {
      _anomalyDetector.recordConnect(_deviceId);
    }
  }

  // Simulator helper: Trigger Anomaly Device Switching
  void _simulateDeviceSwitching() {
    _log('⚡ Simulating rapid device switching (impersonation)...');
    for (int i = 0; i < 5; i++) {
      _anomalyDetector.recordConnect('device-mac-address-fake-$i');
    }
  }

  // Simulator helper: Validate Firmware Package
  Future<void> _simulateFirmwareVerification({required bool makeValid}) async {
    _log('📦 Initializing firmware verifier...');
    final verifier = FirmwareVerifier(
      publicKeyPem: IoTShield.instance.config.firmwarePublicKey,
    );
    verifier.currentDeviceModel = 'WatchPro_X1';
    verifier.currentFirmwareVersion = '1.1.0';

    // Create a temporary zip package manifest
    final tempDir = Directory.systemTemp.createTempSync('ota');
    final firmwareFile = File('${tempDir.path}/firmware.bin');
    firmwareFile.writeAsBytesSync(List.filled(1024, 0xAF));

    // Note: To test zip parsing firmware_verifier.dart requires manifest.json.
    // For simplicity, we can directly test the fallback raw binary case (manifest verification skipped).
    final result = await verifier.verify(firmwareFile);
    if (result is FirmwareVerified) {
      _log('✓ Firmware file verification PASSED. Model: ${result.targetModel}, Version: ${result.version}');
    } else if (result is FirmwareRejected) {
      _log('❌ Firmware file verification REJECTED: ${result.reason}');
    }
    
    // Clean up
    tempDir.deleteSync(recursive: true);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('🛡️ IoT Shield Dashboard'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () {
              setState(() {
                _securityLogs.clear();
                _activeSession = null;
                _encryptedHex = '';
                _decryptedPlaintext = '';
                _lastEncryptedPacket = null;
                _anomalyDetector.reset();
              });
              _log('Dashboard reset complete.');
            },
            tooltip: 'Reset Dashboard',
          )
        ],
        flexibleSpace: Container(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              colors: [Color(0xFF0EA5E9), Color(0xFFA855F7)],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
          ),
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Row 1: Connection & Pairing
            _buildPairingCard(),

            // Row 2: Encryption Playground
            _buildEncryptionCard(),

            // Row 3: Security Attack & Anomaly Simulators
            _buildSimulatorCard(),

            // Row 4: Live Event Logging Log
            _buildEventLogCard(),
          ],
        ),
      ),
    );
  }

  Widget _buildPairingCard() {
    final hasSession = _activeSession != null;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text(
                  '🔐 BLE Session Cryptography (ECDH)',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Color(0xFF0EA5E9)),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: hasSession ? const Color(0x334CAF50) : const Color(0x33FFC107),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: hasSession ? Colors.green : Colors.amber),
                  ),
                  child: Text(
                    hasSession ? 'PAIRED / SECURE' : 'UNSECURED',
                    style: TextStyle(
                      color: hasSession ? Colors.greenAccent : Colors.amberAccent,
                      fontWeight: FontWeight.bold,
                      fontSize: 12,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text('Target Device ID: $_deviceId'),
            if (hasSession) ...[
              const SizedBox(height: 8),
              Text(
                'Derived Shared Session Key (AES-GCM):\n'
                '${_activeSession!.encryptionKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join().substring(0, 32)}...',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: Colors.white70),
              ),
            ],
            const SizedBox(height: 12),
            ElevatedButton(
              onPressed: _isPairing ? null : _simulatePairing,
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF0EA5E9),
                foregroundColor: Colors.white,
              ),
              child: _isPairing
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                    )
                  : Text(hasSession ? 'Refresh Session Key' : 'Establish ECDH Secure Channel'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEncryptionCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '📦 Encrypted Messaging Playground (AES-256-GCM)',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Color(0xFFA855F7)),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _messageController,
              decoration: const InputDecoration(
                labelText: 'Payload Plaintext to Send',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.message),
              ),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton(
                    onPressed: _activeSession == null ? null : _encryptMessage,
                    style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFA855F7), foregroundColor: Colors.white),
                    child: const Text('Encrypt Payload'),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: ElevatedButton(
                    onPressed: _lastEncryptedPacket == null ? null : _decryptMessage,
                    style: ElevatedButton.styleFrom(backgroundColor: Colors.teal, foregroundColor: Colors.white),
                    child: const Text('Decrypt Payload'),
                  ),
                ),
              ],
            ),
            if (_encryptedHex.isNotEmpty) ...[
              const SizedBox(height: 12),
              const Text('Encrypted Hex String:', style: TextStyle(fontWeight: FontWeight.bold)),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(8),
                color: Colors.black26,
                child: Text(
                  _encryptedHex,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
              ),
            ],
            if (_decryptedPlaintext.isNotEmpty) ...[
              const SizedBox(height: 12),
              const Text('Decrypted Plaintext:', style: TextStyle(fontWeight: FontWeight.bold)),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(8),
                color: Colors.black26,
                child: Text(
                  _decryptedPlaintext,
                  style: const TextStyle(color: Colors.greenAccent, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildSimulatorCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '👿 Security Attack & Anomaly Simulator',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.orange),
            ),
            const SizedBox(height: 8),
            const Text(
              'Simulate active security threats and watch how the SDK identifies, blocks, and broadcasts real-time security events.',
              style: TextStyle(color: Colors.white70, fontSize: 13),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                ActionChip(
                  avatar: const Icon(Icons.history_toggle_off, size: 16, color: Colors.white),
                  label: const Text('Simulate Replay Attack'),
                  backgroundColor: const Color(0x4DFF5722),
                  side: const BorderSide(color: Colors.deepOrange),
                  onPressed: _lastEncryptedPacket == null ? null : _simulateReplayAttack,
                ),
                ActionChip(
                  avatar: const Icon(Icons.flash_on, size: 16, color: Colors.white),
                  label: const Text('Reconnect Storm'),
                  backgroundColor: const Color(0x4DF44336),
                  side: const BorderSide(color: Colors.red),
                  onPressed: _simulateReconnectStorm,
                ),
                ActionChip(
                  avatar: const Icon(Icons.swap_horiz, size: 16, color: Colors.white),
                  label: const Text('Device Impersonation'),
                  backgroundColor: const Color(0x4DF44336),
                  side: const BorderSide(color: Colors.red),
                  onPressed: _simulateDeviceSwitching,
                ),
                ActionChip(
                  avatar: const Icon(Icons.system_update, size: 16, color: Colors.white),
                  label: const Text('Verify Firmware'),
                  backgroundColor: const Color(0x4D2196F3),
                  side: const BorderSide(color: Colors.blue),
                  onPressed: () => _simulateFirmwareVerification(makeValid: true),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEventLogCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '🚨 Live Security Log & Event Bus Feed',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.redAccent),
            ),
            const SizedBox(height: 12),
            Container(
              height: 200,
              decoration: BoxDecoration(
                color: Colors.black38,
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: Colors.white10),
              ),
              child: _securityLogs.isEmpty
                  ? const Center(
                      child: Text(
                        'No security logs generated yet.',
                        style: TextStyle(color: Colors.white30),
                      ),
                    )
                  : ListView.builder(
                      itemCount: _securityLogs.length,
                      padding: const EdgeInsets.all(8),
                      itemBuilder: (context, index) {
                        final log = _securityLogs[index];
                        Color textColor = Colors.white70;
                        if (log.contains('[WARNING]')) {
                          textColor = Colors.amberAccent;
                        } else if (log.contains('[CRITICAL]') || log.contains('[ALERT]')) {
                          textColor = Colors.redAccent;
                        } else if (log.contains('✓')) {
                          textColor = Colors.greenAccent;
                        }

                        return Padding(
                          padding: const EdgeInsets.symmetric(vertical: 4.0),
                          child: Text(
                            log,
                            style: TextStyle(
                              fontFamily: 'monospace',
                              fontSize: 12,
                              color: textColor,
                            ),
                          ),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );
  }
}
