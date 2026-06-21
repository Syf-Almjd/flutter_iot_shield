# Changelog

## 1.1.0

- Add support for [GitHub Sponsors](https://github.com/sponsors/Syf-Almjd)
- Upgrade dependencies
- Fix compile errors
- Fix linting errors
- Improve documentation
- Add usage examples




## 1.0.0

- Initial release of `flutter_iot_shield` security layer for Flutter IoT applications.
- **Core Security Channel**: ECDH key exchange with Curve25519 & AES-256-GCM authenticated encryption.
- **Anti-Replay Attack Protection**: Sliding window sequence validation tracking.
- **Device Trust & Attestation**: Custom X.509 certificate verification and challenge signature authentication.
- **Health Validation & Sanitization**: Telemetry data constraints checker and platform channel event sanitizer.
- **Secure Key Store**: Cryptographically protected local key storage leveraging `flutter_secure_storage`.
- **Firmware Verification**: Verifies signed firmware zip packages using ECDSA signature validation.
- **Security Event Bus**: Real-time event publisher for monitoring attacks and anomalies.
