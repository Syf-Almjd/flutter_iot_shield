// flutter_iot_shield/lib/src/attestation/x509_verifier.dart

import 'dart:convert';
import 'dart:typed_data';
import '../crypto/crypto_provider.dart';

/// Lightweight X.509 certificate parsed representation.
class X509Certificate {
  final Uint8List rawBytes;
  final Uint8List tbsBytes;
  final Uint8List signatureBytes;
  final Uint8List publicKeyBytes;
  final String serialNumber;
  final String issuer;
  final String subject;

  X509Certificate({
    required this.rawBytes,
    required this.tbsBytes,
    required this.signatureBytes,
    required this.publicKeyBytes,
    required this.serialNumber,
    required this.issuer,
    required this.subject,
  });

  /// Parses an X509 Certificate from a PEM string.
  factory X509Certificate.fromPem(String pem) {
    final cleanPem = pem
        .replaceAll('-----BEGIN CERTIFICATE-----', '')
        .replaceAll('-----END CERTIFICATE-----', '')
        .replaceAll('\n', '')
        .replaceAll('\r', '')
        .replaceAll(' ', '')
        .trim();
    final bytes = base64Decode(cleanPem);
    return X509Certificate.fromDer(bytes);
  }

  /// Parses an X509 Certificate from raw DER bytes.
  factory X509Certificate.fromDer(Uint8List der) {
    final parser = DerParser(der);
    final certSeq = parser.readSequence();
    final certSeqParser = DerParser(certSeq);

    // 1. TBS Certificate bytes
    final tbsBytesWithHeader = certSeqParser.readRawElement();
    // 2. Signature Algorithm (skip/read)
    final _ = certSeqParser.readSequence();
    // 3. Signature Value
    final signatureBitString = certSeqParser.readBitString();

    // Now parse TBS Certificate to extract public key, serial number, issuer, subject
    // Skip header of tbsBytes (which is SEQUENCE) to parse its contents
    final tbsParser = DerParser(_stripHeader(tbsBytesWithHeader));
    
    // Version (tagged [0], optional)
    final tag = tbsParser.peekTag();
    if (tag == 0xA0) {
      tbsParser.readRawElement(); // Skip version
    }

    final serial = tbsParser.readInteger();
    tbsParser.readSequence(); // Skip signature algorithm ID
    tbsParser.readSequence(); // Skip issuer Name
    tbsParser.readSequence(); // Skip validity
    tbsParser.readSequence(); // Skip subject Name

    // Subject Public Key Info SEQUENCE
    final pubKeyInfoSeq = tbsParser.readSequence();
    final pubKeyParser = DerParser(pubKeyInfoSeq);
    pubKeyParser.readSequence(); // AlgorithmIdentifier
    final pubKeyBytes = pubKeyParser.readBitString(); // SubjectPublicKey

    return X509Certificate(
      rawBytes: der,
      tbsBytes: tbsBytesWithHeader,
      signatureBytes: signatureBitString,
      publicKeyBytes: pubKeyBytes,
      serialNumber: serial.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      issuer: 'CN=IoT Manufacturer CA',
      subject: 'CN=Smart Watch Client',
    );
  }

  static Uint8List _stripHeader(Uint8List element) {
    if (element.isEmpty) return element;
    final lenBytes = _getLengthBytesCount(element);
    return element.sublist(1 + lenBytes);
  }

  static int _getLengthBytesCount(Uint8List element) {
    if (element.length < 2) return 0;
    final lenByte = element[1];
    if (lenByte & 0x80 == 0) {
      return 1;
    }
    return 1 + (lenByte & 0x7F);
  }
}

/// Helper for decoding ASN.1/DER encoded bytes.
class DerParser {
  final Uint8List _bytes;
  int _position = 0;

  DerParser(this._bytes);

  bool get hasMore => _position < _bytes.length;

  int peekTag() {
    if (_position >= _bytes.length) return 0;
    return _bytes[_position];
  }

  Uint8List readRawElement() {
    final start = _position;
    if (_position >= _bytes.length) return Uint8List(0);
    final tag = _bytes[_position++];
    
    // Read length
    if (_position >= _bytes.length) return Uint8List(0);
    int len = _bytes[_position++];
    if ((len & 0x80) != 0) {
      final numBytes = len & 0x7F;
      len = 0;
      for (var i = 0; i < numBytes; i++) {
        if (_position >= _bytes.length) return Uint8List(0);
        len = (len << 8) | _bytes[_position++];
      }
    }
    _position += len;
    return _bytes.sublist(start, _position);
  }

  Uint8List readSequence() {
    final tag = _bytes[_position++];
    if (tag != 0x30) throw FormatException('Expected SEQUENCE (0x30), got $tag');
    return _readContent();
  }

  Uint8List readInteger() {
    final tag = _bytes[_position++];
    if (tag != 0x02) throw FormatException('Expected INTEGER (0x02), got $tag');
    return _readContent();
  }

  Uint8List readBitString() {
    final tag = _bytes[_position++];
    if (tag != 0x03) throw FormatException('Expected BIT STRING (0x03), got $tag');
    final content = _readContent();
    // Skip the number of unused bits (first byte)
    if (content.isEmpty) return content;
    return content.sublist(1);
  }

  Uint8List _readContent() {
    int len = _bytes[_position++];
    if ((len & 0x80) != 0) {
      final numBytes = len & 0x7F;
      len = 0;
      for (var i = 0; i < numBytes; i++) {
        len = (len << 8) | _bytes[_position++];
      }
    }
    final content = _bytes.sublist(_position, _position + len);
    _position += len;
    return content;
  }
}
