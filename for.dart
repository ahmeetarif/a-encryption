import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:math' as math;
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';

void main() {
  HttpOverrides.global = MyHttpOverrides();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: EncryptionScreen(),
      theme: ThemeData(primarySwatch: Colors.blue, useMaterial3: true),
    );
  }
}

class EncryptionScreen extends StatefulWidget {
  @override
  _EncryptionScreenState createState() => _EncryptionScreenState();
}

class _EncryptionScreenState extends State<EncryptionScreen> {
  String _result = "Press the button to start encryption process";
  bool _isLoading = false;

  Future<void> _performEncryptionTest() async {
    setState(() {
      _isLoading = true;
      _result = "Processing...";
    });

    StringBuffer resultLog = StringBuffer();
    
    try {
      resultLog.writeln("Starting encryption process...");
      
      // Generate RSA key pair
      resultLog.writeln("Generating RSA key pair...");
      final keyPair = await compute(generateRSAKeyPair, null);
      resultLog.writeln("🔑 RSA keys generated successfully");
      
      // Get key details for debugging
      final publicKey = keyPair.publicKey;
      resultLog.writeln("Public key modulus length: ${publicKey.modulus!.bitLength} bits");
      resultLog.writeln("Public key exponent: ${publicKey.publicExponent}");
      
      // Convert public key to SPKI format
      final publicKeyDer = await compute(rsaPublicKeyToSpkiDer, keyPair.publicKey);
      final publicKeyBase64 = base64.encode(publicKeyDer);
      resultLog.writeln("🔄 Public key encoded to SPKI DER format");
      resultLog.writeln("Public key length: ${publicKeyDer.length} bytes");
      resultLog.writeln("Public key base64: ${publicKeyBase64.substring(0, 20)}...${publicKeyBase64.substring(publicKeyBase64.length - 20)}");
      
      // Make HTTP request
      resultLog.writeln("\n📡 Making HTTP request to server...");
      
      try {
        final response = await http.get(
          Uri.parse('https://localhost/api/test/encrypt'),
          headers: {
            'X-Public-Key': publicKeyBase64,
            'Authorization': 'Bearer BEARER',
          },
        );
        
        resultLog.writeln("📥 Received response: ${response.statusCode}");
        
        if (response.statusCode == 200) {
          // Extract data from response
          final responseData = jsonDecode(response.body);
          resultLog.writeln("Response data: $responseData");
          
          final encryptedData = responseData['data'];
          final ivBase64 = response.headers['x-requested-iv'];
          final tagBase64 = response.headers['x-requested-tag'];
          final encryptedKeyBase64 = response.headers['x-requested-encryption-key'];
          
          resultLog.writeln("🔐 Extracted encrypted data and keys");
          resultLog.writeln("Encrypted data: ${encryptedData.substring(0, 20)}... (${encryptedData.length} chars)");
          resultLog.writeln("IV: $ivBase64");
          resultLog.writeln("Tag: $tagBase64");
          resultLog.writeln("Encrypted key: ${encryptedKeyBase64?.substring(0, 20)}...");
          
          // Decryption would follow here, but we're focusing on fixing the ASN.1 issue first
          resultLog.writeln("✅ Successfully received encrypted data!");
        } else {
          resultLog.writeln("❌ Response error: ${response.statusCode}");
          resultLog.writeln("Response body: ${response.body}");
        }
      } catch (e) {
        resultLog.writeln("❌ HTTP error: $e");
      }
      
    } catch (e) {
      resultLog.writeln("❌ Error occurred: $e");
    } finally {
      setState(() {
        _isLoading = false;
        _result = resultLog.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Encryption Demo'),
      ),
      body: Center(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'RSA/AES-GCM Encryption Test',
              style: Theme.of(context).textTheme.headlineSmall,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 20),
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.grey[200],
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SingleChildScrollView(
                  child: Text(_result),
                ),
              ),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _isLoading ? null : _performEncryptionTest,
              child: _isLoading
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Text('Start Encryption Process'),
            ),
          ],
        ),
      ),
    );
  }
}

// Helper class to disable certificate verification
class MyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (_, __, ___) => true;
  }
}

// Class to hold RSA key pair
class RsaKeyPair {
  final RSAPublicKey publicKey;
  final RSAPrivateKey privateKey;
  
  RsaKeyPair(this.publicKey, this.privateKey);
}

// Function to generate RSA key pair (runs in isolate)
RsaKeyPair generateRSAKeyPair(_) {
  // Create a secure random number generator
  final secureRandom = FortunaRandom();
  secureRandom.seed(KeyParameter(
    Uint8List.fromList(List.generate(32, (_) => Random.secure().nextInt(256)))
  ));
  
  // Create parameters for RSA key generation
  final keyParams = RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64);
  final params = ParametersWithRandom(keyParams, secureRandom);
  
  // Create and initialize the key generator
  final keyGenerator = RSAKeyGenerator();
  keyGenerator.init(params);
  
  // Generate the key pair
  final keyPair = keyGenerator.generateKeyPair();
  final publicKey = keyPair.publicKey as RSAPublicKey;
  final privateKey = keyPair.privateKey as RSAPrivateKey;
  
  return RsaKeyPair(publicKey, privateKey);
}

// Improved function to encode RSA public key in SPKI format
Uint8List rsaPublicKeyToSpkiDer(RSAPublicKey publicKey) {
  // This follows the ASN.1 structure for SubjectPublicKeyInfo (SPKI)
  
  // 1. Prepare RSA Public Key Sequence (modulus + exponent)
  final modulus = _bigIntToUnsignedBytes(publicKey.modulus!);
  final exponent = _bigIntToUnsignedBytes(publicKey.publicExponent!);
  
  // 2. Create RSA Key bitstring content (PKCS#1 format)
  final rsaPublicKeySequence = _createSequence([
    _createInteger(modulus),
    _createInteger(exponent)
  ]);
  
  // 3. Create AlgorithmIdentifier for RSA
  final algorithmIdentifier = _createSequence([
    _createObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]), // RSA encryption OID
    _createNull()
  ]);
  
  // 4. Create BIT STRING for the public key
  final publicKeyBitString = _createBitString(rsaPublicKeySequence);
  
  // 5. Create final SubjectPublicKeyInfo sequence
  return _createSequence([
    algorithmIdentifier,
    publicKeyBitString
  ]);
}

// Helper functions for ASN.1 DER encoding
Uint8List _bigIntToUnsignedBytes(BigInt value) {
  if (value.sign < 0) {
    throw ArgumentError('Negative values not supported');
  }
  
  // Convert to bytes (big-endian)
  final hexString = value.toRadixString(16).padLeft((value.bitLength + 7) ~/ 8 * 2, '0');
  final bytes = <int>[];
  
  for (var i = 0; i < hexString.length; i += 2) {
    final byteHex = hexString.substring(i, math.min(i + 2, hexString.length));
    bytes.add(int.parse(byteHex, radix: 16));
  }
  
  return Uint8List.fromList(bytes);
}

Uint8List _createInteger(Uint8List value) {
  // Ensure the integer is positive (add leading 0x00 if first bit is set)
  List<int> valueList = value.toList();
  if (valueList.isNotEmpty && (valueList[0] & 0x80) != 0) {
    valueList.insert(0, 0x00);
  }
  
  // Create INTEGER tag (0x02) + length + value
  final result = <int>[0x02];
  _appendEncodedLength(result, valueList.length);
  result.addAll(valueList);
  
  return Uint8List.fromList(result);
}

Uint8List _createObjectIdentifier(List<int> oidComponents) {
  // Encode OID according to DER rules
  final encodedValues = <int>[];
  
  // First two components are encoded as 40*x + y
  if (oidComponents.length >= 2) {
    encodedValues.add(40 * oidComponents[0] + oidComponents[1]);
    
    // Encode remaining components
    for (var i = 2; i < oidComponents.length; i++) {
      var component = oidComponents[i];
      
      if (component < 128) {
        // Simple case: component fits in 7 bits
        encodedValues.add(component);
      } else {
        // Complex case: use multiple bytes with continuation bit
        final bytes = <int>[];
        
        bytes.add(component & 0x7F);
        component >>= 7;
        
        while (component > 0) {
          bytes.add(0x80 | (component & 0x7F));
          component >>= 7;
        }
        
        // Add bytes in reverse order
        for (var j = bytes.length - 1; j >= 0; j--) {
          encodedValues.add(bytes[j]);
        }
      }
    }
  }
  
  // Create OBJECT IDENTIFIER tag (0x06) + length + encoded values
  final result = <int>[0x06];
  _appendEncodedLength(result, encodedValues.length);
  result.addAll(encodedValues);
  
  return Uint8List.fromList(result);
}

Uint8List _createBitString(Uint8List content) {
  // Create BIT STRING tag (0x03) + length + unused bits byte (0x00) + content
  final result = <int>[0x03];
  _appendEncodedLength(result, content.length + 1);
  result.add(0x00); // Unused bits
  result.addAll(content);
  
  return Uint8List.fromList(result);
}

Uint8List _createNull() {
  // Create NULL tag (0x05) + length (0x00)
  return Uint8List.fromList([0x05, 0x00]);
}

Uint8List _createSequence(List<Uint8List> items) {
  // Calculate total length of all items
  var totalLength = 0;
  for (final item in items) {
    totalLength += item.length;
  }
  
  // Create SEQUENCE tag (0x30) + length + concatenated items
  final result = <int>[0x30];
  _appendEncodedLength(result, totalLength);
  
  // Add all items
  for (final item in items) {
    result.addAll(item);
  }
  
  return Uint8List.fromList(result);
}

void _appendEncodedLength(List<int> target, int length) {
  if (length < 128) {
    // Short form: length fits in 7 bits
    target.add(length);
  } else {
    // Long form: length needs multiple bytes
    final lengthBytes = <int>[];
    var tempLength = length;
    
    // Convert length to bytes (big-endian)
    while (tempLength > 0) {
      lengthBytes.insert(0, tempLength & 0xFF);
      tempLength >>= 8;
    }
    
    // Add length of length bytes + 0x80 indicator
    target.add(0x80 | lengthBytes.length);
    target.addAll(lengthBytes);
  }
}
