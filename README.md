# RSA Encryption Class

This class provides RSA encryption and decryption functionality in C#.

## Features

- Generate public/private key pairs
- Support for various key sizes (1024 to 4096 bits)
- Secure encryption/decryption with proper padding (OAEP SHA-256)
- Cryptographic exception handling

## Installation

Simply include the `RsaEncryption.cs` file in your project.

## Basic Usage

### 1. Generate Key Pair

```csharp
var (publicKey, privateKey) = RsaEncryption.GenerateKeyPair(2048);
```

### 2. Encrypt Text

```csharp
string encrypted = RsaEncryption.Encrypt("Secret message", publicKey);
```

### 3. Decrypt Text

```csharp
string decrypted = RsaEncryption.Decrypt(encryptedText, privateKey);
```

### Complete Example

```csharp
// Generate keys (3072-bit)
int keySize = 3072;
var (publicKey, privateKey) = RsaEncryption.GenerateKeyPair(keySize);

// Encrypt
string original = "This is a secret message";
string encrypted = RsaEncryption.Encrypt(original, publicKey, keySize);

// Decrypt
string decrypted = RsaEncryption.Decrypt(encrypted, privateKey, keySize);

Console.WriteLine($"Original: {original}");
Console.WriteLine($"Encrypted: {encrypted}");
Console.WriteLine($"Decrypted: {decrypted}");
```

## Best Practices

### Key Management

- **Always keep private keys secure.**
- Consider using key vaults for production environments.

### Key Sizes

- **Minimum recommended:** 2048-bit
- **For sensitive data:** 4096-bit
- Avoid using 1024-bit for new systems.

### Performance Considerations

- RSA is slower than symmetric encryption.
- For large data, consider hybrid encryption (e.g., RSA + AES).

## Limitations

- Maximum encryptable data size depends on key size.
- Not suitable for encrypting large files directly.

**Typical max data sizes:**

- 1024-bit: 117 bytes
- 2048-bit: 245 bytes
- 4096-bit: 501 bytes

## Security Notes

- Uses OAEP padding with SHA-256 (recommended).
- Always validate and sanitize input.
- **Never hardcode keys in source code.**
- Rotate keys periodically for sensitive applications.

## Troubleshooting

**Common Errors:**

- `CryptographicException: Decryption failed`  
  Usually indicates a wrong private key.
- `ArgumentException`  
  Invalid key size or malformed input.
- `ArgumentNullException`  
  Missing required parameters.

**For production use, consider:**

- Adding key expiration
- Implementing key rotation
- Using certificate-based keys

---

Feel free to contribute or open issues for questions and improvements!
