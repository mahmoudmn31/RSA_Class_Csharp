using System;
using System.Security.Cryptography;
using System.Text;

public class RsaEncryption
{
    public static (string publicKey, string privateKey) GenerateKeyPair(int keySize = 2048)
    {
        ValidateKeySize(keySize);
    
        using (var rsa = RSA.Create())
        {
            rsa.KeySize = keySize;
    
            string publicKey = rsa.ToXmlString(false);
            string privateKey = rsa.ToXmlString(true);
    
            return (publicKey, privateKey);
        }
    }

    public static string Encrypt(string plainText, string publicKey, int keySize = 2048)
    {
        ValidateKeySize(keySize);
    
        if (string.IsNullOrEmpty(plainText))
            throw new ArgumentNullException(nameof(plainText));
        if (string.IsNullOrEmpty(publicKey))
            throw new ArgumentNullException(nameof(publicKey));
    
        using (var rsa = RSA.Create())
        {
            rsa.KeySize = keySize;
            rsa.FromXmlString(publicKey);
    
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes = rsa.Encrypt(plainBytes, RSAEncryptionPadding.OaepSHA256);
    
            return Convert.ToBase64String(encryptedBytes);
        }
    }

    public static string Decrypt(string encryptedText, string privateKey, int keySize = 2048)
    {
        ValidateKeySize(keySize);
        if (string.IsNullOrEmpty(encryptedText))
            throw new ArgumentNullException(nameof(encryptedText));
        if (string.IsNullOrEmpty(privateKey))
            throw new ArgumentNullException(nameof(privateKey));

        try
        {
            using var rsa = RSA.Create();
            rsa.KeySize = keySize;
            rsa.FromXmlString(privateKey);
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
            byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("Decryption failed. Invalid private key or encrypted text.", ex);
        }
    }

    private static void ValidateKeySize(int keySize)
    {
        if (keySize < 1024 || keySize > 4096)
            throw new ArgumentException("Key size must be between 1024 and 4096 bits", nameof(keySize));
        if (keySize % 8 != 0)
            throw new ArgumentException("Key size must be a multiple of 8", nameof(keySize));
    }
}
