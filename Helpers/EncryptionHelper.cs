using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecureBox.Helpers
{
    public class EncryptionHelper
    {
        // Use a valid Base64-encoded key (32 bytes for AES-256) and IV (16 bytes)
        private static readonly string Key = "j8Fg/G1PVpXcDcvk/yK21tPzlyqUqaHz4VPhZvHX0qs="; // 32 bytes key for AES-256
        private static readonly string Iv = "HR6WBxUq1ZW6gFz6gs02rA=="; // 16 bytes IV for AES

        // Encrypt the plain text (password)
        public static string Encrypt(string plainText)
        {
            // Decode the Base64-encoded key and IV
            byte[] keyBytes = Convert.FromBase64String(Key);
            byte[] ivBytes = Convert.FromBase64String(Iv);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = ivBytes;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    // Write the data to the stream
                    swEncrypt.Write(plainText);
                    swEncrypt.Flush();
                    csEncrypt.FlushFinalBlock();

                    // Return the encrypted text as Base64 string
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        // Decrypt the cipher text (password)
        public static string Decrypt(string cipherText)
        {
            // Decode the Base64-encoded key and IV
            byte[] keyBytes = Convert.FromBase64String(Key);
            byte[] ivBytes = Convert.FromBase64String(Iv);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = ivBytes;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    // Read the decrypted data from the stream
                    return srDecrypt.ReadToEnd();
                }
            }
        }
    }
}