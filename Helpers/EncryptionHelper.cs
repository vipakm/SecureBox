using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecureBox.Helpers
{
    public class EncryptionHelper
    {
        // You can store the Key and IV securely using environment variables or a key vault in a production scenario
        private static readonly string Key = "j8Fg/G1PVpXcDcvk/yK21tPzlyqUqaHz4VPhZvHX0qs="; // 32 bytes key for AES-256
        private static readonly string Iv = "HR6WBxUq1ZW6gFz6gs02rA=="; // 16 bytes IV for AES

        // Encrypt the plain text (password)
        public static string Encrypt(string plainText)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(Key);
                aesAlg.IV = Encoding.UTF8.GetBytes(Iv);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    // Write the data to the stream
                    swEncrypt.Write(plainText);
                    // Return the encrypted text as Base64 string
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        // Decrypt the cipher text (password)
        public static string Decrypt(string cipherText)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(Key);
                aesAlg.IV = Encoding.UTF8.GetBytes(Iv);

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
