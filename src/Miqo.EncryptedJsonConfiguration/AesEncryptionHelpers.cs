using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using CryptHash.Net;

namespace Miqo.EncryptedJsonConfiguration
{
    /// <summary>
    /// A collection of helper methods to make working with AES encryption easier.
    /// </summary>
    public static class AesEncryptionHelpers
    {
        /// <summary>
        /// Generates a new 256 bit key.
        /// </summary>
        /// <returns>The encryption key used to der.</returns>
        public static byte[] GenerateKey()
        {
            return CommonMethods.Generate256BitKey();
        }

        /// <summary>
        /// Generates a new 256 bit key.
        /// </summary>
        /// <returns>The encryption key encoded as a base64 string.</returns>
        public static string GenerateBase64EncodedKey()
        {
            var key = CommonMethods.Generate256BitKey();
            return Convert.ToBase64String(key);
        }

        /// <summary>
        /// Encrypts an input string using AES with a 256 bits key in GCM authenticated mode.
        /// </summary>
        /// <param name="text">The plain string input to encrypt.</param>
        /// <param name="key">The encryption key being used.</param>
        /// <returns>The base64 encoded output string encrypted with AES.</returns>
        public static string Encrypt(string text, string key)
        {
            if (string.IsNullOrEmpty(text))
                throw new ArgumentNullException(nameof(text));
            
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));

            var aes = new AEAD_AES_256_GCM();
            return Convert.ToBase64String(aes.EncryptString(text, key));
        }

        /// <summary>
        /// Encrypts an input byte array using AES with a 256 bits key in GCM authenticated mode.
        /// </summary>
        /// <param name="text">The input byte array of the string to encrypt.</param>
        /// <param name="key">The encryption key being used.</param>
        /// <returns>The base64 encoded output string encrypted with AES.</returns>
        public static string Encrypt(byte[] text, byte[] key)
        {
            if (text == null)
                throw new ArgumentNullException(nameof(text));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            var aes = new AEAD_AES_256_GCM();
            return Convert.ToBase64String(aes.EncryptString(text, key));
        }

        /// <summary>
        /// Serializes and encrypts a strongly typed settings object class using AES with a 256 bits key in GCM authenticated mode.
        /// </summary>
        /// <param name="settings">The input strongly typed settings object to encrypt.</param>
        /// <param name="key">The encryption key being used.</param>
        /// <returns>The base64 encoded output string encrypted with AES.</returns>
        public static string Encrypt<TSettings>(TSettings settings, string key)
            where TSettings : class, new()
        {
            if (settings == null)
                throw new ArgumentNullException(nameof(settings));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            var json = JsonSerializer.Serialize<TSettings>(settings);
            return Encrypt(json, key);
        }

        /// <summary>
        /// Serializes and encrypts a strongly typed settings object class using AES with a 256 bits key in GCM authenticated mode.
        /// </summary>
        /// <param name="settings">The input strongly typed settings object to encrypt.</param>
        /// <param name="key">The encryption key being used.</param>
        /// <returns>The base64 encoded output string encrypted with AES.</returns>
        public static string Encrypt<TSettings>(TSettings settings, byte[] key)
            where TSettings : class, new()
        {
            if (settings == null)
                throw new ArgumentNullException(nameof(settings));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            var json = Encoding.UTF8.GetBytes(JsonSerializer.Serialize<TSettings>(settings));
            return Encrypt(json, key);
        }

        /// <summary>
        /// Decrypts an input string using AES with a 256 bits key in GCM authenticated mode.
        /// </summary>
        /// <param name="cipher">The base64 encoded input cipher to decrypt.</param>
        /// <param name="key">The encryption key being used.</param>
        /// <returns>The decrypted output string.</returns>
        public static string Decrypt(string cipher, string key)
        {
            if (string.IsNullOrEmpty(cipher))
                throw new ArgumentNullException(nameof(cipher));

            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));
            
            var aes = new AEAD_AES_256_GCM();
            return Encoding.UTF8.GetString(aes.DecryptString(cipher, key));
        }

        /// <summary>
        /// Encrypts an input byte array using AES with a 256 bits key in GCM authenticated mode.
        /// </summary>
        /// <param name="cipher">The byte array of the cipher to decrypt.</param>
        /// <param name="key">The encryption key being used.</param>
        /// <returns>The decrypted output string.</returns>
        public static string Decrypt(byte[] cipher, byte[] key)
        {
            if (cipher == null)
                throw new ArgumentNullException(nameof(cipher));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            var aes = new AEAD_AES_256_GCM();
            return Encoding.UTF8.GetString(aes.DecryptString(cipher, key));
        }
    }
}
