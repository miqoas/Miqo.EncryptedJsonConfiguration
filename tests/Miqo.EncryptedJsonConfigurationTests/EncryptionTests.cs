using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;
using Miqo.EncryptedJsonConfiguration;

namespace Miqo.EncryptedJsonConfigurationTests
{
    public class EncryptionTests
    {
        [Fact]
        public void Encrypt_When_GivenSettingsAndKey_Then_EncryptedJson()
        {
            var settings = new AppSettings { ConnectionString = "pgsqlconnectionstring", EmailApiKey = "api1.538c9073e4eb4461a87f1947bd47adb2bdd3a53bb26d4daf81d1e21b2039aab1" };
            var key = AesEncryptionHelpers.GenerateKey();

            var encrypted = AesEncryptionHelpers.Encrypt<AppSettings>(settings, key);
            Assert.NotNull(encrypted);
        }

        [Fact]
        public void Decrypt_When_GivenSettingsAndKey_Then_DecryptedJson()
        {
            var apiKey = "api1.538c9073e4eb4461a87f1947bd47adb2bdd3a53bb26d4daf81d1e21b2039aab1";
            var settings = new AppSettings { ConnectionString = "pgsqlconnectionstring", EmailApiKey = apiKey };
            var key = AesEncryptionHelpers.GenerateBase64EncodedKey();

            var encrypted = AesEncryptionHelpers.Encrypt<AppSettings>(settings, key);
            var decrypted = AesEncryptionHelpers.Decrypt(encrypted, key);

            var result = JsonSerializer.Deserialize<AppSettings>(decrypted);
            Assert.Equal(apiKey, result.EmailApiKey);
        }

        [Fact]
        public void Decrypt_When_GivenNoSettings_Then_ThrowsArgumentNullException()
        {
            var key = AesEncryptionHelpers.GenerateKey();

            Assert.Throws<ArgumentNullException>(() =>
            {
                var encrypted = AesEncryptionHelpers.Encrypt(Array.Empty<byte>(), key);
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                var encrypted = AesEncryptionHelpers.Encrypt(null, key);
            });
        }

        [Fact]
        public void Decrypt_When_IncorrectKey_Then_ThrowsCryptographicException()
        {
            var settings = new AppSettings { ConnectionString = "pgsqlconnectionstring", EmailApiKey = "api1.538c9073e4eb4461a87f1947bd47adb2bdd3a53bb26d4daf81d1e21b2039aab1" };
            var key = AesEncryptionHelpers.GenerateBase64EncodedKey();
            var incorrectKey = AesEncryptionHelpers.GenerateBase64EncodedKey();

            var encrypted = AesEncryptionHelpers.Encrypt<AppSettings>(settings, key);
            Assert.Throws<CryptographicException>(() =>
            {
                var decrypted = AesEncryptionHelpers.Decrypt(encrypted, incorrectKey);
            });
        }
    }
}
