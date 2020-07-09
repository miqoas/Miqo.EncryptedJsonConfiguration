using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using Xunit;
using Miqo.EncryptedJsonConfiguration;
using System.Security.Cryptography;

namespace Miqo.EncryptedJsonConfigurationTests
{
    public class EncryptedJsonConfigurationTests
    {
        [Fact]
        public void AddEncryptedJsonStream_When_GivenSettingsStreamAndKey_Then_BuildsConfiguration()
        {
            var apiKey = "api1.538c9073e4eb4461a87f1947bd47adb2bdd3a53bb26d4daf81d1e21b2039aab1";
            var settings = new AppSettings { ConnectionString = "pgsqlconnectionstring", EmailApiKey = apiKey };
            var key = AesEncryptionHelpers.GenerateKey();

            var cipher = Convert.FromBase64String(AesEncryptionHelpers.Encrypt<AppSettings>(settings, key));
            using var stream = new MemoryStream(cipher);
            var configuration = new ConfigurationBuilder()
                .AddEncryptedJsonStream(stream, key)
                .Build();

            Assert.Equal(apiKey, configuration["EmailApiKey"]);
        }

        [Fact]
        public void AddEncryptedJsonFile_When_GivenSettingsFileAndKey_Then_BuildsConfiguration()
        {
            // The key and the settings.ejson file were created using the Kizuna command line tool
            // https://github.com/miqoas/kizuna

            var apiKey = "api1.538c9073e4eb4461a87f1947bd47adb2bdd3a53bb26d4daf81d1e21b2039aab1";
            var key = Convert.FromBase64String("A4HKnoCR/bdUOhogBi3EJpsEboYabtTy010eAoV8wKA=");

            var configuration = new ConfigurationBuilder()
                .AddEncryptedJsonFile("settings.ejson", key)
                .Build();

            Assert.Equal(apiKey, configuration["EmailApiKey"]);
        }

        [Fact]
        public void AddEncryptedJsonStream_When_IncorrectKey_Then_ThrowsCryptographicException()
        {
            var apiKey = "api1.538c9073e4eb4461a87f1947bd47adb2bdd3a53bb26d4daf81d1e21b2039aab1";
            var settings = new AppSettings { ConnectionString = "pgsqlconnectionstring", EmailApiKey = apiKey };
            var encryptionKey = AesEncryptionHelpers.GenerateKey();
            var incorrectKey = AesEncryptionHelpers.GenerateKey();

            var cipher = Convert.FromBase64String(AesEncryptionHelpers.Encrypt<AppSettings>(settings, encryptionKey));
            using var stream = new MemoryStream(cipher);
            Assert.Throws<CryptographicException>(() =>
            {
                var configuration = new ConfigurationBuilder()
                    .AddEncryptedJsonStream(stream, incorrectKey)
                    .Build();
            });
        }

        [Fact]
        public void AddEncryptedJsonFile_When_FileNotFound_Then_ThrowsCryptographicException()
        {
            var key = AesEncryptionHelpers.GenerateKey();

            Assert.Throws<FileNotFoundException>(() =>
            {
                var configuration = new ConfigurationBuilder()
                    .AddEncryptedJsonFile("file_not_found.ejson", key)
                    .Build();
            });
        }


        [Fact]
        public void AddEncryptedJsonStream_When_GivenNonJsonSteam_Then_ThrowsException()
        {
            var key = Convert.FromBase64String("A4HKnoCR/bdUOhogBi3EJpsEboYabtTy010eAoV8wKA=");
            var cipher = Convert.FromBase64String("EFgImF9/q8aV045zJ84+qSYhPltQnGM/ryj9N5JO5jMk21V/1FidLuw6uI5RnTI=");

            using var stream = new MemoryStream(cipher);
            Assert.Throws<FormatException>(() =>
            {
                var configuration = new ConfigurationBuilder()
                    .AddEncryptedJsonStream(stream, key)
                    .Build();
            });
        }
    }
}
