using CryptHash.Net;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Miqo.EncryptedJsonConfiguration
{
    /// <summary>
    /// An Encrypted JSON file based <see cref="EncryptedFileConfigurationProvider"/>.
    /// </summary>
    public class EncryptedJsonConfigurationProvider : FileConfigurationProvider
    {
        /// <summary>
        /// Initializes a new instance with the specified source.
        /// </summary>
        /// <param name="source">The source settings.</param>
        public EncryptedJsonConfigurationProvider(EncryptedJsonConfigurationSource source) : base(source) { }

        /// <summary>
        /// Loads JSON configuration key/values from a stream into a provider.
        /// </summary>
        public override void Load()
        {
            var source = (EncryptedJsonConfigurationSource)Source;

            try
            {
                var text = Convert.FromBase64String(File.ReadAllText(source.Path));
                var aes = new AEAD_AES_256_GCM();
                var settings = aes.DecryptString(text, source.Key);

                Data = EncryptedJsonConfigurationFileParser.Parse(new MemoryStream(settings));
            }
            catch (JsonException e)
            {
                throw new FormatException("Could not parse the encrypted JSON file", e);
            }
        }

        /// <summary>
        /// Loads JSON configuration key/values from a stream into a provider.
        /// </summary>
        /// <param name="stream">The stream to read.</param>
        public override void Load(Stream stream)
        {
            var source = (EncryptedJsonConfigurationSource)Source;

            try
            {
                var encryptedSettings = stream.ToBytes();
                var aes = new AEAD_AES_256_GCM();
                var settings = aes.DecryptString(encryptedSettings, source.Key);

                Data = EncryptedJsonConfigurationFileParser.Parse(new MemoryStream(settings));
            }
            catch (JsonException e)
            {
                throw new FormatException("Could not parse the encrypted JSON file", e);
            }
        }
    }
}
