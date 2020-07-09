using System;
using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using CryptHash.Net;

namespace Miqo.EncryptedJsonConfiguration
{
    /// <summary>
    /// Loads configuration key/values from a JSON stream into a provider.
    /// </summary>
    public class EncryptedJsonStreamConfigurationProvider : StreamConfigurationProvider
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="source">The <see cref="JsonStreamConfigurationSource"/>.</param>
        public EncryptedJsonStreamConfigurationProvider(EncryptedJsonStreamConfigurationSource source) : base(source) { }

        /// <summary>
        /// Loads JSON configuration key/values from a stream into a provider.
        /// </summary>
        /// <param name="stream">The encrypted JSON <see cref="Stream"/> to load configuration data from.</param>
        public override void Load(Stream stream)
        {
            var source = (EncryptedJsonStreamConfigurationSource)Source;

            try
            {
                var encryptedSettings = stream.ToBytes();
                var aes = new AEAD_AES_256_GCM();
                var settings = aes.DecryptString(encryptedSettings, source.Key);

                Data = EncryptedJsonConfigurationFileParser.Parse(new MemoryStream(settings));
            }
            catch (JsonException e)
            {
                throw new FormatException("Could not parse the encrypted JSON stream", e);
            }
        }
    }
}