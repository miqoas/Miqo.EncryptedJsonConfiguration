using Microsoft.Extensions.Configuration;

namespace Miqo.EncryptedJsonConfiguration
{
    /// <summary>
    /// Represents a JSON file as an <see cref="IConfigurationSource"/>.
    /// </summary>
    public class EncryptedJsonConfigurationSource : FileConfigurationSource
    {
        /// <summary>
        /// Encryption key used  to decrypt the configuration file
        /// </summary>
        internal byte[] Key { get; set; }

        /// <summary>
        /// Builds the <see cref="EncryptedJsonConfigurationProvider"/> for this source.
        /// </summary>
        /// <param name="builder">The <see cref="IConfigurationBuilder"/>.</param>
        /// <returns>A <see cref="EncryptedJsonConfigurationProvider"/></returns>
        public override IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            EnsureDefaults(builder);
            return new EncryptedJsonConfigurationProvider(this);
        }
    }
}