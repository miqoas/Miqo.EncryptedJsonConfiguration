using System;
using System.IO;
using System.Security.Authentication;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;

namespace Miqo.EncryptedJsonConfiguration
{
    /// <summary>
    /// Extension methods for adding <see cref="EncryptedJsonConfigurationProvider"/>.
    /// </summary>
    public static class ConfigurationBuilderExtenions
    {
        /// <summary>
        /// Adds the encrypted JSON configuration provider at <paramref name="path"/> to <paramref name="builder"/>.
        /// </summary>
        /// <param name="builder">The <see cref="IConfigurationBuilder"/> to add to.</param>
        /// <param name="path">Path relative to the base path stored in
        /// <see cref="IConfigurationBuilder.Properties"/> of <paramref name="builder"/>.</param>
        /// <param name="key">The encryption key</param>
        /// <returns>The <see cref="IConfigurationBuilder"/>.</returns>
        public static IConfigurationBuilder AddEncryptedJsonFile(this IConfigurationBuilder builder, string path, byte[] key)
        {
            return AddEncryptedJsonFile(builder, provider: null, path: path, optional: false, reloadOnChange: false, key: key);
        }

        /// <summary>
        /// Adds the encrypted JSON configuration provider at <paramref name="path"/> to <paramref name="builder"/>.
        /// </summary>
        /// <param name="builder">The <see cref="IConfigurationBuilder"/> to add to.</param>
        /// <param name="path">Path relative to the base path stored in
        /// <see cref="IConfigurationBuilder.Properties"/> of <paramref name="builder"/>.</param>
        /// <param name="optional">Whether the file is optional.</param>
        /// <param name="key">The encryption key</param>
        /// <returns>The <see cref="IConfigurationBuilder"/>.</returns>
        public static IConfigurationBuilder AddEncryptedJsonFile(this IConfigurationBuilder builder, string path, bool optional, byte[] key)
        {
            return AddEncryptedJsonFile(builder, provider: null, path: path, optional: optional, reloadOnChange: false, key: key);
        }

        /// <summary>
        /// Adds the encrypted JSON configuration provider at <paramref name="path"/> to <paramref name="builder"/>.
        /// </summary>
        /// <param name="builder">The <see cref="IConfigurationBuilder"/> to add to.</param>
        /// <param name="path">Path relative to the base path stored in
        /// <see cref="IConfigurationBuilder.Properties"/> of <paramref name="builder"/>.</param>
        /// <param name="optional">Whether the file is optional.</param>
        /// <param name="reloadOnChange">Whether the configuration should be reloaded if the file changes.</param>
        /// <param name="key">The encryption key</param>
        /// <returns>The <see cref="AddEncryptedJsonFile"/>.</returns>
        public static IConfigurationBuilder AddJsonFile(this IConfigurationBuilder builder, string path, bool optional, bool reloadOnChange, byte[] key)
        {
            return AddEncryptedJsonFile(builder, provider: null, path: path, optional: optional, reloadOnChange: reloadOnChange, key: key);
        }

        /// <summary>
        /// Adds an encrypted JSON configuration source to <paramref name="builder"/>.
        /// </summary>
        /// <param name="builder">The <see cref="IConfigurationBuilder"/> to add to.</param>
        /// <param name="provider">The <see cref="IFileProvider"/> to use to access the file.</param>
        /// <param name="path">Path relative to the base path stored in
        /// <see cref="IConfigurationBuilder.Properties"/> of <paramref name="builder"/>.</param>
        /// <param name="optional">Whether the file is optional.</param>
        /// <param name="reloadOnChange">Whether the configuration should be reloaded if the file changes.</param>
        /// <param name="key">The encryption key</param>
        /// <returns>The <see cref="IConfigurationBuilder"/>.</returns>
        public static IConfigurationBuilder AddEncryptedJsonFile(this IConfigurationBuilder builder, IFileProvider provider, string path, bool optional, bool reloadOnChange, byte[] key)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("File path must be a non-empty string", nameof(path));
            }

            return builder.AddEncryptedJsonFile(s =>
            {
                s.FileProvider = provider;
                s.Path = path;
                s.Optional = optional;
                s.Key = key;
                s.ReloadOnChange = reloadOnChange;
                s.ResolveFileProvider();
            });
        }

        /// <summary>
        /// Adds an encrypted JSON configuration source to <paramref name="builder"/>.
        /// </summary>
        /// <param name="builder">The <see cref="IConfigurationBuilder"/> to add to.</param>
        /// <param name="configureSource">Configures the source.</param>
        /// <param name="key">The encryption key</param>
        /// <returns>The <see cref="IConfigurationBuilder"/>.</returns>
        public static IConfigurationBuilder AddEncryptedJsonFile(this IConfigurationBuilder builder, Action<EncryptedJsonConfigurationSource> configureSource)
            => builder.Add(configureSource);

        /// <summary>
        /// Adds a JSON configuration source to <paramref name="builder"/>.
        /// </summary>
        /// <param name="builder">The <see cref="IConfigurationBuilder"/> to add to.</param>
        /// <param name="stream">The <see cref="Stream"/> to read the json configuration data from.</param>
        /// <param name="key">The encryption key</param>
        /// <returns>The <see cref="IConfigurationBuilder"/>.</returns>
        public static IConfigurationBuilder AddEncryptedJsonStream(this IConfigurationBuilder builder, Stream stream, byte[] key)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.Add<EncryptedJsonStreamConfigurationSource>(s =>
            {
                s.Stream = stream;
                s.Key = key;
            });
        }
    }
}
