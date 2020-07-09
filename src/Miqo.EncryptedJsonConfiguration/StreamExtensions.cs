using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Miqo.EncryptedJsonConfiguration
{
    internal static class StreamExtensions
    {
        public static byte[] ToBytes(this Stream input)
        {
            using var ms = new MemoryStream();
            input.CopyTo(ms);
            return ms.ToArray();
        }
    }
}
