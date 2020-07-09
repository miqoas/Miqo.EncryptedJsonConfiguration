/*
 *      Alessandro Cagliostro, 2020
 *      
 *      https://github.com/alecgn
 */

using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace CryptHash.Net
{
    public static class CommonMethods
    {
        public static byte[] GenerateRandomBytes(int length)
        {
            var randomBytes = new byte[length];

            using (RNGCryptoServiceProvider rngCSP = new RNGCryptoServiceProvider())
            {
                rngCSP.GetBytes(randomBytes);
            }

            return randomBytes;
        }

        public static byte[] Generate128BitKey()
        {
            return GenerateRandomBytes(128 / 8);
        }

        public static byte[] GenerateSalt(int saltLength = 0)
        {
            return (saltLength == 0 ? Generate128BitKey() : GenerateRandomBytes(saltLength));
        }

        public static byte[] Generate256BitKey()
        {
            return GenerateRandomBytes(256 / 8);
        }

        public static byte[] GetHashedBytesFromPBKDF2(byte[] passwordBytes, byte[] saltBytes, int keyBytesLength, int iterations/*, HashAlgorithmName hashAlgorithmName*/)
        {
            byte[] pbkdf2HashedBytes;

            using (var pbkdf2 = new Rfc2898DeriveBytes(passwordBytes, saltBytes, iterations/*, hashAlgorithmName*/))
            {
                pbkdf2HashedBytes = pbkdf2.GetBytes(keyBytesLength);
            }

            return pbkdf2HashedBytes;
        }

        public static byte[] GetHashedBytesFromPBKDF2(byte[] passwordBytes, byte[] saltBytes, int keyBytesLength, int iterations, HashAlgorithmName hashAlgorithmName)
        {
            byte[] pbkdf2HashedBytes;

            using (var pbkdf2 = new Rfc2898DeriveBytes(passwordBytes, saltBytes, iterations, hashAlgorithmName))
            {
                pbkdf2HashedBytes = pbkdf2.GetBytes(keyBytesLength);
            }

            return pbkdf2HashedBytes;
        }

        public static byte[] ConvertSecureStringToByteArray(SecureString secString)
        {
            byte[] byteArray = new byte[secString.Length];
            IntPtr bstr = IntPtr.Zero;

            RuntimeHelpers.ExecuteCodeWithGuaranteedCleanup(
                    delegate
                    {
                        RuntimeHelpers.PrepareConstrainedRegions();
                        try { }
                        finally
                        {
                            bstr = Marshal.SecureStringToBSTR(secString);
                        }

                        Marshal.Copy(bstr, byteArray, 0, secString.Length);
                    },
                    delegate
                    {
                        if (bstr != IntPtr.Zero)
                        {
                            Marshal.ZeroFreeBSTR(bstr);
                            bstr = IntPtr.Zero;
                        }
                    },
                    null);

            return byteArray;
        }

        public static void ClearFileAttributes(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"File not found: {filePath}.", nameof(filePath));

            File.SetAttributes(filePath, FileAttributes.Normal);
        }

        public static void AppendDataBytesToFile(string filePath, byte[] dataBytes)
        {
            using FileStream fs = File.Open(filePath, FileMode.Append, FileAccess.Write, FileShare.None);
            fs.Write(dataBytes, 0, dataBytes.Length);
        }

        public static byte[] GetBytesFromFile(string filePath, int dataLength, long offset = 0)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"File not found: {filePath}.", filePath);

            if (dataLength < 1)
                throw new ArgumentException($"Invalid data length: ({dataLength}).", nameof(dataLength));

            byte[] dataBytes = new byte[dataLength];

            using (FileStream fStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                fStream.Seek(offset, SeekOrigin.Begin);
                fStream.Read(dataBytes, 0, dataLength);
                fStream.Close();
            }

            return dataBytes;
        }

        public static bool TagsMatch(byte[] calcTag, byte[] sentTag)
        {
            if (calcTag.Length != sentTag.Length)
                throw new ArgumentException("Tags length must be equal");

            var result = true;
            var compare = 0;

            for (var i = 0; i < sentTag.Length; i++)
            {
                compare |= sentTag[i] ^ calcTag[i];
            }

            if (compare != 0)
                result = false;

            return result;
        }
    }
}