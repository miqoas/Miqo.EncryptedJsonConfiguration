/*
 *      Alessandro Cagliostro, 2020
 *      
 *      https://github.com/alecgn
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace CryptHash.Net
{
    public abstract class AesGcmBase
    {
        #region fields

        private int _keyBitSize;
        internal int KeyBitSize {
            get => _keyBitSize;
            set {
                _keyBitSize = value;
                _keyBytesLength = (_keyBitSize / 8);
            }
        }

        private int _keyBytesLength;

        private const int _saltBitSize = 128;
        private const int _saltBytesLength = (_saltBitSize / 8);

        private const int _nonceBitSize = 96;
        private const int _nonceBytesLength = (_nonceBitSize / 8);

        private const int _tagBitSize = 128;
        private const int _tagBytesLength = (_tagBitSize / 8);

        // Maximum input size -> 2^39 - 256 bits
        // (long)((Math.Pow(2, 39) - 256) / 8) -> 68,719,476,704 bytes or ≅ 63.9 gigaBytes...
        private const long _maxInputDataSizeBytes = 68719476704;

        // Maximum input authenticated data size -> 2^64 - 1 bit
        // (long)((BigInteger.Pow(2, 64) - 1) / 8) -> 2,305,843,009,213,693,951 bytes or ≅ 2,147,483,647 gigaBytes or 2,097,151 teraBytes...
        private const long _maxInputAuthDataSizeBytes = 2305843009213693951;

        private const int _iterationsForPBKDF2 = 100000;

        #endregion private fields


        #region constructors

        internal AesGcmBase(int keyBitSize)
        {
            if (new int[] { 128, 192, 256 }.Contains(keyBitSize))
                KeyBitSize = keyBitSize;
            else
                throw new ArgumentException($"Invalid key bit size: ({keyBitSize}).", nameof(keyBitSize));
        }

        #endregion constructors


        #region internal methods

        #region string encryption
        internal byte[] EncryptString(string plainString, string password, string associatedDataString = null, bool appendEncryptionDataToOutput = true)
        {
            if (string.IsNullOrEmpty(plainString))
                throw new ArgumentNullException("Input to encrypt required.", nameof(plainString));
            
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException("Password to encrypt required.", nameof(password));

            var plainStringBytes = System.Text.Encoding.UTF8.GetBytes(plainString);
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutput);
        }

        internal byte[] EncryptString(string plainString, SecureString secStrPassword, string associatedDataString = null, bool appendEncryptionDataToOutput = true)
        {
            if (string.IsNullOrWhiteSpace(plainString))
                throw new ArgumentNullException("Input to encrypt required.", nameof(plainString));

            if (secStrPassword == null || secStrPassword.Length <= 0)
                throw new ArgumentNullException("Password to encrypt required.", nameof(secStrPassword));

            var plainStringBytes = System.Text.Encoding.UTF8.GetBytes(plainString);
            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutput);
        }

        internal byte[] EncryptString(byte[] plainStringBytes, SecureString secStrPassword, string associatedDataString = null, bool appendEncryptionDataToOutput = true)
        {
            if (plainStringBytes == null || plainStringBytes.Length <= 0)
                throw new ArgumentNullException("Input to encrypt required.", nameof(plainStringBytes));

            if (secStrPassword == null || secStrPassword.Length <= 0)
                throw new ArgumentNullException("Password to encrypt required.", nameof(secStrPassword));

            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return EncryptString(plainStringBytes, passwordBytes, associatedDataBytes, appendEncryptionDataToOutput);
        }

        internal byte[] EncryptString(byte[] plainStringBytes, byte[] passwordBytes, byte[] associatedData = null, bool appendEncryptionDataToOutput = true)
        {
            if (plainStringBytes == null || plainStringBytes.Length == 0)
                throw new ArgumentNullException("Input to encrypt required.", nameof(plainStringBytes));

            if (plainStringBytes.LongLength > _maxInputDataSizeBytes)
                throw new ArgumentException("Max. input size cannot be greater in bytes than: ({_maxInputDataSizeBytes}).", nameof(plainStringBytes));

            if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
                throw new ArgumentException("Max. associated data size cannot be greater in bytes than: ({_maxInputDataSizeBytes}).", nameof(plainStringBytes));

            byte[] salt = CommonMethods.GenerateSalt();
            byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, _keyBytesLength, _iterationsForPBKDF2, HashAlgorithmName.SHA512);
            byte[] nonce = CommonMethods.GenerateRandomBytes(_nonceBytesLength);
            byte[] tag = new byte[_tagBytesLength];
            byte[] encryptedData = new byte[plainStringBytes.Length];

            using (var aesGcm = new AesGcm(derivedKey))
            {
                aesGcm.Encrypt(nonce, plainStringBytes, encryptedData, tag, associatedData);
            }

            if (appendEncryptionDataToOutput)
            {
                using var ms = new MemoryStream();
                using (var bw = new BinaryWriter(ms))
                {
                    bw.Write(encryptedData);
                    bw.Write(nonce);
                    bw.Write(salt);
                    bw.Write(tag);
                }

                encryptedData = ms.ToArray();
            }

            return encryptedData;
        }

        #endregion string encryption


        #region string decryption

        internal byte[] DecryptString(string base64EncryptedString, string password, string associatedDataString = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            if (string.IsNullOrEmpty(base64EncryptedString))
                throw new ArgumentNullException("Input to decrypt required.", nameof(base64EncryptedString));

            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException("Password to decrypt required.", nameof(password));

            var encryptedStringBytes = Convert.FromBase64String(base64EncryptedString);
            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(encryptedStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInput, tag, salt, nonce);
        }

        internal byte[] DecryptString(string base64EncryptedString, SecureString secStrPassword, string associatedDataString = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            if (string.IsNullOrWhiteSpace(base64EncryptedString))
                throw new ArgumentNullException("Input to decrypt required.", nameof(base64EncryptedString));

            if (secStrPassword == null || secStrPassword.Length <= 0)
                throw new ArgumentNullException("Password to decrypt required.", nameof(secStrPassword));

            var plainStringBytes = System.Text.Encoding.UTF8.GetBytes(base64EncryptedString);
            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(plainStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInput, tag, salt, nonce);
        }

        internal byte[] DecryptString(byte[] encryptedStringBytes, SecureString secStrPassword, string associatedDataString = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            if (encryptedStringBytes == null || encryptedStringBytes.Length <= 0)
                throw new ArgumentNullException("Input to decrypt required.", nameof(encryptedStringBytes));

            if (secStrPassword == null || secStrPassword.Length <= 0)
                throw new ArgumentNullException("Password to decrypt required.", nameof(secStrPassword));

            var passwordBytes = CommonMethods.ConvertSecureStringToByteArray(secStrPassword);
            var associatedDataBytes = (associatedDataString == null ? null : System.Text.Encoding.UTF8.GetBytes(associatedDataString));

            return DecryptString(encryptedStringBytes, passwordBytes, associatedDataBytes, hasEncryptionDataAppendedInInput, tag, salt, nonce);
        }

        internal byte[] DecryptString(byte[] encryptedStringBytes, byte[] passwordBytes, byte[] associatedData = null, bool hasEncryptionDataAppendedInInput = true,
            byte[] tag = null, byte[] salt = null, byte[] nonce = null)
        {
            if (encryptedStringBytes == null || encryptedStringBytes.Length == 0)
                throw new ArgumentNullException("Input to decrypt required.", nameof(encryptedStringBytes));

            
            if (encryptedStringBytes.LongLength > _maxInputDataSizeBytes)
                throw new ArgumentException("Max. encrypted input size cannot be greater in bytes than: {_maxInputDataSizeBytes}).", nameof(encryptedStringBytes));

            if (passwordBytes == null)
                throw new ArgumentNullException("Password to decrypt required.", nameof(passwordBytes));

            if (associatedData != null && associatedData.LongLength > _maxInputAuthDataSizeBytes)
                throw new ArgumentException("Max. encrypted input size cannot be greater in bytes than: {_maxInputDataSizeBytes}).", nameof(encryptedStringBytes));

            byte[] encryptedStringBytesWithEncryptionData = null;

            if (hasEncryptionDataAppendedInInput)
            {
                tag = new byte[_tagBytesLength];
                Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength), tag, 0, tag.Length);

                salt = new byte[_saltBytesLength];
                Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength), salt, 0, salt.Length);

                nonce = new byte[_nonceBytesLength];
                Array.Copy(encryptedStringBytes, (encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength - _nonceBytesLength), nonce, 0, nonce.Length);

                encryptedStringBytesWithEncryptionData = new byte[(encryptedStringBytes.Length - _tagBytesLength - _saltBytesLength - _nonceBytesLength)];
                Array.Copy(encryptedStringBytes, 0, encryptedStringBytesWithEncryptionData, 0, encryptedStringBytesWithEncryptionData.Length);
            }

            byte[] derivedKey = CommonMethods.GetHashedBytesFromPBKDF2(passwordBytes, salt, _keyBytesLength, _iterationsForPBKDF2, HashAlgorithmName.SHA512);
            byte[] decryptedData = new byte[(hasEncryptionDataAppendedInInput ? encryptedStringBytesWithEncryptionData.Length : encryptedStringBytes.Length)];

            using (var aesGcm = new AesGcm(derivedKey))
            {
                aesGcm.Decrypt(nonce, (hasEncryptionDataAppendedInInput ? encryptedStringBytesWithEncryptionData : encryptedStringBytes), tag, decryptedData, associatedData);
            }

            return decryptedData;
        }

        #endregion string decryption

        #endregion internal methods
    }
}
