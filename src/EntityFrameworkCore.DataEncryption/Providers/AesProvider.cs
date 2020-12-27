using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.EntityFrameworkCore.DataEncryption.Providers
{
    /// <summary>
    /// Implements the Advanced Encryption Standard (AES) symmetric algorithm.
    /// </summary>
    public class AesProvider : IEncryptionProvider
    {
        /// <summary>
        /// AES block size constant.
        /// </summary>
        public const int AesBlockSize = 128;

        /// <summary>
        /// Initialization vector size constant.
        /// </summary>
        public const int InitializationVectorSize = 16;

        private readonly byte[] _key;
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;

        /// <summary>
        /// Creates a new <see cref="AesProvider"/> instance used to perform symetric encryption and decryption on strings.
        /// </summary>
        /// <param name="key">AES key used for the symetric encryption.</param>
        /// <param name="mode">Mode for operation used in the symetric encryption.</param>
        /// <param name="padding">Padding mode used in the symetric encryption.</param>
        public AesProvider(byte[] key, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            _key = key;
            _mode = mode;
            _padding = padding;
        }

        /// <summary>
        /// Creates a new <see cref="AesProvider"/> instance used to perform symetric encryption and decryption on strings.
        /// </summary>
        /// <param name="key">AES key used for the symetric encryption.</param>
        /// <param name="initializationVector">AES Initialization Vector used for the symetric encryption.</param>
        /// <param name="mode">Mode for operation used in the symetric encryption.</param>
        /// <param name="padding">Padding mode used in the symetric encryption.</param>
        [Obsolete("This constructor has been deprecated and will be removed in future versions. Please use the AesProvider(byte[], CipherMode, PaddingMode) constructor instead.")]
        public AesProvider(byte[] key, byte[] initializationVector, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
            : this(key, mode, padding)
        {
        }

        /// <summary>
        /// Encrypt a string using the AES algorithm.
        /// </summary>
        /// <param name="dataToEncrypt">Input data as a string to encrypt.</param>
        /// <returns>Encrypted data as a string.</returns>
        public string Encrypt(string dataToEncrypt)
        {
            byte[] input = Encoding.UTF8.GetBytes(dataToEncrypt);
            byte[] encrypted = Encrypt(input);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts a string using the AES algorithm.
        /// </summary>
        /// <param name="dataToEncrypt">Input data as a string to encrypt.</param>
        /// <returns>Encrypted data as a string.</returns>
        public byte[] Encrypt(byte[] dataToEncrypt)
        {
            byte[] encrypted = null;

            using (AesCryptoServiceProvider cryptoServiceProvider = CreateCryptographyProvider())
            {
                cryptoServiceProvider.GenerateIV();

                byte[] initializationVector = cryptoServiceProvider.IV;

                using ICryptoTransform encryptor = cryptoServiceProvider.CreateEncryptor(_key, initializationVector);
                using var memoryStream = new MemoryStream();
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    memoryStream.Write(initializationVector, 0, initializationVector.Length);
                    cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    cryptoStream.FlushFinalBlock();
                }

                encrypted = memoryStream.ToArray();
            }

            return encrypted;
        }

        /// <summary>
        /// Decrypts a string using the AES algorithm.
        /// </summary>
        /// <param name="dataToDecrypt">Encrypted data as a string to decrypt.</param>
        /// <returns>Decrypted data as a string.</returns>
        public string Decrypt(string dataToDecrypt)
        {
            byte[] input = Convert.FromBase64String(dataToDecrypt);

            string decrypted = string.Empty;

            using (var memoryStream = new MemoryStream(input))
            {
                var initializationVector = new byte[InitializationVectorSize];

                memoryStream.Read(initializationVector, 0, initializationVector.Length);

                using AesCryptoServiceProvider cryptoServiceProvider = CreateCryptographyProvider();
                using ICryptoTransform cryptoTransform = cryptoServiceProvider.CreateDecryptor(_key, initializationVector);
                using var crypto = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read);
                using var reader = new StreamReader(crypto);

                decrypted = reader.ReadToEnd().Trim('\0');
            }

            return decrypted;
        }

        /// <summary>
        /// Decrypts a byte array using the AES algorithm.
        /// </summary>
        /// <param name="dataToDecrypt"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] dataToDecrypt)
        {
            using (var memoryStream = new MemoryStream(dataToDecrypt))
            {
                var initializationVector = new byte[InitializationVectorSize];

                memoryStream.Read(initializationVector, 0, initializationVector.Length);

                using AesCryptoServiceProvider cryptoServiceProvider = CreateCryptographyProvider();
                using ICryptoTransform cryptoTransform = cryptoServiceProvider.CreateDecryptor(_key, initializationVector);
                using var crypto = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read);
                using var reader = new MemoryStream();
                crypto.CopyTo(reader);
                return reader.ToArray();
            }
        }

        /// <summary>
        /// Generates an AES cryptography provider.
        /// </summary>
        /// <returns></returns>
        private AesCryptoServiceProvider CreateCryptographyProvider()
        {
            return new AesCryptoServiceProvider
            {
                BlockSize = AesBlockSize,
                Mode = _mode,
                Padding = _padding,
                Key = _key,
                KeySize = _key.Length * 8
            };
        }

        /// <summary>
        /// Generates an AES key.
        /// </summary>
        /// <remarks>
        /// The key size of the Aes encryption must be 128, 192 or 256 bits. 
        /// Please check https://blogs.msdn.microsoft.com/shawnfa/2006/10/09/the-differences-between-rijndael-and-aes/ for more informations.
        /// </remarks>
        /// <param name="keySize">AES Key size</param>
        /// <returns></returns>
        public static AesKeyInfo GenerateKey(AesKeySize keySize)
        {
            var crypto = new AesCryptoServiceProvider
            {
                KeySize = (int)keySize,
                BlockSize = AesBlockSize
            };

            crypto.GenerateKey();
            crypto.GenerateIV();

            return new AesKeyInfo(crypto.Key, crypto.IV);
        }

    }
}
