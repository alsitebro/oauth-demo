using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AuthorisationServer
{
    public class Cryptographer : ICryptographer
    {
        public string Encrypt(string key, string input)
        {
            using (var rijndael = Rijndael.Create())
            {
                byte[] encryptedInput = EncryptStringToBytes(input, Encoding.ASCII.GetBytes(key),
                    Encoding.ASCII.GetBytes($"{key}{DateTime.Today:yy-MM-dd}"));
                var output = Convert.ToBase64String(encryptedInput);
                return output;
            }
        }

        public string Decrypt(string key, string input)
        {
            using (var rijndael = Rijndael.Create())
            {
                var output = DecryptStringFromBytes(Convert.FromBase64String(input), Encoding.ASCII.GetBytes(key),
                    Encoding.ASCII.GetBytes($"{key}{DateTime.Today:yy-MM-dd}"));
                return output;
            }
        }

        public string Hash(string input)
        {
            using(var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.Default.GetBytes(input));
                var sb = new StringBuilder();
                foreach (var item in hash)
                {
                    sb.Append(item);
                }
                return sb.ToString();
            }
        }

        private string DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] initialisationVector)
        {
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException(nameof(cipherText));
            }

            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (initialisationVector == null || initialisationVector.Length <= 0)
            {
                throw new ArgumentNullException(nameof(initialisationVector));
            }

            string result;

            using (Rijndael rijAlg = Rijndael.Create())
            {
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.Key = CalibrateSymmetricKey(key);
                rijAlg.IV = CalibrateInitialisationVector(initialisationVector);

                var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                using (var memoryStream = new MemoryStream(cipherText))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream))
                        {
                            result = streamReader.ReadToEnd();
                        }
                    }
                }
            }

            return result;
        }

        private byte[] EncryptStringToBytes(string stringToEncrypt, byte[] symmetricKey, byte[] initialisationVector)
        {
            if (stringToEncrypt == null || stringToEncrypt.Length <= 0)
            {
                throw new ArgumentNullException(nameof(stringToEncrypt));
            }

            if (symmetricKey == null || symmetricKey.Length <= 0)
            {
                throw new ArgumentNullException(nameof(symmetricKey));
            }

            if (initialisationVector == null || initialisationVector.Length <= 0)
            {
                throw new ArgumentNullException(nameof(initialisationVector));
            }

            byte[] encrypted;

            using (var rijAlg = Rijndael.Create())
            {
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.Key = CalibrateSymmetricKey(symmetricKey); // 32bit
                rijAlg.IV = CalibrateInitialisationVector(initialisationVector); // 16bit
                var encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(stringToEncrypt);
                        }

                        encrypted = memoryStream.ToArray();
                    }
                }
            }

            return encrypted;
        }

        private byte[] CalibrateInitialisationVector(byte[] initialisationVector)
        {
            byte[] iv = new byte[16];
            if (initialisationVector.Length < 16)
            {
                var padding = 16 - initialisationVector.Length;
                for (var i = 0; i < initialisationVector.Length; i++)
                {
                    iv[i] = initialisationVector[i];
                }

                for (var p = initialisationVector.Length; p < 16; p++)
                {
                    iv[p] = byte.MinValue;
                }
            }
            else if (initialisationVector.Length > 16)
            {
                for (int i = 0; i < 16; i++)
                {
                    iv[i] = initialisationVector[i];
                }
            }
            else
            {
                iv = initialisationVector;
            }

            return iv;
        }

        private byte[] CalibrateSymmetricKey(byte[] symmetricKey)
        {
            byte[] key = new byte[32];
            if (symmetricKey.Length < 32)
            {
                var padding = 32 - symmetricKey.Length;
                for (var i = 0; i < symmetricKey.Length; i++)
                {
                    key[i] = symmetricKey[i];
                }

                for (var p = symmetricKey.Length; p < 32; p++)
                {
                    key[p] = byte.MinValue;
                }
            }
            else if (symmetricKey.Length > 32)
            {
                for (int i = 0; i < 32; i++)
                {
                    key[i] = symmetricKey[i];
                }
            }
            else
            {
                key = symmetricKey;
            }

            return key;
        }
    }
}