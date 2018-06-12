using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static DirectoryEncryptor.FileEncryptor;

namespace DirectoryEncryptor
{
    class Program
    {
        private static string Password
        {
            get; set;
        }

        private static string FolderName
        {
            get; set;
        }

        private static char ScrambleAndDelete
        {
            get; set;
        }

        private static char DeleteEncryptedFile
        {
            get; set;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Current directory.");
            Console.WriteLine(Environment.CurrentDirectory);

            Console.WriteLine("Type in the folder name:");
            FolderName = Console.ReadLine();
            Console.WriteLine("Type in the password:");
            Password = ReadPassword('#');

            var folderPath = Path.Combine(Environment.CurrentDirectory, FolderName);

            try
            {
                if (Directory.Exists(folderPath))
                {
                    Encrypt(folderPath);
                    Console.WriteLine("Scramble files and delete directory ? (Y for yes)");
                    ScrambleAndDelete = Console.ReadKey().KeyChar;
                    Console.WriteLine();
                    if (ScrambleAndDelete == 'Y' || ScrambleAndDelete == 'y')
                    {
                        ScrambleDirectoryFiles(folderPath);
                        DeleteFolder(folderPath);
                    }
                }
                else
                {
                    Decrypt(folderPath);
                    Console.WriteLine("Delete encrypted file ? (Y for yes)");
                    DeleteEncryptedFile = Console.ReadKey().KeyChar;
                    if (DeleteEncryptedFile == 'Y' || DeleteEncryptedFile == 'y')
                    {
                        var encryptedFilePath = folderPath + ".crypted";
                        File.Delete(encryptedFilePath);
                    }
                }
                    
            }
            catch (FileEncryptorException ex)
            {
                Console.WriteLine("Error on encryption.");
                Console.WriteLine(ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unknown error.");
                Console.WriteLine(ex.Message);
            }


            Console.WriteLine("");
            Console.WriteLine("Finished");
            Console.ReadLine();
        }

        private static void Encrypt(string folderPath)
        {
            var zipFilePath = folderPath + ".zip";
            if (File.Exists(zipFilePath))
                File.Delete(zipFilePath);

            Console.WriteLine("Zipping the folder...");
            ZipFile.CreateFromDirectory(folderPath, zipFilePath, CompressionLevel.NoCompression, false);

            Console.WriteLine("Encrypting...");
            var crypt = new FileEncryptor(Password);
            var encryptedFilePath = folderPath + ".crypted";
            crypt.Encrypt(zipFilePath, encryptedFilePath);

            Console.WriteLine("Deleting zip file...");
            File.Delete(zipFilePath);
        }

        private static void Decrypt(string folderPath)
        {
            var encryptedFilePath = folderPath + ".crypted";
            var zipFilePath = folderPath + ".zip";

            if (!File.Exists(encryptedFilePath))
            {
                Console.WriteLine($"The file {encryptedFilePath} could not be found.");
                return;
            }

            var crypt = new FileEncryptor(Password);
            Console.WriteLine("Decrypting...");
            crypt.Decrypt(encryptedFilePath, zipFilePath);

            Console.WriteLine("Unzipping the folder...");
            ZipFile.ExtractToDirectory(zipFilePath, folderPath);

            Console.WriteLine("Deleting zip file...");
            File.Delete(zipFilePath);
        }

        public static void ScrambleDirectoryFiles(string diretoryPath)
        {
            Console.WriteLine("Scrambling files...");
            foreach (var filePath in Directory.GetFiles(diretoryPath))
            {
                FileInfo fileInfo = new FileInfo(filePath);

                FileStream fs = File.OpenWrite(filePath);

                for (int i = 0; i < 4; i++)
                {
                    List<long> positions = getFilePositions(fileInfo.Length);

                    Random random = new Random((int)DateTime.Now.Ticks);

                    foreach (var position in positions)
                    {
                        byte randomByte = (byte)random.Next(byte.MaxValue);

                        fs.Seek(position, SeekOrigin.Begin);
                        fs.WriteByte(randomByte);
                    }
                }

                fs.Close();
            }
        }

        private static List<long> getFilePositions(long length)
        {
            List<long> positions = new List<long>();

            Random random = new Random((int)DateTime.Now.Ticks);

            for (int i = 0; i < (Math.Sqrt(length)); i++)
            {
                long nextPosition = LongRandom(0, length, random);

                positions.Add(nextPosition);
            }

            return positions;
        }

        private static long LongRandom(long min, long max, Random rand)
        {
            byte[] buf = new byte[8];
            rand.NextBytes(buf);
            long longRand = BitConverter.ToInt64(buf, 0);

            return (Math.Abs(longRand % (max - min)) + min);
        }

        public static void DeleteFolder(string folderPath)
        {
            Console.WriteLine("Deleting folder...");
            foreach (var filePath in Directory.GetFiles(folderPath))
            {
                File.Delete(filePath);
            }

            Directory.Delete(folderPath);
        }

        public static string ReadPassword(char mask)
        {
            const int ENTER = 13, BACKSP = 8, CTRLBACKSP = 127;
            int[] FILTERED = { 0, 27, 9, 10 /*, 32 space, if you care */ }; // const

            var pass = new Stack<char>();
            char chr = (char)0;

            while ((chr = System.Console.ReadKey(true).KeyChar) != ENTER)
            {
                if (chr == BACKSP)
                {
                    if (pass.Count > 0)
                    {
                        System.Console.Write("\b \b");
                        pass.Pop();
                    }
                }
                else if (chr == CTRLBACKSP)
                {
                    while (pass.Count > 0)
                    {
                        System.Console.Write("\b \b");
                        pass.Pop();
                    }
                }
                else if (FILTERED.Count(x => chr == x) > 0) { }
                else
                {
                    pass.Push((char)chr);
                    System.Console.Write(mask);
                }
            }

            System.Console.WriteLine();

            return new string(pass.Reverse().ToArray());
        }
    }

    public class FileEncryptor
    {
        public class FileEncryptorException : Exception
        {
            public FileEncryptorException(string Message) : base(Message)
            {
            }
        }

        // Internal value of the phrase used to generate the secret key
        private string _Phrase = "";
        //contains input file path and name
        private string _inputFile = "";
        //contains output file path and name
        private string _outputFile = "";
        enum TransformType { ENCRYPT = 0, DECRYPT = 1 }

        /// <value>Set the phrase used to generate the secret key.</value>
        public string Phrase
        {
            set
            {
                this._Phrase = value;
                this.GenerateKey(this._Phrase);
            }
        }

        // Internal initialization vector value to 
        // encrypt/decrypt the first block
        private byte[] _IV;

        // Internal secret key value
        private byte[] _Key;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="SecretPhrase">Secret phrase to generate key</param>
        public FileEncryptor(string SecretPhrase)
        {
            this.Phrase = SecretPhrase;
        }

        /// <summary>
        /// Encrypt the given value with the Rijndael algorithm.
        /// </summary>
        /// <param name="EncryptValue">Value to encrypt</param>
        /// <returns>Encrypted value. </returns>
        public string Encrypt(string EncryptValue)
        {
            try
            {
                if (EncryptValue.Length > 0)
                {
                    // Write the encrypted value into memory
                    byte[] input = Encoding.UTF8.GetBytes(EncryptValue);

                    // Retrieve the encrypted value and return it
                    return (Convert.ToBase64String(Transform(input,
                        TransformType.ENCRYPT)));
                }
                else
                {
                    return "";
                }
            }
            catch (Exception ex)
            {
                throw new FileEncryptorException(ex.Message);
            }
        }

        /// <summary>
        /// Decrypt the given value with the Rijndael algorithm.
        /// </summary>
        /// <param name="DecryptValue">Value to decrypt</param>
        /// <returns>Decrypted value. </returns>
        public string Decrypt(string DecryptValue)
        {

            try
            {
                if (DecryptValue.Length > 0)
                {
                    // Write the encrypted value into memory                    
                    byte[] input = Convert.FromBase64String(DecryptValue);

                    // Retrieve the decrypted value and return it
                    return (Encoding.UTF8.GetString(Transform(input,
                        TransformType.DECRYPT)));
                }
                else
                {
                    return "";
                }
            }
            catch (Exception ex)
            {
                throw new FileEncryptorException(ex.Message);
            }
        }

        /// <summary>
        /// Encrypt the given value with the Rijndael algorithm.
        /// </summary>
        /// <param name="EncryptValue">Value to encrypt</param>
        /// <returns>Encrypted value. </returns>
        public void Encrypt(string InputFile, string OutputFile)
        {
            try
            {
                if ((InputFile != null) && (InputFile.Length > 0))
                {
                    _inputFile = InputFile;
                }
                if ((OutputFile != null) && (OutputFile.Length > 0))
                {
                    _outputFile = OutputFile;
                }
                Transform(null, TransformType.ENCRYPT);
            }
            catch (Exception ex)
            {
                throw new FileEncryptorException(ex.Message);
            }
        }

        /// <summary>
        /// Decrypt the given value with the Rijndael algorithm.
        /// </summary>
        /// <param name="DecryptValue">Value to decrypt</param>
        /// <returns>Decrypted value. </returns>
        public void Decrypt(string InputFile, string OutputFile)
        {
            try
            {
                if ((InputFile != null) && (InputFile.Length > 0))
                {
                    _inputFile = InputFile;
                }
                if ((OutputFile != null) && (OutputFile.Length > 0))
                {
                    _outputFile = OutputFile;
                }
                Transform(null, TransformType.DECRYPT);
            }
            catch (Exception ex)
            {
                throw new FileEncryptorException(ex.Message);
            }
        }

        /*****************************************************************
         * Generate an encryption key based on the given phrase.  The 
         * phrase is hashed to create a unique 32 character (256-bit) 
         * value, of which 24 characters (192 bit) are used for the
         * key and the remaining 8 are used for the initialization 
         * vector (IV).
         * 
         * Parameters:  SecretPhrase - phrase to generate the key and 
         * IV from.
         * 
         * Return Val:  None  
         ***************************************************************/
        private void GenerateKey(string SecretPhrase)
        {
            // Initialize internal values
            this._Key = new byte[24];
            this._IV = new byte[16];

            // Perform a hash operation using the phrase.  This will 
            // generate a unique 32 character value to be used as the key.
            byte[] bytePhrase = Encoding.ASCII.GetBytes(SecretPhrase);
            SHA384Managed sha384 = new SHA384Managed();
            sha384.ComputeHash(bytePhrase);
            byte[] result = sha384.Hash;

            // Transfer the first 24 characters of the hashed value to the key
            // and the remaining 16 characters to the initialization vector.
            for (int loop = 0; loop < 24; loop++)
                this._Key[loop] = result[loop];
            for (int loop = 24; loop < 40; loop++)
                this._IV[loop - 24] = result[loop];
        }

        /*****************************************************************
         * Transform one form to anoter based on CryptoTransform
         * It is used to encrypt to decrypt as well as decrypt to encrypt
         * Parameters:  input <byte /> - which needs to be transform 
         *              transformType - encrypt/decrypt transform
         * 
         * Return Val:  byte array - transformed value.
         ***************************************************************/
        private byte[] Transform(byte[] input, TransformType transformType)
        {
            CryptoStream cryptoStream = null;      // Stream used to encrypt
            RijndaelManaged rijndael = null;        // Rijndael provider
            ICryptoTransform rijndaelTransform = null;// Encrypting object 
            FileStream fsIn = null;                 //input file
            FileStream fsOut = null;                //output file
            MemoryStream memStream = null;          // Stream to contain data
            try
            {
                // Create the crypto objects
                rijndael = new RijndaelManaged();
                Console.WriteLine($"Rijndael block size is {rijndael.BlockSize} bits.");
                rijndael.Key = this._Key;
                rijndael.IV = this._IV;
                if (transformType == TransformType.ENCRYPT)
                {
                    rijndaelTransform = rijndael.CreateEncryptor();
                }
                else
                {
                    rijndaelTransform = rijndael.CreateDecryptor();
                }

                if ((input != null) && (input.Length > 0))
                {
                    memStream = new MemoryStream();
                    cryptoStream = new CryptoStream(
                         memStream, rijndaelTransform,
                         CryptoStreamMode.Write);

                    cryptoStream.Write(input, 0, input.Length);

                    cryptoStream.FlushFinalBlock();

                    return memStream.ToArray();
                }
                else if ((_inputFile.Length > 0) && (_outputFile.Length > 0))
                {
                    // First we are going to open the file streams 
                    fsIn = new FileStream(_inputFile,
                                FileMode.Open, FileAccess.Read);
                    fsOut = new FileStream(_outputFile,
                                FileMode.OpenOrCreate, FileAccess.Write);

                    cryptoStream = new CryptoStream(
                        fsOut, rijndaelTransform, CryptoStreamMode.Write);

                    // Now will initialize a buffer and will be 
                    // processing the input file in chunks. 
                    // This is done to avoid reading the whole file 
                    // (which can be huge) into memory. 
                    int bufferLen = 4096;
                    byte[] buffer = new byte[bufferLen];
                    int bytesRead;
                    do
                    {
                        // read a chunk of data from the input file 
                        bytesRead = fsIn.Read(buffer, 0, bufferLen);
                        // Encrypt it 
                        cryptoStream.Write(buffer, 0, bytesRead);

                    } while (bytesRead != 0);

                    cryptoStream.FlushFinalBlock();

                    fsIn.Close();
                    fsOut.Close();
                }
                return null;
            }
            catch (CryptographicException)
            {
                throw new FileEncryptorException(
                    "Password is invalid. Please verify once again.");
            }
            catch (Exception ex)
            {
                throw new FileEncryptorException(ex.Message);
            }
            finally
            {
                if (rijndael != null) rijndael.Clear();
                if (rijndaelTransform != null) rijndaelTransform.Dispose();
                if (cryptoStream != null) cryptoStream.Close();
                if (memStream != null) memStream.Close();
                if (fsOut != null) fsOut.Close();
                if (fsIn != null) fsIn.Close();
            }
        }
    }
}
