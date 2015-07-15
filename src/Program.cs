using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace Crypter
{
    class Program
    {
        static private string _inputFile;
        static private string _outputFile;
        static private string _configFile;
        static private string _cryptKey;
        static private string _nonce;
        static private string _nonceText;
        static private byte[] _nonceKod;
        static private bool _addNonceToName;
        private static bool _setCryptKey;

        static private void SetTestData()
        {
            _cryptKey = "qwertyuiQWERTYUIasdfghjkASDFGHJK";
            _nonce = "zxcvbnmmZXCVBNMM";
            _inputFile = @"D:\work\freelance\Crypter\test\input.txt";
            _outputFile = @"D:\work\freelance\Crypter\test\output.txt";
            _setCryptKey = true;
        }

        static void Main(string[] args)
        {
            //SetTestData();
            CheckItems(args);

            if ((!string.IsNullOrEmpty(_configFile)) && File.Exists(_configFile))
                LoadConfigFile();
            
            if (!File.Exists(_inputFile))
                return;
            if (string.IsNullOrEmpty(_outputFile))
                return;
            if (!_setCryptKey)
                return;
            _nonceKod = new byte[16];
            if (string.IsNullOrEmpty(_nonce))
                CreateOwnNonce();
            else
            {
                byte[] nn = Encoding.ASCII.GetBytes(_nonce);
                for (int i = 0; i < Math.Min(nn.Length, 16); i++)
                    _nonceKod[i] = nn[i];
                if (nn.Length < 16)
                    for (int i = nn.Length; i < 16; i++)
                        _nonceKod[i] = 255;
            }
            if (_addNonceToName)
            {
                _nonceText = "";
                for (int i = 0; i < 16; i++)
                {
                    byte n = _nonceKod[i];
                    if (((n > 47) && (n < 58)) || ((n > 64) && (n < 91)) || ((n > 96) && (n < 123)))
                        _nonceText += ((char) n).ToString(CultureInfo.InvariantCulture);
                    else
                        _nonceText += "%" + n.ToString("x2");
                }
                int sep = _outputFile.LastIndexOf('.');
                if (sep > -1)
                    _outputFile = _outputFile.Substring(0, sep) + "_" + _nonceText + _outputFile.Substring(sep);
                else
                    _outputFile += "_" + _nonceText;
            }

            EncryptFile(_inputFile, _outputFile, _cryptKey, _nonceKod);
        }

        static void EncryptFile(string inputPath, string outputPath, string password, byte[] nonceKod)
        {
            RijndaelManaged aes = new RijndaelManaged
            {
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None,
                KeySize = 256,
                BlockSize = 128
            };
            using (CounterModeCryptoTransform tran = new CounterModeCryptoTransform(aes,
                Encoding.ASCII.GetBytes(password), nonceKod))
            {
                byte[] myOutputBytes = new byte[tran.OutputBlockSize];
                FileStream myInputFile = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
                FileStream myOutputFile = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
                byte[] myInputBytes = new byte[myInputFile.Length];
                myInputFile.Read(myInputBytes, 0, myInputBytes.Length);
                int i = 0;
                while(myInputBytes.Length - i > tran.OutputBlockSize)
                {
                    tran.TransformBlock(myInputBytes, i, tran.OutputBlockSize, myOutputBytes, 0);
                    i += tran.OutputBlockSize;
                    myOutputFile.Write(myOutputBytes, 0, tran.OutputBlockSize);
                }

                myOutputBytes = tran.TransformFinalBlock(myInputBytes, i, myInputBytes.Length - i);
                myOutputFile.Write(myOutputBytes, 0, myOutputBytes.Length);

                myInputFile.Close();
                myOutputFile.Close();
            }
        }

        static private void CreateOwnNonce()
        {
            Random set = new Random((int)(DateTime.Now.Ticks % int.MaxValue));
            Random rr = new Random(set.Next(DateTime.Now.Millisecond));
            for (int i = 0; i < 4; i++)
            {
                byte[] bytes = BitConverter.GetBytes( rr.Next(int.MaxValue));
                for(int j = 0; j < 4; j++)
                    _nonceKod[i*4+j] = bytes[j];
            }
        }

        static private void LoadConfigFile()
        {
            StreamReader sr = new StreamReader(_configFile);
            string line = "";
            while (!sr.EndOfStream)
                line += sr.ReadLine() + " ";
            line = line.Trim();
            int pos = GetNextParam(line, 0);
            while ((pos != -1)&&(pos <= line.Length - 2))
            {
                string key = line.Substring(pos, 2);
                int nextPos = GetNextParam(line, pos+1);
                
                if (key == "-a")
                    _addNonceToName = true;
                else
                {
                    string value = line.Substring(pos + 2, nextPos - (pos+2)).Trim();
                    switch (key)
                    {
                        case "-i":
                            _inputFile = value;
                            break;
                        case "-o":
                            _outputFile = value;
                            break;
                        case "-c":
                            _configFile = value;
                            break;
                        case "-k":
                            _setCryptKey = true;
                            _cryptKey = value.PadRight(32, (char)255);
                            break;
                        case "-n":
                            _nonce = value;
                            break;
                    }
                }
                pos = nextPos;
            }
        }

        static private int GetNextParam(string line, int pos)
        {
            int posRet = line.Length;
            string[] lineDelim = {"-i ", "-o ", "-c ", "-k ", "-n ", "-a"};
            foreach (string delim in lineDelim)
            {
                int p = line.IndexOf(delim, pos, StringComparison.Ordinal);
                if (p > -1)
                    posRet = Math.Min(p, posRet);
            }
            return posRet;
        }

        static private void CheckItems(string[] items)
        {
            int i = 0;
            
            while (i < items.Length)
            {
                string key = items[i];
                switch (key)
                {
                    case "-i":
                        if ((i + 1 <= items.Length - 1) && (!IsInlist(items[i + 1])))
                        {
                            _inputFile = items[i + 1];
                            i += 2;
                        }
                        else
                            i++;
                        break;
                    case "-o":
                        if ((i + 1 <= items.Length - 1) && (!IsInlist(items[i + 1])))
                        {
                            _outputFile = items[i + 1];
                            i += 2;
                        }
                        else
                            i++;
                        break;
                    case "-c":
                        if ((i + 1 <= items.Length - 1) && (!IsInlist(items[i + 1])))
                        {
                            _configFile = items[i + 1];
                            i += 2;
                        }
                        else
                            i++;
                        break;
                    case "-k":
                        if ((i + 1 <= items.Length - 1) && (!IsInlist(items[i + 1])))
                        {
                            _setCryptKey = true;
                            _cryptKey = items[i + 1];
                            i += 2;
                        }
                        else
                        {
                            _cryptKey = "";
                            i += 1;
                        }
                        break;
                    case "-n":
                        if ((i+1 <= items.Length - 1)&&(!IsInlist(items[i + 1])))
                        {
                            _nonce = items[i + 1];
                            i += 2;
                        }
                        else
                        {
                            _nonce = "";
                            i += 1;
                        }
                        break;
                    case "-a":
                        _addNonceToName = true;
                        i++;
                        break;
                }
            }
        }

        static private bool IsInlist(string item)
        {
            string[] lineDelim = {"-i ", "-o ", "-c ", "-k ", "-n ", "-a"};
            foreach(string s in lineDelim)
                if (s == item)
                    return true;
            return false;
        }
    }
}
