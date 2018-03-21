using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rijndael_Encyption
{
    class Program
    {
        static void Main(string[] args)
        {
            AESEncryption crypt = new AESEncryption();
            Console.WriteLine("Original Text: hello my name is mohsin");
            string enc = crypt.Encrypt("hello my name is mohsin", "this it the key.");
            Console.WriteLine("Encrypted :" + enc);
            string dec = crypt.Decrypt(enc, "this it the key.");
            Console.WriteLine("Decrypted:" + dec);
            Console.ReadLine();
        }
    }
}
