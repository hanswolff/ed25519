using NUnit.Framework;
using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Text;

namespace Cryptographic.Tests
{
    [TestFixture]
    public class Ed25519Tests
    {
        [Test]
        public void TestPortedFromJava()
        {
            var sw = Stopwatch.StartNew();

            var sk = new byte[32];
            byte[] pk = Ed25519.PublicKey(sk);
            Console.WriteLine("publickey for 0 is \"" + GetHex(pk) + "\"");
            Assert.AreEqual("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29", GetHex(pk));

            Console.WriteLine("encodeint 0 = " + GetHex(Ed25519.EncodeInt(BigInteger.Zero)));
            Console.WriteLine("encodeint 1 = " + GetHex(Ed25519.EncodeInt(BigInteger.One)));
            Console.WriteLine("encodeint 10 = " + GetHex(Ed25519.EncodeInt(new BigInteger(10))));
            var pkr = new Tuple<BigInteger, BigInteger>
                (
                BigInteger.Parse("9639205628789703341510410801487549615560488670885798085067615194958049462616"),
                BigInteger.Parse("18930617471878267742194159801949745215346600387277955685031939302387136031291")
                );
            Console.WriteLine("encodepoint 0,0 = " + GetHex(Ed25519.EncodePoint(BigInteger.Zero, BigInteger.Zero)));
            Console.WriteLine("encodepoint 1,1 = " + GetHex(Ed25519.EncodePoint(BigInteger.One, BigInteger.One)));
            Console.WriteLine("encodepoint 10,0 = " + GetHex(Ed25519.EncodePoint(new BigInteger(10), BigInteger.Zero)));
            Console.WriteLine("encodepoint 1,10 = " + GetHex(Ed25519.EncodePoint(BigInteger.One, new BigInteger(10))));
            Console.WriteLine(
                "encodepoint 9639205628789703341510410801487549615560488670885798085067615194958049462616,18930617471878267742194159801949745215346600387277955685031939302387136031291 = " +
                GetHex(Ed25519.EncodePoint(pkr.Item1, pkr.Item2)));

            Assert.AreEqual("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29", GetHex(Ed25519.EncodePoint(pkr.Item1, pkr.Item2)));

            byte[] message = Encoding.UTF8.GetBytes("This is a secret message");
            byte[] signature = Ed25519.Signature(message, sk, pk);
            Assert.AreEqual("94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f", GetHex(signature));

            Console.WriteLine("signature(\"This is a secret message\") = " + GetHex(signature));
            bool signatureValid = Ed25519.CheckValid(signature, message, pk);
            Console.WriteLine("check signature result:\n" + signatureValid + ", Test run in " + sw.Elapsed);

            Assert.IsTrue(signatureValid);
        }

        [Test]
        public void RandomTest()
        {
            var sw = Stopwatch.StartNew();

            var seed = new Random().Next();

            var rnd = new Random(seed);
            var signingKey = Enumerable.Range(0, 32).Select(x => (byte) rnd.Next(256)).ToArray();

            byte[] publicKey = Ed25519.PublicKey(signingKey);

            byte[] message = Encoding.UTF8.GetBytes("This is a secret message");
            byte[] signature = Ed25519.Signature(message, signingKey, publicKey);
            bool signatureValid = Ed25519.CheckValid(signature, message, publicKey);
            Assert.IsTrue(signatureValid, "Test with random seed {0} failed", seed);

            message[0] = (byte)(message[0] ^ 1);
            var signatureValidAfterChange = Ed25519.CheckValid(signature, message, publicKey);
            Assert.IsFalse(signatureValidAfterChange, "Test with random seed {0} failed", seed);

            Console.WriteLine("Test run in " + sw.Elapsed);
        }

        const string HexString = "0123456789abcdef";

        public static String GetHex(byte[] raw)
        {
            if (raw == null)
            {
                return null;
            }
            var hex = new StringBuilder(2 * raw.Length);
            foreach (byte b in raw)
            {
                hex.Append(HexString[((b & 0xF0) >> 4)]);
                hex.Append(HexString[((b & 0x0F))]);
            }
            return hex.ToString();
        }
    }
}