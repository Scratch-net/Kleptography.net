using System;
using System.ComponentModel;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace RsaBackdoor.Backdoor
{
	class SeededGenerator : IRandomGenerator
	{
		private readonly AesFastEngine _engine = new AesFastEngine();
		private readonly byte[] _counter = new byte[16];
		private readonly byte[] _buf = new byte[16];
		private int bufOffset = 0;

		public SeededGenerator(byte[] key)
		{
			_engine.Init(true, new KeyParameter(key));
			MakeBytes();
		}

		private void MakeBytes()
		{
			bufOffset = 0;
			_engine.ProcessBlock(_counter, 0, _buf, 0);
			IncrementCounter();
		}

		public void IncrementCounter()
		{
			for (int i = 0; i < _counter.Length; i++)
			{
				_counter[i]++;
				if (_counter[i] != 0)
					break;
			}
		}

		public void AddSeedMaterial(byte[] seed)
		{

		}

		public void AddSeedMaterial(long seed)
		{

		}

		public void NextBytes(byte[] bytes)
		{
			NextBytes(bytes, 0, bytes.Length);
		}

		public void NextBytes(byte[] bytes, int start, int len)
		{
			var count = 0;
			while (count < len)
			{
				var amount = Math.Min(_buf.Length - bufOffset, len - count);
				Array.Copy(_buf, bufOffset, bytes, start + count, amount);
				count += amount;
				bufOffset += amount;
				if (bufOffset >= _buf.Length)
				{
					MakeBytes();
				}
			}
		}
	}
}
