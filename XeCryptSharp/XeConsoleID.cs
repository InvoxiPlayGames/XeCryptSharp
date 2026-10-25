using System;
using System.Collections.Generic;
using System.Linq;

namespace XeCryptSharp
{
    public class XeConsoleID
    {
        private byte[] _data;
        private ulong _id;

        public ulong ID { get { return _id; } }

        public XeConsoleID(IEnumerable<byte> id)
        {
            if (id == null || id.Count() != 0x5)
                throw new Exception("Invalid console ID length");
            
            _data = id.ToArray();
            ulong counter = 0;
            for (int i = 0; i < 5; i++)
                counter = _data[i] + counter * 0x100;
            string converted = (counter >> 4).ToString("D11") + (counter & 0xF).ToString("X1");
            _id = ulong.Parse(converted);
        }

        public override string ToString()
        {
            return _id.ToString("D12");
        }

        public IEnumerable<byte> GetBytes()
        {
            return _data;
        }
    }
}