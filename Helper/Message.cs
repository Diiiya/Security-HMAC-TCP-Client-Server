using System;

namespace Helper
{
    [Serializable]
    public class Message
    {
        public Guid Nonce { get; set; }
        public string Text { get; set; }
        public byte[] Hash { get; set; }
    }
}
