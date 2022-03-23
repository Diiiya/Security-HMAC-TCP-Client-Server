using System;

namespace Helper
{
    [Serializable]
    public class Message
    {
        public string Text { get; set; }
        public byte[] Hash { get; set; }
    }
}
