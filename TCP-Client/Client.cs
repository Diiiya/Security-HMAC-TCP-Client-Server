using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using Helper;

namespace TCP_Client
{
    public class Client
    {
        private static byte[] SignMessage(string text, Guid nonce)
        {
            string key = "V3rY!$ecR3TXmaC#k33Y" + nonce;
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);
            using HMACSHA256 hmac = new HMACSHA256(keyBytes);
            byte[] bytes = Encoding.ASCII.GetBytes(text);
            byte[] hashValue = hmac.ComputeHash(bytes);
            return hashValue;
        }
        private static void SerializeMessage(NetworkStream stream, string inputText)
        {
            var nonce = Guid.NewGuid();
            // To test Replay attack check works, new Guid() always outputs 000-00.. 
            // var nonce = new Guid();
            Message msg = new()
            {
                Nonce = nonce,
                Hash = SignMessage(inputText, nonce),
                Text = inputText
            };

            BinaryFormatter bf = new BinaryFormatter();
            bf.Serialize(stream, msg);
        }
        private static (TcpClient, StreamReader, StreamWriter) EstablishConnection()
        {
            IPAddress ip_address = IPAddress.Parse("127.0.0.1"); //default
            int port = 8080;

            Console.WriteLine("Connecting to server at IP address: {0} port: {1}", ip_address.ToString(), port);
            TcpClient client = new TcpClient(ip_address.ToString(), port);
            Console.WriteLine("Connection established!");
            StreamReader reader = new StreamReader(client.GetStream());
            StreamWriter writer = new StreamWriter(client.GetStream());

            return (client, reader, writer);
        }
        private static void HandleInput(TcpClient client, StreamReader reader, StreamWriter writer, string input)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            switch (input)
            {
                case "send":
                {
                    writer.WriteLine(input);
                    writer.Flush();
                    Console.Write("Type message: ");
                    input = Console.ReadLine();
                    SerializeMessage(client.GetStream(), input);
                    client.GetStream().Flush();
                    Console.WriteLine();
                    break;
                }
                case "exit":
                {
                    writer.WriteLine(input);
                    writer.Flush();
                    break;
                }
                default:
                {
                    writer.WriteLine(input);
                    writer.Flush();
                    string serverString = reader.ReadLine();
                    Console.WriteLine(serverString);
                    Console.WriteLine();
                    break;
                }
            }
        }

        public static void Main(String[] args)
        {
            try
            {
                var (client, reader, writer) = EstablishConnection();
                string input = String.Empty;

                while (!input.Equals("exit"))
                {
                    Console.Write("Enter \"send\" to send message to server: ");
                    input = Console.ReadLine();
                    Console.WriteLine();
                    HandleInput(client, reader, writer, input);
                }
                reader.Close();
                writer.Close();
                client.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
	}
}
