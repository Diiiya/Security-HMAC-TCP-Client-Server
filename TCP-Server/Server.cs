using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Helper;

namespace TCP_Server
{
    public class Server
    {
        private static bool VerifyMessage(byte[] key, Message signedMsg)
        {
            bool err = false;
            using HMACSHA256 hmac = new HMACSHA256(key);
            var storedHash = signedMsg.Hash;
            byte[] msgBytes = Encoding.ASCII.GetBytes(signedMsg.Text);

            byte[] computedHash = hmac.ComputeHash(msgBytes);

            for (int i = 0; i < storedHash.Length; i++)
            {
                if (computedHash[i] != storedHash[i])
                {
                    err = true;
                }
            }

            Console.WriteLine();
            if (err)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Hash values differ! Signed file has been tampered with!");
                return false;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Hash values are the same! No tampering has occurred.");
                return true;
            }
        }
        private static Message DeserializeMessage(NetworkStream stream)
        {
            BinaryFormatter bf = new BinaryFormatter();
            return (Message)bf.Deserialize(stream);
        }
        private static void WriteResultsToConsole(Message msg)
        {
            string key = "V3rY!$ecR3TXmaC#k33Y";
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);
            VerifyMessage(keyBytes, msg);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("Original Text Message: " + msg.Text);
        }
        private static void ProcessClientRequests(object argument)
        {
            TcpClient client = (TcpClient)argument;
            try
            {
                StreamReader reader = new StreamReader(client.GetStream());
                StreamWriter writer = new StreamWriter(client.GetStream());
                string s = String.Empty;
                while (!((s = reader.ReadLine()).Equals("Exit") || (s == null)))
                {
                    switch (s)
                    {
                        case "send":
                        {
                            writer.WriteLine(s);
                            writer.Flush();
                            WriteResultsToConsole(DeserializeMessage(client.GetStream()));
                            Console.WriteLine();
                            break;
                        }
                        default:
                        {
                            Console.WriteLine("From client -> " + s);
                            writer.WriteLine("From server -> " + s);
                            writer.Flush();
                            break;
                        }
                    } 
                } 
                reader.Close();
                writer.Close();
                client.Close();
                Console.WriteLine("Client connection closed!");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            finally
            {
                if (client != null)
                {
                    client.Close();
                }
            }
        } 
		public static void Main()
        {
            TcpListener listener = null;
            try
            {
                listener = new TcpListener(IPAddress.Any, 8080);
                listener.Start();
                Console.WriteLine("HMAC Auth Server started!");
                while (true)
                {
                    Console.WriteLine("Waiting for incoming client connections ...");
                    TcpClient client = listener.AcceptTcpClient();
                    Console.WriteLine("New Client connection established!");
                    Thread t = new Thread(ProcessClientRequests);
                    t.Start(client);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            finally
            {
                if (listener != null)
                {
                    listener.Stop();
                }
            }
        }
	}
}
