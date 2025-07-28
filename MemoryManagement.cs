using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace CheatToolUI
{
    internal class MemoryManagement
    {
        private Socket s;

        public MemoryManagement(Socket socket)
        {
            s = socket;
        }

        public void WriteMem(bool IsMain, long address, long value, int byteCount)
        {
            if (byteCount < 1 || byteCount > 8)
                throw new ArgumentOutOfRangeException(nameof(byteCount), "Byte count must be between 1 and 8.");

            byte[] valueBytes;

            if (byteCount == 8)
            {
                uint low32 = (uint)(value & 0xFFFFFFFF);
                uint high32 = (uint)(value >> 32);

                long swappedValue = ((long)low32 << 32) | high32;
                valueBytes = BitConverter.GetBytes(swappedValue);
            }
            else
            {
                valueBytes = BitConverter.GetBytes(value);
            }

            byte[] trimmed = valueBytes.Take(byteCount).ToArray();

            StringBuilder hexBuilder = new StringBuilder("0x");

            foreach (byte b in trimmed)
                hexBuilder.Append(b.ToString("X2"));

            string valueStr = hexBuilder.ToString();
            string addressStr = $"0x{address:X16}";

            string command = "";
            if (!IsMain)
            {
                command = $"poke {addressStr} {valueStr}\r\n";
            }
            else
            {
                command = $"pokeMain {addressStr} {valueStr}\r\n";
            }

            try
            {
                byte[] commandBytes = Encoding.UTF8.GetBytes(command);
                Debug.WriteLine($"[MemoryManagement] Sending: {command.Trim()}");
                s.Send(commandBytes);

            }
            catch (SocketException ex)
            {
                throw new Exception($"Network error during WriteMem: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"Error during WriteMem: {ex.Message}", ex);
            }
        }

        public byte[] ReadMem(bool IsMain, long address, int byteCount)
        {
            if (byteCount < 1 || byteCount > 128)
                throw new ArgumentOutOfRangeException(nameof(byteCount), "Byte count must be between 1 and 128.");

            string addressStr = $"0x{address:X16}";
            string command = "";

            if (!IsMain)
            {
                command = $"peek {addressStr} {byteCount}\r\n";
            }
            else
            {
                command = $"peekMain {addressStr} {byteCount}\r\n";
            }

            try
            {
                byte[] commandBytes = Encoding.UTF8.GetBytes(command);
                s.Send(commandBytes);

                byte[] buffer = new byte[byteCount * 2 + 100];
                int bytesReceived = s.Receive(buffer);
                string response = Encoding.UTF8.GetString(buffer, 0, bytesReceived).Trim();

                Match match = Regex.Match(response, @"^0x([0-9A-Fa-f]+)$");
                if (match.Success)
                {
                    string hexValue = match.Groups[1].Value;
                    if (hexValue.Length % 2 != 0) hexValue = "0" + hexValue;

                    List<byte> resultBytes = new List<byte>();
                    for (int i = 0; i < hexValue.Length; i += 2)
                    {
                        string byteString = hexValue.Substring(i, 2);
                        resultBytes.Add(Convert.ToByte(byteString, 16));
                    }
                    return resultBytes.ToArray();
                }
                else
                {
                    throw new Exception($"Unexpected response format for peek: {response}");
                }
            }
            catch (SocketException ex)
            {
                throw new Exception($"Network error during ReadMem: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"Error during ReadMem: {ex.Message}", ex);
            }
        }
    }
}