using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CheatToolUI
{
    public partial class SwitchInjection : Form
    {
        private Socket s;
        private MemoryManagement memMgr;

        public SwitchInjection()
        {
            InitializeComponent();
        }

        private void SwitchInjection_Load(object sender, EventArgs e)
        {
            string savedIP = ConfigurationManager.AppSettings["ipAddress"];
            if (!string.IsNullOrEmpty(savedIP))
                textBoxSwitchIPInput.Text = savedIP;

            SetUIDisconnected();
        }

        private void textBoxSwitchIPInput_Changed(object sender, EventArgs e)
        {

        }

        private void btnConnect_Click(object sender, EventArgs e)
        {
            string ip = textBoxSwitchIPInput.Text.Trim();

            if (!IPAddress.TryParse(ip, out IPAddress address))
            {
                MessageBox.Show("Invalid IP address format.");
                return;
            }

            if (s != null && s.Connected)
            {
                DisconnectFromSwitch();
                return;
            }

            s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint ep = new IPEndPoint(address, 6000);

            btnConnect.Enabled = false;

            new Thread(() =>
            {
                Thread.CurrentThread.IsBackground = true;

                try
                {
                    IAsyncResult result = s.BeginConnect(ep, null, null);
                    if (result.AsyncWaitHandle.WaitOne(3000, true))
                    {
                        s.EndConnect(result);
                        if (s.Connected)
                        {
                            Invoke((System.Windows.Forms.MethodInvoker)(() =>
                            {
                                MessageBox.Show("Connected to switch!");
                                SetUIConnected(ip);
                                SaveSetting("ipAddress", ip);
                                memMgr = new MemoryManagement(s);
                            }));
                        }
                        else
                        {
                            s.Close();
                            ShowConnectionFailed();
                        }
                    }
                    else
                    {
                        s.Close();
                        ShowConnectionFailed();
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Connection error: {ex.Message}");
                    ShowConnectionFailed();
                }
                finally
                {
                    Invoke((System.Windows.Forms.MethodInvoker)(() =>
                    {
                        btnConnect.Enabled = true;
                    }));
                }
            }).Start();
        }

        private void DisconnectFromSwitch()
        {
            if (s != null && s.Connected)
            {
                try
                {
                    s.Shutdown(SocketShutdown.Both);
                    s.Close();
                    s = null;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error disconnecting: {ex.Message}");
                }
            }
            SetUIDisconnected();
            memMgr = null;
        }

        private void SetUIConnected(string ip)
        {
            Invoke((System.Windows.Forms.MethodInvoker)delegate
            {
                pbStatusLight.BackColor = System.Drawing.Color.Green;
                btnConnect.Text = $"Connected to {ip} (Click to Disconnect)";
                btnConnect.BackColor = System.Drawing.Color.LightGreen;
                richTextBoxCodeInput.Enabled = true;
                btnSendData.Enabled = true;
                textBoxSwitchIPInput.Enabled = false;
            });
        }

        private void SetUIDisconnected()
        {
            Invoke((System.Windows.Forms.MethodInvoker)delegate
            {
                pbStatusLight.BackColor = System.Drawing.Color.Red;
                btnConnect.Text = "Connect to Switch";
                btnConnect.BackColor = System.Drawing.SystemColors.Control;
                richTextBoxCodeInput.Enabled = false;
                btnSendData.Enabled = false;
                textBoxSwitchIPInput.Enabled = true;
            });
        }

        private void ShowConnectionFailed()
        {
            Invoke((System.Windows.Forms.MethodInvoker)delegate
            {
                MessageBox.Show("Unable to connect. \nPlease check your Switch IP address, and then try again. \n\nGo to your internet settings, scroll down to internet, \nthen under 'Connection Status', you'll see your consoles \nlocal IP address in the 7th column.");
                SetUIDisconnected();
            });
        }

        private void btnSendData_Click(object sender, EventArgs e)
        {
            if (memMgr == null || !s.Connected)
            {
                MessageBox.Show("Not connected to the Switch. Please connect first.", "Connection Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            string codeInput = richTextBoxCodeInput.Text.Trim();
            if (string.IsNullOrEmpty(codeInput))
            {
                MessageBox.Show("Please enter some opcode data into the text box.", "No Data", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string[] lines = codeInput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string line in lines)
            {
                string trimmedLine = line.Trim();

                if (trimmedLine.StartsWith("[") || trimmedLine.StartsWith("//") || string.IsNullOrWhiteSpace(trimmedLine))
                {
                    continue;
                }

                Match fourDwordMatch = Regex.Match(trimmedLine, @"^([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})$");
                Match threeDwordMatch = Regex.Match(trimmedLine, @"^([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})$");

                Match currentMatch = null;
                int dwordCount = 0;

                if (fourDwordMatch.Success)
                {
                    currentMatch = fourDwordMatch;
                    dwordCount = 4;
                }
                else if (threeDwordMatch.Success)
                {
                    currentMatch = threeDwordMatch;
                    dwordCount = 3;
                }

                if (currentMatch != null)
                {
                    try
                    {
                        uint firstDword = Convert.ToUInt32(currentMatch.Groups[1].Value, 16);
                        uint secondDword = Convert.ToUInt32(currentMatch.Groups[2].Value, 16);

                        uint opcode_val = (firstDword >> 28) & 0xF;

                        if (opcode_val == (uint)CheatVmOpcodeType.StoreStatic)
                        {
                            int bit_width = (int)((firstDword >> 24) & 0xF);
                            MemoryAccessType mem_type = (MemoryAccessType)((firstDword >> 20) & 0xF);

                            long rel_address_high_8 = (firstDword & 0xFF);
                            long address = (rel_address_high_8 << 32) | secondDword;

                            long valueToWrite = 0;
                            int byteCount = bit_width;

                            if (dwordCount == 3 && byteCount == 4)
                            {
                                valueToWrite = Convert.ToUInt32(currentMatch.Groups[3].Value, 16);
                            }
                            else if (dwordCount == 4 && byteCount == 8)
                            {
                                uint valueLow = Convert.ToUInt32(currentMatch.Groups[3].Value, 16);
                                uint valueHigh = Convert.ToUInt32(currentMatch.Groups[4].Value, 16);
                                valueToWrite = ((long)valueHigh << 32) | valueLow;
                            }
                            else
                            {
                                MessageBox.Show($"Mismatched DWORD count ({dwordCount}) and bit_width ({bit_width}) for StoreStatic opcode in line: {trimmedLine}", "Parsing Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                continue;
                            }

                            bool isMain = (mem_type == MemoryAccessType.MainNso);

                            if (byteCount == 0)
                            {
                                MessageBox.Show($"Invalid bit_width (0) detected for command: {trimmedLine}", "Parsing Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                continue;
                            }
                            if (byteCount > 8)
                            {
                                MessageBox.Show($"Byte count {byteCount} is too large for simple memory write from this opcode type. Max 8 bytes allowed.", "Parsing Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                continue;
                            }

                            memMgr.WriteMem(isMain, address, valueToWrite, byteCount);

                        }
                        else
                        {
                            MessageBox.Show($"Only CheatVmOpcodeType.StoreStatic (opcode 0) is currently supported. Found opcode {opcode_val} in line: {trimmedLine}", "Unsupported Opcode Type", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        }
                    }
                    catch (FormatException)
                    {
                        MessageBox.Show($"Invalid hexadecimal format in line: {trimmedLine}", "Parsing Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    catch (OverflowException)
                    {
                        MessageBox.Show($"Value too large for type in line: {trimmedLine}", "Parsing Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Error sending command '{trimmedLine}': {ex.Message}", "Send Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
                else
                {
                    MessageBox.Show($"Invalid raw opcode line format: '{trimmedLine}'. Expected three or four 8-character hex numbers separated by spaces.", "Format Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            MessageBox.Show("Opcode data processing complete.", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void SaveSetting(string key, string value)
        {
            try
            {
                Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                if (config.AppSettings.Settings[key] == null)
                {
                    config.AppSettings.Settings.Add(key, value);
                }
                else
                {
                    config.AppSettings.Settings[key].Value = value;
                }
                config.Save(ConfigurationSaveMode.Modified);
                ConfigurationManager.RefreshSection("appSettings");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error saving setting {key}: {ex.Message}");
            }
        }

        private void SwitchInjection_FormClosing(object sender, FormClosingEventArgs e)
        {
            DisconnectFromSwitch();
        }

        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            string url = "https://github.com/olliz0r/sys-botbase/releases";

            linkLabel1.LinkVisited = true;

            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not open link: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public enum MemoryAccessType
        {
            MainNso = 0,
            Heap = 1,
            Alias = 2,
            Aslr = 3,
            Blank = 4
        }

        public enum CheatVmOpcodeType
        {
            StoreStatic = 0,
            BeginConditionalBlock = 1,
            EndConditionalBlock = 2,
            ControlLoop = 3,
            LoadRegisterStatic = 4,
            LoadRegisterMemory = 5,
            StoreStaticToAddress = 6,
            PerformArithmeticStatic = 7,
            BeginKeypressConditionalBlock = 8,
            PerformArithmeticRegister = 9,
            StoreRegisterToAddress = 10,
            Reserved11 = 11,
            ExtendedWidth = 12,
            BeginRegisterConditionalBlock = 0xC0,
            SaveRestoreRegister = 0xC1,
            SaveRestoreRegisterMask = 0xC2,
            ReadWriteStaticRegister = 0xC3,
            BeginExtendedKeypressConditionalBlock = 0xC4,
            DoubleExtendedWidth = 0xF0,
            PauseProcess = 0xFF0,
            ResumeProcess = 0xFF1,
            DebugLog = 0xFFF
        }
    }
}