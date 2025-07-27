using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Drawing;
using System.Text.RegularExpressions;

namespace CheatToolUI
{
    public partial class CheatToolGUI : Form
    {
        private string pythonExecutableName = "python.exe";
        private string resolvedPythonPath = string.Empty;

        private string assembleScriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "assemble_cheats.py");
        private string disassembleScriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ARMdisassemble_cheats.py");

        private AppSettings currentAppSettings;

        public CheatToolGUI()
        {
            InitializeComponent();

            Version appVersion = Assembly.GetExecutingAssembly().GetName().Version;
            this.Text = $"Cheat Tool v{appVersion.Major}.{appVersion.Minor}.{appVersion.Build}";

            currentAppSettings = AppSettings.Load();
            ApplySettingsToUI();

            SetStatus("Ready.");
            ResolvePythonPath();

            textBoxOutput.Font = new Font("Consolas", 9.75F, FontStyle.Regular);
        }

        private void ApplySettingsToUI()
        {
            if (currentAppSettings.DefaultArchitecture == "ARM32")
            {
                radioButtonArm32.Checked = true;
            }
            else
            {
                radioButtonArm64.Checked = true;
            }
            checkBoxShowRawOpcodes.Checked = currentAppSettings.ShowRawOpcodesInDisassembly;
        }

        private void ResolvePythonPath()
        {
            SetStatus("Locating Python executable...", false);
            string foundPath = string.Empty;

            if (!string.IsNullOrEmpty(currentAppSettings.PythonPath) && File.Exists(currentAppSettings.PythonPath))
            {
                foundPath = currentAppSettings.PythonPath;
                SetStatus($"Python found (from settings): {foundPath}");
            }
            else
            {
                foundPath = FindPythonExecutableInPath(pythonExecutableName);

                if (!string.IsNullOrEmpty(foundPath))
                {
                    resolvedPythonPath = foundPath;
                    SetStatus($"Python found at: {resolvedPythonPath}");
                }
                else
                {
                    foundPath = FindPythonExecutableInPath("py.exe");
                    if (!string.IsNullOrEmpty(foundPath))
                    {
                        pythonExecutableName = "py.exe";
                        resolvedPythonPath = foundPath;
                        SetStatus($"Python Launcher (py.exe) found at: {resolvedPythonPath}");
                    }
                    else
                    {
                        SetStatus("ERROR: Python executable (python.exe or py.exe) not found. Please install Python or set path in settings.", true);
                        btnAssemble.Enabled = false;
                        btnDisassemble.Enabled = false;
                    }
                }
            }
            resolvedPythonPath = foundPath;

            btnInstallPythonLibs.Enabled = !string.IsNullOrEmpty(resolvedPythonPath);
            btnAssemble.Enabled = !string.IsNullOrEmpty(resolvedPythonPath);
            btnDisassemble.Enabled = !string.IsNullOrEmpty(resolvedPythonPath);
        }

        private async void btnAssemble_Click(object sender, EventArgs e)
        {
            textBoxOutput.Clear();
            SetStatus("Assembling...");
            DisableUI();

            string inputCode = textBoxInput.Text;
            string targetArch = radioButtonArm32.Checked ? "ARM32" : "ARM64"; // Get selected arch from UI
            var result = await RunPythonScriptAsync(assembleScriptPath, inputCode, targetArch);

            textBoxOutput.Text = result.Output;
            if (!string.IsNullOrEmpty(result.Error))
            {
                SetStatus($"Assembly finished with errors.", true);
                textBoxOutput.AppendText(Environment.NewLine + "--- Errors ---" + Environment.NewLine + result.Error);
            }
            else
            {
                SetStatus("Assembly complete.");
            }
            EnableUI();
        }

        private async void btnDisassemble_Click(object sender, EventArgs e)
        {
            textBoxOutput.Clear();
            SetStatus("Disassembling...");
            DisableUI();

            string inputOpcodes = textBoxInput.Text;
            string targetArch = radioButtonArm32.Checked ? "ARM32" : "ARM64";
            bool showRawOpcodes = checkBoxShowRawOpcodes.Checked;

            var result = await RunPythonScriptAsync(disassembleScriptPath, inputOpcodes, targetArch, showRawOpcodes);

            textBoxOutput.Text = result.Output;
            if (!string.IsNullOrEmpty(result.Error))
            {
                SetStatus($"Disassembly finished with errors.", true);
                textBoxOutput.AppendText(Environment.NewLine + "--- Errors ---" + Environment.NewLine + result.Error);
            }
            else
            {
                SetStatus("Disassembly complete.");
            }
            EnableUI();
        }

        private async Task<(string Output, string Error)> RunPythonScriptAsync(string scriptPath, string inputData, string archArgument, bool showRawOpcodesInDisassembly = true)
        {
            StringBuilder outputBuilder = new StringBuilder();
            StringBuilder errorBuilder = new StringBuilder();

            if (string.IsNullOrEmpty(resolvedPythonPath))
            {
                return (string.Empty, "FATAL ERROR: Python executable path not resolved. Cannot run script.");
            }

            try
            {
                if (!File.Exists(scriptPath))
                {
                    errorBuilder.AppendLine($"Python script '{scriptPath}' not found. Ensure it's in the application's output directory.");
                    return (string.Empty, errorBuilder.ToString());
                }

                inputData = inputData.TrimStart('\uFEFF');

                using (Process process = new Process())
                {
                    process.StartInfo.FileName = resolvedPythonPath;

                    string arguments = $"-X utf8 \"{scriptPath}\" --arch {archArgument}";

                    if (scriptPath == disassembleScriptPath)
                    {
                        string rawOpcodesValue = showRawOpcodesInDisassembly ? "true" : "false";
                        arguments += $" --show-raw-opcodes {rawOpcodesValue}";
                    }

                    process.StartInfo.Arguments = arguments;

                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.RedirectStandardInput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.StartInfo.StandardInputEncoding = Encoding.UTF8;
                    process.StartInfo.StandardOutputEncoding = Encoding.UTF8;
                    process.StartInfo.StandardErrorEncoding = Encoding.UTF8;

                    process.OutputDataReceived += (sender, e) => { if (e.Data != null) outputBuilder.AppendLine(e.Data); };
                    process.ErrorDataReceived += (sender, e) => { if (e.Data != null) errorBuilder.AppendLine(e.Data); };

                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    await process.StandardInput.WriteAsync(inputData);
                    process.StandardInput.Close();

                    await Task.Run(() => process.WaitForExit());
                }
            }
            catch (Exception ex)
            {
                errorBuilder.AppendLine($"An unexpected error occurred: {ex.Message}");
                if (ex.InnerException != null)
                {
                    errorBuilder.AppendLine($"Inner Exception: {ex.InnerException.Message}");
                }
            }
            return (outputBuilder.ToString(), errorBuilder.ToString());
        }

        private async void btnInstallPythonLibs_Click(object sender, EventArgs e)
        {
            textBoxOutput.Clear();
            DisableUI();

            if (string.IsNullOrEmpty(resolvedPythonPath))
            {
                SetStatus("ERROR: Python executable not found. Cannot run pip. Please ensure Python is installed and in your PATH.", true);
                EnableUI();
                return;
            }

            SetStatus("Ensuring pip is installed and up-to-date...");
            textBoxOutput.AppendText("Running: " + resolvedPythonPath + " -m ensurepip --upgrade" + Environment.NewLine);
            var pipResult = await RunPipCommandAsync(resolvedPythonPath, "-m ensurepip --upgrade");

            textBoxOutput.AppendText(Environment.NewLine + "--- Pip Self-Install/Upgrade Output ---" + Environment.NewLine);
            textBoxOutput.AppendText(pipResult.Output);
            if (!string.IsNullOrEmpty(pipResult.Error))
            {
                textBoxOutput.AppendText(Environment.NewLine + "--- Pip Self-Install/Upgrade Errors ---" + Environment.NewLine);
                textBoxOutput.AppendText(pipResult.Error);
                SetStatus("Failed to install/upgrade pip. See errors above.", true);
                EnableUI();
                return;
            }
            else
            {
                textBoxOutput.AppendText("Pip self-install/upgrade command completed." + Environment.NewLine);
            }

            SetStatus("Installing/Updating Keystone and Capstone (this may take a moment)...");
            textBoxOutput.AppendText(Environment.NewLine + "Running: " + resolvedPythonPath + " -m pip install --upgrade keystone-engine capstone" + Environment.NewLine);

            var libsResult = await RunPipCommandAsync(
                resolvedPythonPath,
                "-m pip install --upgrade keystone-engine capstone"
            );

            textBoxOutput.AppendText(Environment.NewLine + "--- Library Installation Output ---" + Environment.NewLine);
            textBoxOutput.AppendText(libsResult.Output);

            if (!string.IsNullOrEmpty(libsResult.Error))
            {
                textBoxOutput.AppendText(Environment.NewLine + "--- Library Installation Errors ---" + Environment.NewLine);
                textBoxOutput.AppendText(libsResult.Error);
                SetStatus("Library installation/update finished with errors.", true);
            }
            else if (libsResult.Output.Contains("Successfully installed") || libsResult.Output.Contains("Requirement already satisfied"))
            {
                SetStatus("Keystone and Capstone installed/updated successfully!");
            }
            else
            {
                SetStatus("Library installation/update command completed. Check output for details.");
            }

            EnableUI();
        }

        private async Task<(string Output, string Error)> RunPipCommandAsync(string fileName, string arguments)
        {
            StringBuilder outputBuilder = new StringBuilder();
            StringBuilder errorBuilder = new StringBuilder();

            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = fileName;
                    process.StartInfo.Arguments = arguments;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.StartInfo.StandardOutputEncoding = Encoding.UTF8;
                    process.StartInfo.StandardErrorEncoding = Encoding.UTF8;

                    process.OutputDataReceived += (sender, e) => { if (e.Data != null) outputBuilder.AppendLine(e.Data); };
                    process.ErrorDataReceived += (sender, e) => { if (e.Data != null) errorBuilder.AppendLine(e.Data); };

                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    await Task.Run(() => process.WaitForExit());
                }
            }
            catch (Exception ex)
            {
                errorBuilder.AppendLine($"An unexpected error occurred while running command: {ex.Message}");
                if (ex.InnerException != null)
                {
                    errorBuilder.AppendLine($"Inner Exception: {ex.InnerException.Message}");
                }
            }
            return (outputBuilder.ToString(), errorBuilder.ToString());
        }

        private string FindPythonExecutableInPath(string executableName)
        {
            if (File.Exists(executableName))
            {
                return Path.GetFullPath(executableName);
            }

            var pathVar = Environment.GetEnvironmentVariable("PATH");
            if (string.IsNullOrEmpty(pathVar)) return string.Empty;

            var paths = pathVar.Split(Path.PathSeparator);
            foreach (var path in paths)
            {
                try
                {
                    string fullPath = Path.Combine(path, executableName);
                    if (File.Exists(fullPath))
                    {
                        return fullPath;
                    }
                }
                catch (ArgumentException)
                {
                    continue;
                }
            }
            return string.Empty;
        }

        private void SetStatus(string message, bool isError = false)
        {
            if (statusStrip.InvokeRequired)
            {
                statusStrip.Invoke(new Action(() => SetStatus(message, isError)));
            }
            else
            {
                statusLabel.Text = message;
                statusLabel.ForeColor = isError ? System.Drawing.Color.Red : System.Drawing.Color.Black;
            }
        }

        private void DisableUI()
        {
            textBoxInput.Enabled = false;
            btnAssemble.Enabled = false;
            btnDisassemble.Enabled = false;
            btnInstallPythonLibs.Enabled = false;
            btnLoadInput.Enabled = false;
            btnSaveOutput.Enabled = false;
            btnSaveInput.Enabled = false;
            btnSettings.Enabled = false;
            btnCopyOutput.Enabled = false;
            btnCopyInput.Enabled = false;
            radioButtonArm32.Enabled = false;
            radioButtonArm64.Enabled = false;
            checkBoxShowRawOpcodes.Enabled = false;
            textBoxCaveBaseAddress.Enabled = false;
            numericUpDownCaveLines.Enabled = false;
            btnGenerateCodeCave.Enabled = false;
            this.Cursor = Cursors.WaitCursor;
        }

        private void EnableUI()
        {
            if (!string.IsNullOrEmpty(resolvedPythonPath))
            {
                textBoxInput.Enabled = true;
                btnAssemble.Enabled = true;
                btnDisassemble.Enabled = true;
                radioButtonArm32.Enabled = true;
                radioButtonArm64.Enabled = true;
                checkBoxShowRawOpcodes.Enabled = true;
            }
            btnInstallPythonLibs.Enabled = !string.IsNullOrEmpty(resolvedPythonPath);
            btnLoadInput.Enabled = true;
            btnSaveOutput.Enabled = true;
            btnSaveInput.Enabled = true;
            btnSettings.Enabled = true;
            btnCopyOutput.Enabled = true;
            btnCopyInput.Enabled = true;
            textBoxCaveBaseAddress.Enabled = true;
            numericUpDownCaveLines.Enabled = true;
            btnGenerateCodeCave.Enabled = true;
            this.Cursor = Cursors.Default;
        }

        private void btnClearAll_Click(object sender, EventArgs e)
        {
            textBoxInput.Clear();
            textBoxOutput.Clear();
            SetStatus("Ready.");
            textBoxInput.Focus();
        }

        private void btnLoadInput_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "Text Files (*.txt)|*.txt|Cheat Files (*.cheat)|*.cheat|All Files (*.*)|*.*";
                openFileDialog.Title = "Load Input Text File";
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        string fileContent = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        textBoxInput.Text = fileContent;
                        SetStatus($"Loaded '{Path.GetFileName(openFileDialog.FileName)}'.");
                    }
                    catch (IOException ex)
                    {
                        SetStatus($"ERROR loading file: {ex.Message}", true);
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        SetStatus($"ERROR: Access to file denied: {ex.Message}", true);
                    }
                    catch (Exception ex)
                    {
                        SetStatus($"An unexpected error occurred: {ex.Message}", true);
                    }
                }
            }
        }

        private void btnSaveOutput_Click(object sender, EventArgs e)
        {
            using (SaveFileDialog saveFileDialog = new SaveFileDialog())
            {
                saveFileDialog.Filter = "Text Files (*.txt)|*.txt|Cheat Files (*.cheat)|*.cheat|All Files (*.*)|*.*";
                saveFileDialog.Title = "Save Assembled/Disassembled Output";
                saveFileDialog.DefaultExt = "txt";
                saveFileDialog.AddExtension = true;
                saveFileDialog.RestoreDirectory = true;

                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        File.WriteAllText(saveFileDialog.FileName, textBoxOutput.Text, Encoding.UTF8);
                        SetStatus($"Output saved to '{Path.GetFileName(saveFileDialog.FileName)}'.");
                    }
                    catch (IOException ex)
                    {
                        SetStatus($"ERROR saving file: {ex.Message}", true);
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        SetStatus($"ERROR: Access to file denied: {ex.Message}", true);
                    }
                    catch (Exception ex)
                    {
                        SetStatus($"An unexpected error occurred: {ex.Message}", true);
                    }
                }
            }
        }

        private void btnSaveInput_Click(object sender, EventArgs e)
        {
            using (SaveFileDialog saveFileDialog = new SaveFileDialog())
            {
                saveFileDialog.Filter = "Text Files (*.txt)|*.txt|Cheat Files (*.cheat)|*.cheat|All Files (*.*)|*.*";
                saveFileDialog.Title = "Save Current Input Text";
                saveFileDialog.DefaultExt = "txt";
                saveFileDialog.AddExtension = true;
                saveFileDialog.RestoreDirectory = true;

                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        File.WriteAllText(saveFileDialog.FileName, textBoxInput.Text, Encoding.UTF8);
                        SetStatus($"Input saved to '{Path.GetFileName(saveFileDialog.FileName)}'.");
                    }
                    catch (IOException ex)
                    {
                        SetStatus($"ERROR saving file: {ex.Message}", true);
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        SetStatus($"ERROR: Access to file denied: {ex.Message}", true);
                    }
                    catch (Exception ex)
                    {
                        SetStatus($"An unexpected error occurred: {ex.Message}", true);
                    }
                }
            }
        }

        private void btnSettings_Click(object sender, EventArgs e)
        {
            AppSettings tempSettings = new AppSettings
            {
                PythonPath = currentAppSettings.PythonPath,
                DefaultArchitecture = currentAppSettings.DefaultArchitecture,
                ShowRawOpcodesInDisassembly = currentAppSettings.ShowRawOpcodesInDisassembly
            };

            using (SettingsForm settingsForm = new SettingsForm(tempSettings))
            {
                if (settingsForm.ShowDialog() == DialogResult.OK)
                {
                    currentAppSettings.PythonPath = settingsForm.CurrentSettings.PythonPath;
                    currentAppSettings.DefaultArchitecture = settingsForm.CurrentSettings.DefaultArchitecture;
                    currentAppSettings.ShowRawOpcodesInDisassembly = settingsForm.CurrentSettings.ShowRawOpcodesInDisassembly;
                    currentAppSettings.Save();

                    ApplySettingsToUI();
                    ResolvePythonPath();
                    SetStatus("Settings saved and applied.");
                }
                else
                {
                    SetStatus("Settings not saved.");
                }
            }
        }

        private void checkBoxShowRawOpcodes_CheckedChanged(object sender, EventArgs e)
        {
            currentAppSettings.ShowRawOpcodesInDisassembly = checkBoxShowRawOpcodes.Checked;
            currentAppSettings.Save();
        }

        private void btnCopyOutput_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(textBoxOutput.Text))
            {
                try
                {
                    Clipboard.SetText(textBoxOutput.Text);
                    SetStatus("Output copied to clipboard.");
                }
                catch (Exception ex)
                {
                    SetStatus($"ERROR copying output: {ex.Message}", true);
                }
            }
            else
            {
                SetStatus("Output text box is empty. Nothing to copy.");
            }
        }

        private void btnCopyInput_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(textBoxInput.Text))
            {
                try
                {
                    Clipboard.SetText(textBoxInput.Text);
                    SetStatus("Input copied to clipboard.");
                }
                catch (Exception ex)
                {
                    SetStatus($"ERROR copying input: {ex.Message}", true);
                }
            }
            else
            {
                SetStatus("Input text box is empty. Nothing to copy.");
            }
        }

        private void btnGenerateCodeCave_Click(object sender, EventArgs e)
        {
            GenerateCodeCaveLayout();
        }

        private void GenerateCodeCaveLayout()
        {
            string inputLine = textBoxCaveBaseAddress.Text.Trim();
            int numberOfLines = (int)numericUpDownCaveLines.Value;

            if (string.IsNullOrWhiteSpace(inputLine))
            {
                SetStatus("Please enter a base address line for the code cave.", true);
                return;
            }
            if (numberOfLines <= 0)
            {
                SetStatus("Number of lines must be greater than zero.", true);
                return;
            }

            // Use a StringBuilder for efficient string concatenation
            StringBuilder outputBuilder = new StringBuilder();

            // Regular expression to find the hexadecimal address part
            // This regex looks for 0x followed by one or more hex characters
            // and captures it, along with the prefix and suffix.
            // Group 1: Prefix (e.g., [Main+R0+)
            // Group 2: The 0xhexaddress
            // Group 3: Suffix (e.g., =)
            System.Text.RegularExpressions.Match match =
                System.Text.RegularExpressions.Regex.Match(inputLine, @"^(.+)(0x[0-9a-fA-F]+)(.*)$");

            if (!match.Success)
            {
                SetStatus("Invalid input format. Expected something like '[Main+R0+0x0004E4B640]='", true);
                return;
            }

            string prefix = match.Groups[1].Value;
            string hexAddressString = match.Groups[2].Value; // e.g., "0x0004E4B640"
            string suffix = match.Groups[3].Value; // e.g., "="

            // Parse the hexadecimal address
            // Remove "0x" prefix for parsing
            if (!long.TryParse(hexAddressString.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out long baseAddress))
            {
                SetStatus($"Failed to parse hexadecimal address: {hexAddressString}", true);
                return;
            }

            // Generate the lines
            for (int i = 0; i < numberOfLines; i++)
            {
                long currentAddress = baseAddress + (long)(i * 4); // Increment by 4 bytes (standard instruction size)
                string currentHexAddress = $"0x{currentAddress:X}"; // Format back to hex with "0x" and uppercase

                outputBuilder.AppendLine($"{prefix}{currentHexAddress}{suffix}");
            }

            textBoxOutput.Text = outputBuilder.ToString();
            SetStatus($"Generated {numberOfLines} code cave lines.");
        }
    }
}