using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Drawing;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Net.Sockets;
using CheatToolUI;


namespace CheatToolUI
{
    public partial class CheatToolGUI : Form
    {
        private string pythonExecutableName = "python.exe";
        private string resolvedPythonPath = string.Empty;
        private bool isApplyingTheme = false;

        private string assembleScriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "assemble_cheats.py");
        private string disassembleScriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ARMdisassemble_cheats.py");

        private AppSettings currentAppSettings;

        private List<Instruction> allInstructions;
        private const string InstructionDataFileName = "InstructionData.json";
        private List<VMOpcode> allVMOpcodes;
        private const string VMOpcodeDataFileName = "vm_opcodes.json";

        private bool isHighlighting = false;

        public class VMOpcode
        {
            public string Name { get; set; }
            public string OpcodeValue { get; set; }
            public List<string> Architectures { get; set; }
            public List<string> Syntax { get; set; }
            public string Description { get; set; }
        }

        public CheatToolGUI()
        {
            InitializeComponent();

            Version appVersion = Assembly.GetExecutingAssembly().GetName().Version;
            this.Text = $"Cheat Tool v{appVersion.Major}.{appVersion.Minor}.{appVersion.Build}";

            currentAppSettings = AppSettings.Load();
            ApplyTheme(currentAppSettings.DarkModeEnabled);
            ApplySettingsToUI();

            SetStatus("Ready.");
            ResolvePythonPath();

            textBoxOutput.Font = new Font("Consolas", 9.75F, FontStyle.Regular);
            textBoxInput.Font = new Font("Consolas", 9.75F, FontStyle.Regular);
            richTextBoxOpDescription.Font = new Font("Consolas", 9.75F, FontStyle.Regular);

            LoadInstructions();
            LoadVMOpcodes();

            textBoxSearchInstruction.TextChanged += TextBoxSearchInstruction_TextChanged;
            listBoxInstructions.SelectedIndexChanged += ListBoxInstructions_SelectedIndexChanged;
            listBoxVmOpcodes.SelectedIndexChanged += ListBoxVmOpcodes_SelectedIndexChanged;

            textBoxInput.TextChanged += TextBoxInput_TextChanged;
            HighlightSyntax(currentAppSettings.DarkModeEnabled);
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

        // --- Dark Mode Theming Logic ---

        public void ApplyTheme(bool isDarkMode)
        {
            if (isApplyingTheme) return;
            isApplyingTheme = true;

            this.BackColor = isDarkMode ? ThemeColors.Dark_Background : ThemeColors.Light_Background;
            this.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;

            ApplyThemeToControls(this.Controls, isDarkMode);

            if (statusStrip != null)
            {
                statusStrip.BackColor = isDarkMode ? ThemeColors.Dark_StatusStripBackground : ThemeColors.Light_StatusStripBackground;
                foreach (ToolStripItem item in statusStrip.Items)
                {
                    item.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;
                }
            }

            if (statusStrip != null)
            {
                statusStrip.BackColor = isDarkMode ? ThemeColors.Dark_MenuBackground : ThemeColors.Light_MenuBackground;
                statusStrip.ForeColor = isDarkMode ? ThemeColors.Dark_MenuForeground : ThemeColors.Light_MenuForeground;
                ApplyThemeToMenuItems(statusStrip.Items, isDarkMode);
            }

            // After applying the new theme, re-highlight syntax to ensure colors are correct
            // Temporarily detach TextChanged event to prevent re-highlighting during theme change
            textBoxInput.TextChanged -= TextBoxInput_TextChanged;
            HighlightSyntax(currentAppSettings.DarkModeEnabled); // Re-highlight based on new theme colors
            textBoxInput.TextChanged += TextBoxInput_TextChanged;

            isApplyingTheme = false;
        }

        private void ApplyThemeToControls(Control.ControlCollection controls, bool isDarkMode)
        {
            foreach (Control control in controls)
            {
                control.BackColor = isDarkMode ? ThemeColors.Dark_ControlBackground : ThemeColors.Light_ControlBackground;
                control.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;

                if (control is Button button)
                {
                    button.BackColor = isDarkMode ? ThemeColors.Dark_ButtonBackground : ThemeColors.Light_ButtonBackground;
                    button.ForeColor = isDarkMode ? ThemeColors.Dark_ButtonForeground : ThemeColors.Light_ButtonForeground;
                    button.FlatStyle = FlatStyle.Flat; // Ensures consistent look
                    button.FlatAppearance.BorderColor = isDarkMode ? ThemeColors.Dark_InputBorder : ThemeColors.Light_InputBorder;
                    button.FlatAppearance.BorderSize = 1;
                }
                else if (control is TextBox textBox)
                {
                    textBox.BackColor = isDarkMode ? ThemeColors.Dark_TextBoxBackground : ThemeColors.Light_TextBoxBackground;
                    textBox.ForeColor = isDarkMode ? ThemeColors.Dark_TextBoxForeground : ThemeColors.Light_TextBoxForeground;
                    textBox.BorderStyle = BorderStyle.FixedSingle;
                }
                else if (control is RichTextBox richTextBox)
                {
                    richTextBox.BackColor = isDarkMode ? ThemeColors.Dark_TextBoxBackground : ThemeColors.Light_TextBoxBackground;
                    richTextBox.ForeColor = isDarkMode ? ThemeColors.Dark_TextBoxForeground : ThemeColors.Light_TextBoxForeground;
                    richTextBox.BorderStyle = BorderStyle.FixedSingle;
                }
                else if (control is Label label)
                {
                    label.BackColor = isDarkMode ? ThemeColors.Dark_Background : ThemeColors.Light_Background; // Labels often inherit parent background
                    label.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;
                }
                else if (control is RadioButton radioButton)
                {
                    radioButton.BackColor = isDarkMode ? ThemeColors.Dark_Background : ThemeColors.Light_Background;
                    radioButton.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;
                }
                else if (control is CheckBox checkBox)
                {
                    checkBox.BackColor = isDarkMode ? ThemeColors.Dark_Background : ThemeColors.Light_Background;
                    checkBox.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;
                }
                else if (control is GroupBox groupBox)
                {
                    groupBox.BackColor = isDarkMode ? ThemeColors.Dark_Background : ThemeColors.Light_Background;
                    groupBox.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;
                }
                else if (control is Panel panel)
                {
                    panel.BackColor = isDarkMode ? ThemeColors.Dark_Background : ThemeColors.Light_Background; // Panels often just hold other controls
                    panel.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;
                }
                else if (control is ListBox listBox)
                {
                    listBox.BackColor = isDarkMode ? ThemeColors.Dark_TextBoxBackground : ThemeColors.Light_TextBoxBackground;
                    listBox.ForeColor = isDarkMode ? ThemeColors.Dark_TextBoxForeground : ThemeColors.Light_TextBoxForeground;
                    listBox.BorderStyle = BorderStyle.FixedSingle;
                }

                if (control.HasChildren)
                {
                    ApplyThemeToControls(control.Controls, isDarkMode);
                }
            }
        }

        private void ApplyThemeToMenuItems(ToolStripItemCollection items, bool isDarkMode)
        {
            foreach (ToolStripItem item in items)
            {
                item.BackColor = isDarkMode ? ThemeColors.Dark_MenuBackground : ThemeColors.Light_MenuBackground;
                item.ForeColor = isDarkMode ? ThemeColors.Dark_MenuForeground : ThemeColors.Light_MenuForeground;

                if (item is ToolStripMenuItem menuItem && menuItem.HasDropDownItems)
                {
                    ApplyThemeToMenuItems(menuItem.DropDownItems, isDarkMode);
                }
            }
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
            string targetArch = radioButtonArm32.Checked ? "ARM32" : "ARM64";
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
                statusStrip.Invoke(new System.Windows.Forms.MethodInvoker(() => SetStatus(message, isError)));
                return;
            }


            bool isDarkMode = currentAppSettings.DarkModeEnabled;

            if (isError)
            {
                statusLabel.ForeColor = isDarkMode ? ThemeColors.Dark_ErrorText : ThemeColors.Light_ErrorText;
            }
            else if (message.Contains("Warning", StringComparison.OrdinalIgnoreCase))
            {
                statusLabel.ForeColor = isDarkMode ? ThemeColors.Dark_WarningText : ThemeColors.Light_WarningText;
            }
            else if (message.Contains("complete", StringComparison.OrdinalIgnoreCase) || message.Contains("Ready", StringComparison.OrdinalIgnoreCase))
            {
                statusLabel.ForeColor = isDarkMode ? ThemeColors.Dark_SuccessText : ThemeColors.Light_SuccessText;
            }
            else
            {
                // Default foreground color
                statusLabel.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;
            }
            statusLabel.Text = message;
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

            textBoxSearchInstruction.Enabled = false;
            listBoxInstructions.Enabled = false;
            richTextBoxInstructionDetails.Enabled = false;

            listBoxVmOpcodes.Enabled = false;
            richTextBoxOpDescription.Enabled = false;

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

            textBoxSearchInstruction.Enabled = true;
            listBoxInstructions.Enabled = true;
            richTextBoxInstructionDetails.Enabled = true;

            listBoxVmOpcodes.Enabled = true;
            richTextBoxOpDescription.Enabled = true;

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

            using (SettingsForm settingsForm = new SettingsForm(currentAppSettings))
            {
                if (settingsForm.ShowDialog() == DialogResult.OK)
                {

                    currentAppSettings.Save(); // Save the updated settings to file

                    ApplyTheme(currentAppSettings.DarkModeEnabled);

                    ApplySettingsToUI();
                    ResolvePythonPath();
                    SetStatus("Settings saved and applied.");
                }
                else
                {
                    currentAppSettings = AppSettings.Load();
                    ApplyTheme(currentAppSettings.DarkModeEnabled);
                    ApplySettingsToUI();
                    ResolvePythonPath();
                    SetStatus("Settings not saved (reverted to previous settings).");
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

            StringBuilder outputBuilder = new StringBuilder();

            System.Text.RegularExpressions.Match match =
                System.Text.RegularExpressions.Regex.Match(inputLine, @"^(.+)(0x[0-9a-fA-F]+)(.*)$");

            if (!match.Success)
            {
                SetStatus("Invalid input format. Expected something like '[Main+R0+0x0004E4B640]='", true);
                return;
            }

            string prefix = match.Groups[1].Value;
            string hexAddressString = match.Groups[2].Value;
            string suffix = match.Groups[3].Value;

            if (!long.TryParse(hexAddressString.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out long baseAddress))
            {
                SetStatus($"Failed to parse hexadecimal address: {hexAddressString}", true);
                return;
            }

            for (int i = 0; i < numberOfLines; i++)
            {
                long currentAddress = baseAddress + (long)(i * 4);
                string currentHexAddress = $"0x{currentAddress:X}";

                outputBuilder.AppendLine($"{prefix}{currentHexAddress}{suffix}");
            }

            textBoxOutput.Text = outputBuilder.ToString();
            SetStatus($"Generated {numberOfLines} code cave lines.");
        }

        private void LoadVMOpcodes()
        {
            string vmOpcodeFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, VMOpcodeDataFileName);
            if (File.Exists(vmOpcodeFilePath))
            {
                try
                {
                    string jsonString = File.ReadAllText(vmOpcodeFilePath);
                    allVMOpcodes = JsonSerializer.Deserialize<List<VMOpcode>>(jsonString);
                    SetStatus("VM Opcode reference data loaded.");
                    PopulateVMOpcodeListBox(allVMOpcodes);
                }
                catch (Exception ex)
                {
                    allVMOpcodes = new List<VMOpcode>();
                    SetStatus($"ERROR loading VM opcode data: {ex.Message}", true);
                    MessageBox.Show($"Could not load VM opcode data from '{VMOpcodeDataFileName}'. Please ensure it's a valid JSON file. Error: {ex.Message}", "VM Opcode Data Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else
            {
                allVMOpcodes = new List<VMOpcode>();
                SetStatus($"WARNING: VM opcode data file '{VMOpcodeDataFileName}' not found.", true);
                MessageBox.Show($"VM opcode data file '{VMOpcodeDataFileName}' not found. The VM opcode reference feature will not be available.", "VM Opcode Data Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void PopulateVMOpcodeListBox(List<VMOpcode> vmOpcodesToDisplay)
        {
            listBoxVmOpcodes.DataSource = null; // Clear existing data source
            if (vmOpcodesToDisplay != null)
            {
                listBoxVmOpcodes.DisplayMember = "Name";
                listBoxVmOpcodes.ValueMember = "Name"; // Display "Name", use "Name" as value
                listBoxVmOpcodes.DataSource = vmOpcodesToDisplay.OrderBy(o => o.Name).ToList();
            }
        }

        private void ListBoxVmOpcodes_SelectedIndexChanged(object sender, EventArgs e)
        {
            // Clear the ARM instruction details when a VM opcode is selected
            richTextBoxInstructionDetails.Clear();
            // Ensure the Opcode description box is also cleared if nothing is selected
            richTextBoxOpDescription.Clear();

            if (listBoxVmOpcodes.SelectedItem is VMOpcode selectedVMOpcode)
            {
                richTextBoxOpDescription.SelectAll();
                richTextBoxOpDescription.SelectionColor = richTextBoxOpDescription.ForeColor;
                richTextBoxOpDescription.SelectionFont = richTextBoxOpDescription.Font;
                richTextBoxOpDescription.Clear();

                // Display Name and OpcodeValue (bold)
                richTextBoxOpDescription.SelectionFont = new Font(richTextBoxOpDescription.Font, FontStyle.Bold);
                richTextBoxOpDescription.AppendText($"{selectedVMOpcode.Name} (Opcode: {selectedVMOpcode.OpcodeValue})\n\n");

                // Display Architectures
                richTextBoxOpDescription.SelectionFont = new Font(richTextBoxOpDescription.Font, FontStyle.Regular);
                richTextBoxOpDescription.AppendText("Architectures: ");
                richTextBoxOpDescription.SelectionFont = new Font(richTextBoxOpDescription.Font, FontStyle.Bold);
                richTextBoxOpDescription.AppendText(string.Join(", ", selectedVMOpcode.Architectures));
                richTextBoxOpDescription.AppendText("\n\n");

                // Display Syntax
                richTextBoxOpDescription.SelectionFont = new Font(richTextBoxOpDescription.Font, FontStyle.Regular);
                richTextBoxOpDescription.AppendText("Syntax:\n");
                foreach (string syntaxLine in selectedVMOpcode.Syntax)
                {
                    richTextBoxOpDescription.SelectionFont = new Font("Consolas", richTextBoxOpDescription.Font.Size, FontStyle.Italic);
                    richTextBoxOpDescription.AppendText($"  {syntaxLine}\n");
                }
                richTextBoxOpDescription.AppendText("\n");

                // Display Description
                richTextBoxOpDescription.SelectionFont = new Font(richTextBoxOpDescription.Font, FontStyle.Regular);
                richTextBoxOpDescription.AppendText("Description:\n");
                richTextBoxOpDescription.AppendText(selectedVMOpcode.Description);

                // Reset font and color for future appended text
                richTextBoxOpDescription.SelectionFont = richTextBoxOpDescription.Font;
                richTextBoxOpDescription.SelectionColor = richTextBoxOpDescription.ForeColor;

                // Optionally, deselect the ARM instruction listbox if an VM opcode is selected
                listBoxInstructions.ClearSelected();
            }
            else
            {
                richTextBoxOpDescription.Clear();
            }
        }

        private void LoadInstructions()
        {
            string instructionFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, InstructionDataFileName);
            if (File.Exists(instructionFilePath))
            {
                try
                {
                    string jsonString = File.ReadAllText(instructionFilePath);
                    allInstructions = JsonSerializer.Deserialize<List<Instruction>>(jsonString);
                    SetStatus("Instruction reference data loaded.");
                    PopulateInstructionListBox(allInstructions);
                }
                catch (Exception ex)
                {
                    allInstructions = new List<Instruction>();
                    SetStatus($"ERROR loading instruction data: {ex.Message}", true);
                    MessageBox.Show($"Could not load instruction data from '{InstructionDataFileName}'. Please ensure it's a valid JSON file. Error: {ex.Message}", "Instruction Data Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else
            {
                allInstructions = new List<Instruction>();
                SetStatus($"WARNING: Instruction data file '{InstructionDataFileName}' not found.", true);
                MessageBox.Show($"Instruction data file '{InstructionDataFileName}' not found. The instruction reference feature will not be available.", "Instruction Data Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void PopulateInstructionListBox(List<Instruction> instructionsToDisplay)
        {
            listBoxInstructions.DataSource = null;
            if (instructionsToDisplay != null)
            {
                listBoxInstructions.DisplayMember = "Name";
                listBoxInstructions.ValueMember = "Name";
                listBoxInstructions.DataSource = instructionsToDisplay.OrderBy(i => i.Name).ToList();
            }
        }

        private void TextBoxSearchInstruction_TextChanged(object sender, EventArgs e)
        {
            string searchTerm = textBoxSearchInstruction.Text.Trim();
            if (string.IsNullOrEmpty(searchTerm))
            {
                PopulateInstructionListBox(allInstructions);
            }
            else
            {
                var filteredInstructions = allInstructions
                    .Where(i => i.Name.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                PopulateInstructionListBox(filteredInstructions);
            }
        }

        private void ListBoxInstructions_SelectedIndexChanged(object sender, EventArgs e)
        {
            richTextBoxOpDescription.Clear();

            if (listBoxInstructions.SelectedItem is Instruction selectedInstruction)
            {
                richTextBoxInstructionDetails.SelectAll();
                richTextBoxInstructionDetails.SelectionColor = richTextBoxInstructionDetails.ForeColor;
                richTextBoxInstructionDetails.SelectionFont = richTextBoxInstructionDetails.Font;
                richTextBoxInstructionDetails.Clear();

                richTextBoxInstructionDetails.SelectionFont = new Font(richTextBoxInstructionDetails.Font, FontStyle.Bold);
                richTextBoxInstructionDetails.AppendText($"{selectedInstruction.Name}\n\n");

                richTextBoxInstructionDetails.SelectionFont = new Font(richTextBoxInstructionDetails.Font, FontStyle.Regular);
                richTextBoxInstructionDetails.AppendText("Architectures: ");
                richTextBoxInstructionDetails.SelectionFont = new Font(richTextBoxInstructionDetails.Font, FontStyle.Bold);
                richTextBoxInstructionDetails.AppendText(string.Join(", ", selectedInstruction.Architectures));
                richTextBoxInstructionDetails.AppendText("\n\n");

                richTextBoxInstructionDetails.SelectionFont = new Font(richTextBoxInstructionDetails.Font, FontStyle.Regular);
                richTextBoxInstructionDetails.AppendText("Syntax:\n");
                foreach (string syntaxLine in selectedInstruction.Syntax)
                {
                    richTextBoxInstructionDetails.SelectionFont = new Font("Consolas", richTextBoxInstructionDetails.Font.Size, FontStyle.Italic);
                    richTextBoxInstructionDetails.AppendText($"  {syntaxLine}\n");
                }
                richTextBoxInstructionDetails.AppendText("\n");

                richTextBoxInstructionDetails.SelectionFont = new Font(richTextBoxInstructionDetails.Font, FontStyle.Regular);
                richTextBoxInstructionDetails.AppendText("Description:\n");
                richTextBoxInstructionDetails.AppendText(selectedInstruction.Description);
            }
            else
            {
                richTextBoxInstructionDetails.Clear();
            }
            listBoxVmOpcodes.ClearSelected();
        }

        private void TextBoxInput_TextChanged(object sender, EventArgs e)
        {
            if (isApplyingTheme) return;
            if (isHighlighting) return;
            HighlightSyntax(currentAppSettings.DarkModeEnabled);
        }

        private void HighlightSyntax(bool isDarkMode)
        {
            if (isHighlighting) return;
            isHighlighting = true;

            int originalSelectionStart = textBoxInput.SelectionStart;
            int originalSelectionLength = textBoxInput.SelectionLength;

            textBoxInput.SelectAll();
            textBoxInput.SelectionColor = isDarkMode ? ThemeColors.Dark_TextBoxForeground : ThemeColors.Light_TextBoxForeground;
            textBoxInput.SelectionFont = new Font("Consolas", 9.75F, FontStyle.Regular);
            textBoxInput.DeselectAll();

            textBoxInput.BackColor = isDarkMode ? ThemeColors.Dark_TextBoxBackground : ThemeColors.Light_TextBoxBackground;


            Regex opcodeRegex = new Regex(@"^\s*([a-zA-Z]{2,6})\b", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            Regex registerRegex = new Regex(@"\b(X(?:[0-2]?[0-9]|30|ZR)|W(?:[0-2]?[0-9]|30|ZR)|LR|SP|PC|R(?:[0-9]|1[0-5]|LR|SP|PC)|CPSR|SPSR|APSR|IP)\b", RegexOptions.IgnoreCase);
            Regex hexLiteralRegex = new Regex(@"\b0x[0-9a-fA-F]+\b", RegexOptions.IgnoreCase);
            Regex decimalLiteralRegex = new Regex(@"\b#?-?\d+\b", RegexOptions.IgnoreCase);
            Regex commentRegex = new Regex(@";.*$", RegexOptions.Multiline);
            Regex labelRegex = new Regex(@"^\s*([a-zA-Z_][a-zA-Z0-9_]*):", RegexOptions.Multiline);

            string[] lines = textBoxInput.Lines;
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];
                int lineStart = textBoxInput.GetFirstCharIndexFromLine(i);

                Match labelMatch = labelRegex.Match(line);
                if (labelMatch.Success)
                {
                    textBoxInput.Select(lineStart + labelMatch.Groups[1].Index, labelMatch.Groups[1].Length);
                    textBoxInput.SelectionColor = isDarkMode ? Color.LightGreen : Color.DarkGreen;
                    textBoxInput.Select(lineStart + labelMatch.Index + labelMatch.Length - 1, 1);
                    textBoxInput.SelectionColor = isDarkMode ? Color.LightGray : Color.Silver;
                }

                Match commentMatch = commentRegex.Match(line);
                if (commentMatch.Success)
                {
                    textBoxInput.Select(lineStart + commentMatch.Index, commentMatch.Length);
                    // Make Comment Color Theme Aware
                    textBoxInput.SelectionColor = isDarkMode ? Color.DimGray : Color.DarkGray; // Example: Adjust for theme
                }
            }

            foreach (Match match in opcodeRegex.Matches(textBoxInput.Text))
            {
                textBoxInput.Select(match.Groups[1].Index, match.Groups[1].Length);
                // Make Opcode Color Theme Aware
                textBoxInput.SelectionColor = isDarkMode ? ThemeColors.Dark_CheatHeader : ThemeColors.Light_CheatHeader; // Using Dark_CheatHeader (Cyan)
            }

            foreach (Match match in registerRegex.Matches(textBoxInput.Text))
            {
                textBoxInput.Select(match.Index, match.Length);
                // Make Register Color Theme Aware
                textBoxInput.SelectionColor = isDarkMode ? Color.Orange : Color.DarkOrange; // Example: Adjust for theme
            }

            foreach (Match match in hexLiteralRegex.Matches(textBoxInput.Text))
            {
                textBoxInput.Select(match.Index, match.Length);
                // Make Hex Literal Color Theme Aware
                textBoxInput.SelectionColor = isDarkMode ? Color.LightCoral : Color.DarkRed; // Example: Adjust for theme
            }

            foreach (Match match in decimalLiteralRegex.Matches(textBoxInput.Text))
            {
                textBoxInput.Select(match.Index, match.Length);
                // Make Decimal Literal Color Theme Aware
                textBoxInput.SelectionColor = isDarkMode ? Color.LightCoral : Color.DarkRed; // Example: Adjust for theme
            }

            textBoxInput.SelectionStart = originalSelectionStart;
            textBoxInput.SelectionLength = originalSelectionLength;

            // This line is important to ensure newly typed text inherits the current ForeColor of the RTB
            // and doesn't pick up the last SelectionColor.
            textBoxInput.SelectionColor = textBoxInput.ForeColor;
            textBoxInput.SelectionFont = new Font("Consolas", 9.75F, FontStyle.Regular); // Ensure current font is correct

            isHighlighting = false;
        }

        private void tabPageMain_Click(object sender, EventArgs e)
        {

        }

        private void tabPageInstructionRef_Click(object sender, EventArgs e)
        {

        }

        private void btnSwitchInjection_Click(object sender, EventArgs e)
        {
            // Create a new instance of the SwitchInjection form
            SwitchInjection switchForm = new SwitchInjection();

            // Show the form
            // Option 1: ShowDialog() - Opens modally. User must close SwitchInjection before interacting with CheatToolGUI.
            // switchForm.ShowDialog();

            // Option 2: Show() - Opens non-modally. User can interact with both forms simultaneously.
            switchForm.Show();

            // Optional: If I want to prevent multiple instances of SwitchInjection,
            // I could store a reference to the form and only create it once.
            // Example (add private SwitchInjection _switchForm; to class):
            /*
            if (_switchForm == null || _switchForm.IsDisposed)
            {
                _switchForm = new SwitchInjection();
                _switchForm.Show();
            }
            else
            {
                _switchForm.Activate(); // Bring it to the front if it's already open
            }
            */
        }
    }
}