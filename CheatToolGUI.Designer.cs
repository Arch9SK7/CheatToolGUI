namespace CheatToolUI

{
    partial class CheatToolGUI
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            textBoxInput = new RichTextBox();
            textBoxOutput = new RichTextBox();
            btnDisassemble = new Button();
            btnAssemble = new Button();
            btnClearAll = new Button();
            radioButtonArm32 = new RadioButton();
            radioButtonArm64 = new RadioButton();
            statusStrip = new StatusStrip();
            statusLabel = new ToolStripStatusLabel();
            btnInstallPythonLibs = new Button();
            btnLoadInput = new Button();
            btnSaveInput = new Button();
            btnSaveOutput = new Button();
            btnSettings = new Button();
            btnCopyInput = new Button();
            btnCopyOutput = new Button();
            checkBoxShowRawOpcodes = new CheckBox();
            textBoxCaveBaseAddress = new TextBox();
            numericUpDownCaveLines = new NumericUpDown();
            btnGenerateCodeCave = new Button();
            statusStrip.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)numericUpDownCaveLines).BeginInit();
            SuspendLayout();
            // 
            // textBoxInput
            // 
            textBoxInput.Location = new Point(16, 99);
            textBoxInput.Name = "textBoxInput";
            textBoxInput.ScrollBars = RichTextBoxScrollBars.Vertical;
            textBoxInput.Size = new Size(608, 587);
            textBoxInput.TabIndex = 0;
            textBoxInput.Text = "";
            // 
            // textBoxOutput
            // 
            textBoxOutput.Location = new Point(630, 99);
            textBoxOutput.Name = "textBoxOutput";
            textBoxOutput.ReadOnly = true;
            textBoxOutput.Size = new Size(834, 587);
            textBoxOutput.TabIndex = 1;
            textBoxOutput.Text = "";
            textBoxOutput.WordWrap = false;
            // 
            // btnDisassemble
            // 
            btnDisassemble.Location = new Point(311, 53);
            btnDisassemble.Name = "btnDisassemble";
            btnDisassemble.Size = new Size(160, 40);
            btnDisassemble.TabIndex = 2;
            btnDisassemble.Text = "Disassemble";
            btnDisassemble.UseVisualStyleBackColor = true;
            btnDisassemble.Click += btnDisassemble_Click;
            // 
            // btnAssemble
            // 
            btnAssemble.Location = new Point(1087, 53);
            btnAssemble.Name = "btnAssemble";
            btnAssemble.Size = new Size(160, 40);
            btnAssemble.TabIndex = 3;
            btnAssemble.Text = "Assemble";
            btnAssemble.UseVisualStyleBackColor = true;
            btnAssemble.Click += btnAssemble_Click;
            // 
            // btnClearAll
            // 
            btnClearAll.Location = new Point(743, 62);
            btnClearAll.Name = "btnClearAll";
            btnClearAll.Size = new Size(75, 23);
            btnClearAll.TabIndex = 4;
            btnClearAll.Text = "Clear All";
            btnClearAll.UseVisualStyleBackColor = true;
            btnClearAll.Click += btnClearAll_Click;
            // 
            // radioButtonArm32
            // 
            radioButtonArm32.AutoSize = true;
            radioButtonArm32.Location = new Point(557, 53);
            radioButtonArm32.Name = "radioButtonArm32";
            radioButtonArm32.Size = new Size(63, 19);
            radioButtonArm32.TabIndex = 5;
            radioButtonArm32.TabStop = true;
            radioButtonArm32.Text = "ARM32";
            radioButtonArm32.UseVisualStyleBackColor = true;
            // 
            // radioButtonArm64
            // 
            radioButtonArm64.AutoSize = true;
            radioButtonArm64.Location = new Point(557, 74);
            radioButtonArm64.Name = "radioButtonArm64";
            radioButtonArm64.Size = new Size(63, 19);
            radioButtonArm64.TabIndex = 6;
            radioButtonArm64.TabStop = true;
            radioButtonArm64.Text = "ARM64";
            radioButtonArm64.UseVisualStyleBackColor = true;
            // 
            // statusStrip
            // 
            statusStrip.Items.AddRange(new ToolStripItem[] { statusLabel });
            statusStrip.Location = new Point(0, 812);
            statusStrip.Name = "statusStrip";
            statusStrip.Size = new Size(1476, 22);
            statusStrip.TabIndex = 7;
            statusStrip.Text = "statusLabel1";
            // 
            // statusLabel
            // 
            statusLabel.Name = "statusLabel";
            statusLabel.Size = new Size(1461, 17);
            statusLabel.Spring = true;
            // 
            // btnInstallPythonLibs
            // 
            btnInstallPythonLibs.Location = new Point(1304, 53);
            btnInstallPythonLibs.Name = "btnInstallPythonLibs";
            btnInstallPythonLibs.RightToLeft = RightToLeft.No;
            btnInstallPythonLibs.Size = new Size(160, 40);
            btnInstallPythonLibs.TabIndex = 8;
            btnInstallPythonLibs.Text = "Install/Update Python Libs";
            btnInstallPythonLibs.UseVisualStyleBackColor = true;
            btnInstallPythonLibs.Click += btnInstallPythonLibs_Click;
            // 
            // btnLoadInput
            // 
            btnLoadInput.Location = new Point(12, 12);
            btnLoadInput.Name = "btnLoadInput";
            btnLoadInput.Size = new Size(75, 23);
            btnLoadInput.TabIndex = 9;
            btnLoadInput.Text = "Load Input";
            btnLoadInput.UseVisualStyleBackColor = true;
            btnLoadInput.Click += btnLoadInput_Click;
            // 
            // btnSaveInput
            // 
            btnSaveInput.Location = new Point(12, 41);
            btnSaveInput.Name = "btnSaveInput";
            btnSaveInput.Size = new Size(75, 23);
            btnSaveInput.TabIndex = 10;
            btnSaveInput.Text = "Save Input";
            btnSaveInput.UseVisualStyleBackColor = true;
            btnSaveInput.Click += btnSaveInput_Click;
            // 
            // btnSaveOutput
            // 
            btnSaveOutput.Location = new Point(1380, 12);
            btnSaveOutput.Name = "btnSaveOutput";
            btnSaveOutput.Size = new Size(84, 23);
            btnSaveOutput.TabIndex = 11;
            btnSaveOutput.Text = "Save Output";
            btnSaveOutput.UseVisualStyleBackColor = true;
            btnSaveOutput.Click += btnSaveOutput_Click;
            // 
            // btnSettings
            // 
            btnSettings.Location = new Point(100, 53);
            btnSettings.Name = "btnSettings";
            btnSettings.Size = new Size(160, 40);
            btnSettings.TabIndex = 12;
            btnSettings.Text = "Settings";
            btnSettings.UseVisualStyleBackColor = true;
            btnSettings.Click += btnSettings_Click;
            // 
            // btnCopyInput
            // 
            btnCopyInput.Location = new Point(837, 62);
            btnCopyInput.Name = "btnCopyInput";
            btnCopyInput.Size = new Size(75, 23);
            btnCopyInput.TabIndex = 13;
            btnCopyInput.Text = "Copy Input";
            btnCopyInput.UseVisualStyleBackColor = true;
            btnCopyInput.Click += btnCopyInput_Click;
            // 
            // btnCopyOutput
            // 
            btnCopyOutput.Location = new Point(929, 62);
            btnCopyOutput.Name = "btnCopyOutput";
            btnCopyOutput.Size = new Size(89, 23);
            btnCopyOutput.TabIndex = 14;
            btnCopyOutput.Text = "Copy Output";
            btnCopyOutput.UseVisualStyleBackColor = true;
            btnCopyOutput.Click += btnCopyOutput_Click;
            // 
            // checkBoxShowRawOpcodes
            // 
            checkBoxShowRawOpcodes.AutoSize = true;
            checkBoxShowRawOpcodes.Checked = true;
            checkBoxShowRawOpcodes.CheckState = CheckState.Checked;
            checkBoxShowRawOpcodes.Location = new Point(650, 66);
            checkBoxShowRawOpcodes.Name = "checkBoxShowRawOpcodes";
            checkBoxShowRawOpcodes.Size = new Size(80, 19);
            checkBoxShowRawOpcodes.TabIndex = 15;
            checkBoxShowRawOpcodes.Text = "Show Raw";
            checkBoxShowRawOpcodes.UseVisualStyleBackColor = true;
            checkBoxShowRawOpcodes.CheckedChanged += checkBoxShowRawOpcodes_CheckedChanged;
            // 
            // textBoxCaveBaseAddress
            // 
            textBoxCaveBaseAddress.Location = new Point(153, 704);
            textBoxCaveBaseAddress.Name = "textBoxCaveBaseAddress";
            textBoxCaveBaseAddress.Size = new Size(197, 23);
            textBoxCaveBaseAddress.TabIndex = 16;
            textBoxCaveBaseAddress.Text = "[Main+R0+0x00000000]= ";
            // 
            // numericUpDownCaveLines
            // 
            numericUpDownCaveLines.Location = new Point(356, 704);
            numericUpDownCaveLines.Name = "numericUpDownCaveLines";
            numericUpDownCaveLines.Size = new Size(62, 23);
            numericUpDownCaveLines.TabIndex = 17;
            // 
            // btnGenerateCodeCave
            // 
            btnGenerateCodeCave.Location = new Point(16, 704);
            btnGenerateCodeCave.Name = "btnGenerateCodeCave";
            btnGenerateCodeCave.Size = new Size(131, 23);
            btnGenerateCodeCave.TabIndex = 18;
            btnGenerateCodeCave.Text = "Generate Code Cave";
            btnGenerateCodeCave.UseVisualStyleBackColor = true;
            btnGenerateCodeCave.Click += btnGenerateCodeCave_Click;
            // 
            // CheatToolGUI
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1476, 834);
            Controls.Add(btnGenerateCodeCave);
            Controls.Add(numericUpDownCaveLines);
            Controls.Add(textBoxCaveBaseAddress);
            Controls.Add(checkBoxShowRawOpcodes);
            Controls.Add(btnCopyOutput);
            Controls.Add(btnCopyInput);
            Controls.Add(btnSettings);
            Controls.Add(btnSaveOutput);
            Controls.Add(btnSaveInput);
            Controls.Add(btnLoadInput);
            Controls.Add(btnInstallPythonLibs);
            Controls.Add(statusStrip);
            Controls.Add(radioButtonArm64);
            Controls.Add(radioButtonArm32);
            Controls.Add(btnClearAll);
            Controls.Add(btnAssemble);
            Controls.Add(btnDisassemble);
            Controls.Add(textBoxOutput);
            Controls.Add(textBoxInput);
            Name = "CheatToolGUI";
            Text = "Form1";
            statusStrip.ResumeLayout(false);
            statusStrip.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)numericUpDownCaveLines).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private RichTextBox textBoxInput;
        private RichTextBox textBoxOutput;
        private Button btnDisassemble;
        private Button btnAssemble;
        private Button btnClearAll;
        private RadioButton radioButtonArm32;
        private RadioButton radioButtonArm64;
        private StatusStrip statusStrip;
        private ToolStripStatusLabel statusLabel;
        private Button btnInstallPythonLibs;
        private Button btnLoadInput;
        private Button btnSaveInput;
        private Button btnSaveOutput;
        private Button btnSettings;
        private Button btnCopyInput;
        private Button btnCopyOutput;
        private CheckBox checkBoxShowRawOpcodes;
        private TextBox textBoxCaveBaseAddress;
        private NumericUpDown numericUpDownCaveLines;
        private Button btnGenerateCodeCave;
    }
}
