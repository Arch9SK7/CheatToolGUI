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
            statusStrip = new StatusStrip();
            statusLabel = new ToolStripStatusLabel();
            tabControlMain = new TabControl();
            tabPageMain = new TabPage();
            btnRelocate = new Button();
            btnGenerateCodeCave = new Button();
            numericUpDownCaveLines = new NumericUpDown();
            textBoxCaveBaseAddress = new TextBox();
            checkBoxShowRawOpcodes = new CheckBox();
            btnCopyOutput = new Button();
            btnCopyInput = new Button();
            btnSettings = new Button();
            btnSaveOutput = new Button();
            btnSaveInput = new Button();
            btnLoadInput = new Button();
            btnInstallPythonLibs = new Button();
            radioButtonArm64 = new RadioButton();
            radioButtonArm32 = new RadioButton();
            btnClearAll = new Button();
            btnAssemble = new Button();
            btnDisassemble = new Button();
            textBoxOutput = new RichTextBox();
            textBoxInput = new RichTextBox();
            tabPageInstructionRef = new TabPage();
            lblVMOpCodes = new Label();
            richTextBoxOpDescription = new RichTextBox();
            listBoxVmOpcodes = new ListBox();
            richTextBoxInstructionDetails = new RichTextBox();
            lblInstructionDetails = new Label();
            listBoxInstructions = new ListBox();
            textBoxSearchInstruction = new TextBox();
            lblSearchInstruction = new Label();
            tabPageMemoryInjection = new TabPage();
            btnSwitchInjection = new Button();
            lblTestWarning = new Label();
            statusStrip.SuspendLayout();
            tabControlMain.SuspendLayout();
            tabPageMain.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)numericUpDownCaveLines).BeginInit();
            tabPageInstructionRef.SuspendLayout();
            tabPageMemoryInjection.SuspendLayout();
            SuspendLayout();
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
            // tabControlMain
            // 
            tabControlMain.Controls.Add(tabPageMain);
            tabControlMain.Controls.Add(tabPageInstructionRef);
            tabControlMain.Controls.Add(tabPageMemoryInjection);
            tabControlMain.Location = new Point(0, 1);
            tabControlMain.Name = "tabControlMain";
            tabControlMain.SelectedIndex = 0;
            tabControlMain.Size = new Size(1476, 808);
            tabControlMain.TabIndex = 19;
            // 
            // tabPageMain
            // 
            tabPageMain.Controls.Add(btnRelocate);
            tabPageMain.Controls.Add(btnGenerateCodeCave);
            tabPageMain.Controls.Add(numericUpDownCaveLines);
            tabPageMain.Controls.Add(textBoxCaveBaseAddress);
            tabPageMain.Controls.Add(checkBoxShowRawOpcodes);
            tabPageMain.Controls.Add(btnCopyOutput);
            tabPageMain.Controls.Add(btnCopyInput);
            tabPageMain.Controls.Add(btnSettings);
            tabPageMain.Controls.Add(btnSaveOutput);
            tabPageMain.Controls.Add(btnSaveInput);
            tabPageMain.Controls.Add(btnLoadInput);
            tabPageMain.Controls.Add(btnInstallPythonLibs);
            tabPageMain.Controls.Add(radioButtonArm64);
            tabPageMain.Controls.Add(radioButtonArm32);
            tabPageMain.Controls.Add(btnClearAll);
            tabPageMain.Controls.Add(btnAssemble);
            tabPageMain.Controls.Add(btnDisassemble);
            tabPageMain.Controls.Add(textBoxOutput);
            tabPageMain.Controls.Add(textBoxInput);
            tabPageMain.Location = new Point(4, 24);
            tabPageMain.Name = "tabPageMain";
            tabPageMain.Padding = new Padding(3);
            tabPageMain.Size = new Size(1468, 780);
            tabPageMain.TabIndex = 0;
            tabPageMain.Text = "Assemble/Disassemble";
            tabPageMain.UseVisualStyleBackColor = true;
            tabPageMain.Click += tabPageMain_Click;
            // 
            // btnRelocate
            // 
            btnRelocate.Enabled = false;
            btnRelocate.Location = new Point(488, 725);
            btnRelocate.Name = "btnRelocate";
            btnRelocate.Size = new Size(107, 23);
            btnRelocate.TabIndex = 37;
            btnRelocate.Text = "Relocate Caves";
            btnRelocate.UseVisualStyleBackColor = true;
            btnRelocate.Click += btnRelocate_Click;
            // 
            // btnGenerateCodeCave
            // 
            btnGenerateCodeCave.Location = new Point(12, 725);
            btnGenerateCodeCave.Name = "btnGenerateCodeCave";
            btnGenerateCodeCave.Size = new Size(131, 23);
            btnGenerateCodeCave.TabIndex = 36;
            btnGenerateCodeCave.Text = "Generate Code Cave";
            btnGenerateCodeCave.UseVisualStyleBackColor = true;
            btnGenerateCodeCave.Click += btnGenerateCodeCave_Click;
            // 
            // numericUpDownCaveLines
            // 
            numericUpDownCaveLines.Location = new Point(352, 725);
            numericUpDownCaveLines.Name = "numericUpDownCaveLines";
            numericUpDownCaveLines.Size = new Size(62, 23);
            numericUpDownCaveLines.TabIndex = 35;
            // 
            // textBoxCaveBaseAddress
            // 
            textBoxCaveBaseAddress.Location = new Point(149, 725);
            textBoxCaveBaseAddress.Name = "textBoxCaveBaseAddress";
            textBoxCaveBaseAddress.Size = new Size(197, 23);
            textBoxCaveBaseAddress.TabIndex = 34;
            textBoxCaveBaseAddress.Text = "[Main+R0+0x00000000]= ";
            // 
            // checkBoxShowRawOpcodes
            // 
            checkBoxShowRawOpcodes.AutoSize = true;
            checkBoxShowRawOpcodes.Checked = true;
            checkBoxShowRawOpcodes.CheckState = CheckState.Checked;
            checkBoxShowRawOpcodes.Location = new Point(646, 87);
            checkBoxShowRawOpcodes.Name = "checkBoxShowRawOpcodes";
            checkBoxShowRawOpcodes.Size = new Size(80, 19);
            checkBoxShowRawOpcodes.TabIndex = 33;
            checkBoxShowRawOpcodes.Text = "Show Raw";
            checkBoxShowRawOpcodes.UseVisualStyleBackColor = true;
            checkBoxShowRawOpcodes.Click += checkBoxShowRawOpcodes_CheckedChanged;
            // 
            // btnCopyOutput
            // 
            btnCopyOutput.Location = new Point(925, 83);
            btnCopyOutput.Name = "btnCopyOutput";
            btnCopyOutput.Size = new Size(89, 23);
            btnCopyOutput.TabIndex = 32;
            btnCopyOutput.Text = "Copy Output";
            btnCopyOutput.UseVisualStyleBackColor = true;
            btnCopyOutput.Click += btnCopyOutput_Click;
            // 
            // btnCopyInput
            // 
            btnCopyInput.Location = new Point(833, 83);
            btnCopyInput.Name = "btnCopyInput";
            btnCopyInput.Size = new Size(75, 23);
            btnCopyInput.TabIndex = 31;
            btnCopyInput.Text = "Copy Input";
            btnCopyInput.UseVisualStyleBackColor = true;
            btnCopyInput.Click += btnCopyInput_Click;
            // 
            // btnSettings
            // 
            btnSettings.Location = new Point(96, 74);
            btnSettings.Name = "btnSettings";
            btnSettings.Size = new Size(160, 40);
            btnSettings.TabIndex = 30;
            btnSettings.Text = "Settings";
            btnSettings.UseVisualStyleBackColor = true;
            btnSettings.Click += btnSettings_Click;
            // 
            // btnSaveOutput
            // 
            btnSaveOutput.Location = new Point(1376, 33);
            btnSaveOutput.Name = "btnSaveOutput";
            btnSaveOutput.Size = new Size(84, 23);
            btnSaveOutput.TabIndex = 29;
            btnSaveOutput.Text = "Save Output";
            btnSaveOutput.UseVisualStyleBackColor = true;
            btnSaveOutput.Click += btnSaveOutput_Click;
            // 
            // btnSaveInput
            // 
            btnSaveInput.Location = new Point(8, 62);
            btnSaveInput.Name = "btnSaveInput";
            btnSaveInput.Size = new Size(75, 23);
            btnSaveInput.TabIndex = 28;
            btnSaveInput.Text = "Save Input";
            btnSaveInput.UseVisualStyleBackColor = true;
            btnSaveInput.Click += btnSaveInput_Click;
            // 
            // btnLoadInput
            // 
            btnLoadInput.Location = new Point(8, 33);
            btnLoadInput.Name = "btnLoadInput";
            btnLoadInput.Size = new Size(75, 23);
            btnLoadInput.TabIndex = 27;
            btnLoadInput.Text = "Load Input";
            btnLoadInput.UseVisualStyleBackColor = true;
            btnLoadInput.Click += btnLoadInput_Click;
            // 
            // btnInstallPythonLibs
            // 
            btnInstallPythonLibs.Location = new Point(1300, 74);
            btnInstallPythonLibs.Name = "btnInstallPythonLibs";
            btnInstallPythonLibs.RightToLeft = RightToLeft.No;
            btnInstallPythonLibs.Size = new Size(160, 40);
            btnInstallPythonLibs.TabIndex = 26;
            btnInstallPythonLibs.Text = "Install/Update Python Libs";
            btnInstallPythonLibs.UseVisualStyleBackColor = true;
            btnInstallPythonLibs.Click += btnInstallPythonLibs_Click;
            // 
            // radioButtonArm64
            // 
            radioButtonArm64.AutoSize = true;
            radioButtonArm64.Location = new Point(553, 95);
            radioButtonArm64.Name = "radioButtonArm64";
            radioButtonArm64.Size = new Size(63, 19);
            radioButtonArm64.TabIndex = 25;
            radioButtonArm64.TabStop = true;
            radioButtonArm64.Text = "ARM64";
            radioButtonArm64.UseVisualStyleBackColor = true;
            // 
            // radioButtonArm32
            // 
            radioButtonArm32.AutoSize = true;
            radioButtonArm32.Location = new Point(553, 74);
            radioButtonArm32.Name = "radioButtonArm32";
            radioButtonArm32.Size = new Size(63, 19);
            radioButtonArm32.TabIndex = 24;
            radioButtonArm32.TabStop = true;
            radioButtonArm32.Text = "ARM32";
            radioButtonArm32.UseVisualStyleBackColor = true;
            // 
            // btnClearAll
            // 
            btnClearAll.Location = new Point(739, 83);
            btnClearAll.Name = "btnClearAll";
            btnClearAll.Size = new Size(75, 23);
            btnClearAll.TabIndex = 23;
            btnClearAll.Text = "Clear All";
            btnClearAll.UseVisualStyleBackColor = true;
            btnClearAll.Click += btnClearAll_Click;
            // 
            // btnAssemble
            // 
            btnAssemble.Location = new Point(1083, 74);
            btnAssemble.Name = "btnAssemble";
            btnAssemble.Size = new Size(160, 40);
            btnAssemble.TabIndex = 22;
            btnAssemble.Text = "Assemble";
            btnAssemble.UseVisualStyleBackColor = true;
            btnAssemble.Click += btnAssemble_Click;
            // 
            // btnDisassemble
            // 
            btnDisassemble.Location = new Point(307, 74);
            btnDisassemble.Name = "btnDisassemble";
            btnDisassemble.Size = new Size(160, 40);
            btnDisassemble.TabIndex = 21;
            btnDisassemble.Text = "Disassemble";
            btnDisassemble.UseVisualStyleBackColor = true;
            btnDisassemble.Click += btnDisassemble_Click;
            // 
            // textBoxOutput
            // 
            textBoxOutput.Location = new Point(626, 120);
            textBoxOutput.Name = "textBoxOutput";
            textBoxOutput.ReadOnly = true;
            textBoxOutput.Size = new Size(834, 587);
            textBoxOutput.TabIndex = 20;
            textBoxOutput.Text = "";
            textBoxOutput.WordWrap = false;
            // 
            // textBoxInput
            // 
            textBoxInput.Location = new Point(12, 120);
            textBoxInput.Name = "textBoxInput";
            textBoxInput.ScrollBars = RichTextBoxScrollBars.Vertical;
            textBoxInput.Size = new Size(608, 587);
            textBoxInput.TabIndex = 19;
            textBoxInput.Text = "";
            textBoxInput.Click += TextBoxInput_TextChanged;
            // 
            // tabPageInstructionRef
            // 
            tabPageInstructionRef.Controls.Add(lblVMOpCodes);
            tabPageInstructionRef.Controls.Add(richTextBoxOpDescription);
            tabPageInstructionRef.Controls.Add(listBoxVmOpcodes);
            tabPageInstructionRef.Controls.Add(richTextBoxInstructionDetails);
            tabPageInstructionRef.Controls.Add(lblInstructionDetails);
            tabPageInstructionRef.Controls.Add(listBoxInstructions);
            tabPageInstructionRef.Controls.Add(textBoxSearchInstruction);
            tabPageInstructionRef.Controls.Add(lblSearchInstruction);
            tabPageInstructionRef.Location = new Point(4, 24);
            tabPageInstructionRef.Name = "tabPageInstructionRef";
            tabPageInstructionRef.Padding = new Padding(3);
            tabPageInstructionRef.Size = new Size(1468, 780);
            tabPageInstructionRef.TabIndex = 1;
            tabPageInstructionRef.Text = "Instruction Reference";
            tabPageInstructionRef.UseVisualStyleBackColor = true;
            tabPageInstructionRef.Click += tabPageInstructionRef_Click;
            // 
            // lblVMOpCodes
            // 
            lblVMOpCodes.AutoSize = true;
            lblVMOpCodes.Location = new Point(1008, 84);
            lblVMOpCodes.Name = "lblVMOpCodes";
            lblVMOpCodes.Size = new Size(122, 15);
            lblVMOpCodes.TabIndex = 7;
            lblVMOpCodes.Text = "VM Op Codes/Syntax:";
            // 
            // richTextBoxOpDescription
            // 
            richTextBoxOpDescription.Location = new Point(868, 105);
            richTextBoxOpDescription.Name = "richTextBoxOpDescription";
            richTextBoxOpDescription.ReadOnly = true;
            richTextBoxOpDescription.Size = new Size(393, 454);
            richTextBoxOpDescription.TabIndex = 6;
            richTextBoxOpDescription.Text = "";
            // 
            // listBoxVmOpcodes
            // 
            listBoxVmOpcodes.FormattingEnabled = true;
            listBoxVmOpcodes.Location = new Point(737, 105);
            listBoxVmOpcodes.Name = "listBoxVmOpcodes";
            listBoxVmOpcodes.Size = new Size(125, 454);
            listBoxVmOpcodes.TabIndex = 5;
            // 
            // richTextBoxInstructionDetails
            // 
            richTextBoxInstructionDetails.Location = new Point(251, 105);
            richTextBoxInstructionDetails.Name = "richTextBoxInstructionDetails";
            richTextBoxInstructionDetails.ReadOnly = true;
            richTextBoxInstructionDetails.Size = new Size(478, 454);
            richTextBoxInstructionDetails.TabIndex = 4;
            richTextBoxInstructionDetails.Text = "";
            // 
            // lblInstructionDetails
            // 
            lblInstructionDetails.AutoSize = true;
            lblInstructionDetails.Location = new Point(461, 86);
            lblInstructionDetails.Name = "lblInstructionDetails";
            lblInstructionDetails.Size = new Size(45, 15);
            lblInstructionDetails.TabIndex = 3;
            lblInstructionDetails.Text = "Details:";
            // 
            // listBoxInstructions
            // 
            listBoxInstructions.FormattingEnabled = true;
            listBoxInstructions.Location = new Point(112, 105);
            listBoxInstructions.Name = "listBoxInstructions";
            listBoxInstructions.Size = new Size(131, 454);
            listBoxInstructions.TabIndex = 2;
            // 
            // textBoxSearchInstruction
            // 
            textBoxSearchInstruction.Location = new Point(251, 50);
            textBoxSearchInstruction.Name = "textBoxSearchInstruction";
            textBoxSearchInstruction.Size = new Size(228, 23);
            textBoxSearchInstruction.TabIndex = 1;
            // 
            // lblSearchInstruction
            // 
            lblSearchInstruction.AutoSize = true;
            lblSearchInstruction.Location = new Point(140, 53);
            lblSearchInstruction.Name = "lblSearchInstruction";
            lblSearchInstruction.Size = new Size(105, 15);
            lblSearchInstruction.TabIndex = 0;
            lblSearchInstruction.Text = "Search Instruction:";
            // 
            // tabPageMemoryInjection
            // 
            tabPageMemoryInjection.Controls.Add(btnSwitchInjection);
            tabPageMemoryInjection.Controls.Add(lblTestWarning);
            tabPageMemoryInjection.Location = new Point(4, 24);
            tabPageMemoryInjection.Name = "tabPageMemoryInjection";
            tabPageMemoryInjection.Size = new Size(1468, 780);
            tabPageMemoryInjection.TabIndex = 2;
            tabPageMemoryInjection.Text = "Switch Mem Injection";
            tabPageMemoryInjection.UseVisualStyleBackColor = true;
            // 
            // btnSwitchInjection
            // 
            btnSwitchInjection.Location = new Point(591, 166);
            btnSwitchInjection.Name = "btnSwitchInjection";
            btnSwitchInjection.Size = new Size(152, 81);
            btnSwitchInjection.TabIndex = 1;
            btnSwitchInjection.Text = "Switch Injection";
            btnSwitchInjection.UseVisualStyleBackColor = true;
            btnSwitchInjection.Click += btnSwitchInjection_Click;
            // 
            // lblTestWarning
            // 
            lblTestWarning.AutoSize = true;
            lblTestWarning.Location = new Point(499, 130);
            lblTestWarning.Name = "lblTestWarning";
            lblTestWarning.Size = new Size(352, 15);
            lblTestWarning.TabIndex = 0;
            lblTestWarning.Text = "THIS IS FOR TESTING. YOU NEED SYSBOTBASE ON YOUR SWITCH";
            // 
            // CheatToolGUI
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1476, 834);
            Controls.Add(tabControlMain);
            Controls.Add(statusStrip);
            Name = "CheatToolGUI";
            Text = "Form1";
            statusStrip.ResumeLayout(false);
            statusStrip.PerformLayout();
            tabControlMain.ResumeLayout(false);
            tabPageMain.ResumeLayout(false);
            tabPageMain.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)numericUpDownCaveLines).EndInit();
            tabPageInstructionRef.ResumeLayout(false);
            tabPageInstructionRef.PerformLayout();
            tabPageMemoryInjection.ResumeLayout(false);
            tabPageMemoryInjection.PerformLayout();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion
        private StatusStrip statusStrip;
        private ToolStripStatusLabel statusLabel;
        private TabControl tabControlMain;
        private TabPage tabPageMain;
        private TabPage tabPageInstructionRef;
        private Button btnGenerateCodeCave;
        private NumericUpDown numericUpDownCaveLines;
        private TextBox textBoxCaveBaseAddress;
        private CheckBox checkBoxShowRawOpcodes;
        private Button btnCopyOutput;
        private Button btnCopyInput;
        private Button btnSettings;
        private Button btnSaveOutput;
        private Button btnSaveInput;
        private Button btnLoadInput;
        private Button btnInstallPythonLibs;
        private RadioButton radioButtonArm64;
        private RadioButton radioButtonArm32;
        private Button btnClearAll;
        private Button btnAssemble;
        private Button btnDisassemble;
        private RichTextBox textBoxOutput;
        private RichTextBox textBoxInput;
        private Label lblSearchInstruction;
        private RichTextBox richTextBoxInstructionDetails;
        private Label lblInstructionDetails;
        private ListBox listBoxInstructions;
        private TextBox textBoxSearchInstruction;
        private TabPage tabPageMemoryInjection;
        private RichTextBox richTextBoxOpDescription;
        private ListBox listBoxVmOpcodes;
        private Label lblVMOpCodes;
        private Button btnSwitchInjection;
        private Label lblTestWarning;
        private Button btnRelocate;
    }
}
