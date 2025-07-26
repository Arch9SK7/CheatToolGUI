namespace CheatToolUI
{
    partial class SettingsForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
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
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            lblPythonPath = new Label();
            txtPythonPath = new TextBox();
            btnBrowsePythonPath = new Button();
            grpDefaultArchitecture = new GroupBox();
            radioArm32 = new RadioButton();
            radioArm64 = new RadioButton();
            btnCancel = new Button();
            btnOK = new Button();
            grpDefaultArchitecture.SuspendLayout();
            SuspendLayout();
            // 
            // lblPythonPath
            // 
            lblPythonPath.AutoSize = true;
            lblPythonPath.Location = new Point(133, 22);
            lblPythonPath.Name = "lblPythonPath";
            lblPythonPath.Size = new Size(134, 15);
            lblPythonPath.TabIndex = 0;
            lblPythonPath.Text = "Python Executable Path:";
            // 
            // txtPythonPath
            // 
            txtPythonPath.Location = new Point(129, 40);
            txtPythonPath.Name = "txtPythonPath";
            txtPythonPath.Size = new Size(339, 23);
            txtPythonPath.TabIndex = 1;
            // 
            // btnBrowsePythonPath
            // 
            btnBrowsePythonPath.Location = new Point(45, 39);
            btnBrowsePythonPath.Name = "btnBrowsePythonPath";
            btnBrowsePythonPath.Size = new Size(75, 23);
            btnBrowsePythonPath.TabIndex = 2;
            btnBrowsePythonPath.Text = "Browse...";
            btnBrowsePythonPath.UseVisualStyleBackColor = true;
            btnBrowsePythonPath.Click += btnBrowsePythonPath_Click;
            // 
            // grpDefaultArchitecture
            // 
            grpDefaultArchitecture.Controls.Add(radioArm32);
            grpDefaultArchitecture.Controls.Add(radioArm64);
            grpDefaultArchitecture.Location = new Point(132, 69);
            grpDefaultArchitecture.Name = "grpDefaultArchitecture";
            grpDefaultArchitecture.Size = new Size(200, 100);
            grpDefaultArchitecture.TabIndex = 3;
            grpDefaultArchitecture.TabStop = false;
            grpDefaultArchitecture.Text = "Default Architecture";
            // 
            // radioArm32
            // 
            radioArm32.AutoSize = true;
            radioArm32.Location = new Point(30, 57);
            radioArm32.Name = "radioArm32";
            radioArm32.Size = new Size(63, 19);
            radioArm32.TabIndex = 1;
            radioArm32.TabStop = true;
            radioArm32.Text = "ARM32";
            radioArm32.UseVisualStyleBackColor = true;
            // 
            // radioArm64
            // 
            radioArm64.AutoSize = true;
            radioArm64.Location = new Point(30, 32);
            radioArm64.Name = "radioArm64";
            radioArm64.Size = new Size(63, 19);
            radioArm64.TabIndex = 0;
            radioArm64.TabStop = true;
            radioArm64.Text = "ARM64";
            radioArm64.UseVisualStyleBackColor = true;
            // 
            // btnCancel
            // 
            btnCancel.Location = new Point(125, 271);
            btnCancel.Name = "btnCancel";
            btnCancel.Size = new Size(100, 50);
            btnCancel.TabIndex = 4;
            btnCancel.Text = "Cancel";
            btnCancel.UseVisualStyleBackColor = true;
            btnCancel.Click += btnCancel_Click;
            // 
            // btnOK
            // 
            btnOK.Location = new Point(368, 271);
            btnOK.Name = "btnOK";
            btnOK.Size = new Size(100, 50);
            btnOK.TabIndex = 5;
            btnOK.Text = "OK";
            btnOK.UseVisualStyleBackColor = true;
            btnOK.Click += btnOK_Click;
            // 
            // SettingsForm
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(575, 333);
            Controls.Add(btnOK);
            Controls.Add(btnCancel);
            Controls.Add(grpDefaultArchitecture);
            Controls.Add(btnBrowsePythonPath);
            Controls.Add(txtPythonPath);
            Controls.Add(lblPythonPath);
            Name = "SettingsForm";
            Text = "SettingsForm";
            grpDefaultArchitecture.ResumeLayout(false);
            grpDefaultArchitecture.PerformLayout();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Label lblPythonPath;
        private TextBox txtPythonPath;
        private Button btnBrowsePythonPath;
        private GroupBox grpDefaultArchitecture;
        private RadioButton radioArm32;
        private RadioButton radioArm64;
        private Button btnCancel;
        private Button btnOK;
    }
}