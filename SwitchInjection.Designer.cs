namespace CheatToolUI
{
    partial class SwitchInjection
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
            lblSwitchIP = new Label();
            textBoxSwitchIPInput = new TextBox();
            btnConnect = new Button();
            richTextBoxCodeInput = new RichTextBox();
            lblPlaceCode = new Label();
            btnSendData = new Button();
            pbStatusLight = new PictureBox();
            label1 = new Label();
            linkLabel1 = new LinkLabel();
            ((System.ComponentModel.ISupportInitialize)pbStatusLight).BeginInit();
            SuspendLayout();
            // 
            // lblSwitchIP
            // 
            lblSwitchIP.AutoSize = true;
            lblSwitchIP.Location = new Point(12, 9);
            lblSwitchIP.Name = "lblSwitchIP";
            lblSwitchIP.Size = new Size(58, 15);
            lblSwitchIP.TabIndex = 0;
            lblSwitchIP.Text = "Switch IP:";
            // 
            // textBoxSwitchIPInput
            // 
            textBoxSwitchIPInput.Location = new Point(76, 6);
            textBoxSwitchIPInput.Name = "textBoxSwitchIPInput";
            textBoxSwitchIPInput.Size = new Size(100, 23);
            textBoxSwitchIPInput.TabIndex = 1;
            // 
            // btnConnect
            // 
            btnConnect.Location = new Point(182, 6);
            btnConnect.Name = "btnConnect";
            btnConnect.Size = new Size(22, 23);
            btnConnect.TabIndex = 2;
            btnConnect.Text = "📶";
            btnConnect.UseVisualStyleBackColor = true;
            btnConnect.Click += btnConnect_Click;
            // 
            // richTextBoxCodeInput
            // 
            richTextBoxCodeInput.Location = new Point(76, 53);
            richTextBoxCodeInput.Name = "richTextBoxCodeInput";
            richTextBoxCodeInput.Size = new Size(297, 385);
            richTextBoxCodeInput.TabIndex = 3;
            richTextBoxCodeInput.Text = "";
            // 
            // lblPlaceCode
            // 
            lblPlaceCode.AutoSize = true;
            lblPlaceCode.Location = new Point(163, 35);
            lblPlaceCode.Name = "lblPlaceCode";
            lblPlaceCode.Size = new Size(126, 15);
            lblPlaceCode.TabIndex = 4;
            lblPlaceCode.Text = "Place ASM cheats here";
            // 
            // btnSendData
            // 
            btnSendData.Location = new Point(379, 233);
            btnSendData.Name = "btnSendData";
            btnSendData.Size = new Size(94, 23);
            btnSendData.TabIndex = 5;
            btnSendData.Text = "Send Data";
            btnSendData.UseVisualStyleBackColor = true;
            btnSendData.Click += btnSendData_Click;
            // 
            // pbStatusLight
            // 
            pbStatusLight.Location = new Point(213, 2);
            pbStatusLight.Name = "pbStatusLight";
            pbStatusLight.Size = new Size(27, 29);
            pbStatusLight.TabIndex = 6;
            pbStatusLight.TabStop = false;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(490, 33);
            label1.Name = "label1";
            label1.Size = new Size(224, 15);
            label1.TabIndex = 7;
            label1.Text = "HOLD L booting your game to get results";
            // 
            // linkLabel1
            // 
            linkLabel1.AutoSize = true;
            linkLabel1.Location = new Point(490, 53);
            linkLabel1.Name = "linkLabel1";
            linkLabel1.Size = new Size(126, 15);
            linkLabel1.TabIndex = 8;
            linkLabel1.TabStop = true;
            linkLabel1.Text = "Grab Sys bot base here";
            linkLabel1.LinkClicked += linkLabel1_LinkClicked;
            // 
            // SwitchInjection
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(800, 450);
            Controls.Add(linkLabel1);
            Controls.Add(label1);
            Controls.Add(pbStatusLight);
            Controls.Add(btnSendData);
            Controls.Add(lblPlaceCode);
            Controls.Add(richTextBoxCodeInput);
            Controls.Add(btnConnect);
            Controls.Add(textBoxSwitchIPInput);
            Controls.Add(lblSwitchIP);
            Name = "SwitchInjection";
            Text = "SwitchInjection";
            ((System.ComponentModel.ISupportInitialize)pbStatusLight).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Label lblSwitchIP;
        private TextBox textBoxSwitchIPInput;
        private Button btnConnect;
        private RichTextBox richTextBoxCodeInput;
        private Label lblPlaceCode;
        private Button btnSendData;
        private PictureBox pbStatusLight;
        private Label label1;
        private LinkLabel linkLabel1;
    }
}