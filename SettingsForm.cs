using System;
using System.IO;
using System.Windows.Forms;

namespace CheatToolUI
{
    public partial class SettingsForm : Form
    {
        public AppSettings CurrentSettings { get; private set; }

        public SettingsForm(AppSettings initialSettings)
        {
            InitializeComponent();
            CurrentSettings = initialSettings; // Get a copy of the initial settings

            // Populate controls with initial settings
            txtPythonPath.Text = CurrentSettings.PythonPath;
            if (CurrentSettings.DefaultArchitecture == "ARM32")
            {
                radioArm32.Checked = true;
            }
            else
            {
                radioArm64.Checked = true; // Default to ARM64 if not explicitly ARM32
            }
        }

        private void btnBrowsePythonPath_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "Python Executable (python.exe;py.exe)|python.exe;py.exe|All Files (*.*)|*.*";
                openFileDialog.Title = "Select Python Executable";
                openFileDialog.CheckFileExists = true;
                openFileDialog.CheckPathExists = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    txtPythonPath.Text = openFileDialog.FileName;
                }
            }
        }

        private void btnOK_Click(object sender, EventArgs e)
        {
            // Save changes back to the CurrentSettings object
            CurrentSettings.PythonPath = txtPythonPath.Text.Trim();
            CurrentSettings.DefaultArchitecture = radioArm32.Checked ? "ARM32" : "ARM64";

            this.DialogResult = DialogResult.OK; // Set dialog result to OK
            this.Close(); // Close the form
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.Cancel; // Set dialog result to Cancel
            this.Close(); // Close the form
        }
    }
}