using System;
using System.IO;
using System.Windows.Forms;
using System.Drawing;

namespace CheatToolUI
{
    public partial class SettingsForm : Form
    {
        public AppSettings CurrentSettings { get; private set; }

        public SettingsForm(AppSettings initialSettings)
        {
            InitializeComponent();
            CurrentSettings = initialSettings;

            txtPythonPath.Text = CurrentSettings.PythonPath;
            if (CurrentSettings.DefaultArchitecture == "ARM32")
            {
                radioArm32.Checked = true;
            }
            else
            {
                radioArm64.Checked = true; // Default to ARM64 if not explicitly ARM32
            }

            checkBoxDarkMode.Checked = CurrentSettings.DarkModeEnabled;

            ApplyTheme(this, CurrentSettings.DarkModeEnabled);
        }

        private void ApplyTheme(Control parent, bool isDarkMode)
        {
            // Set form's background and foreground colors
            parent.BackColor = isDarkMode ? ThemeColors.Dark_Background : ThemeColors.Light_Background;
            parent.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;

            // Apply theme to all controls on the form recursively
            ApplyThemeToControls(parent.Controls, isDarkMode);
        }

        private void ApplyThemeToControls(Control.ControlCollection controls, bool isDarkMode)
        {
            foreach (Control control in controls)
            {
                // Apply general background/foreground for most controls
                control.BackColor = isDarkMode ? ThemeColors.Dark_ControlBackground : ThemeColors.Light_ControlBackground;
                control.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;

                // Specific handling for common control types
                if (control is Button button)
                {
                    button.BackColor = isDarkMode ? ThemeColors.Dark_ButtonBackground : ThemeColors.Light_ButtonBackground;
                    button.ForeColor = isDarkMode ? ThemeColors.Dark_ButtonForeground : ThemeColors.Light_ButtonForeground;
                    button.FlatStyle = FlatStyle.Flat;
                    button.FlatAppearance.BorderColor = isDarkMode ? ThemeColors.Dark_InputBorder : ThemeColors.Light_InputBorder;
                    button.FlatAppearance.BorderSize = 1;
                }
                else if (control is TextBox textBox)
                {
                    textBox.BackColor = isDarkMode ? ThemeColors.Dark_TextBoxBackground : ThemeColors.Light_TextBoxBackground;
                    textBox.ForeColor = isDarkMode ? ThemeColors.Dark_TextBoxForeground : ThemeColors.Light_TextBoxForeground;
                    textBox.BorderStyle = BorderStyle.FixedSingle;
                }
                else if (control is Label label)
                {
                    label.BackColor = isDarkMode ? ThemeColors.Dark_Background : ThemeColors.Light_Background;
                    label.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;
                }
                else if (control is RadioButton radioButton)
                {
                    radioButton.BackColor = isDarkMode ? ThemeColors.Dark_Background : ThemeColors.Light_Background;
                    radioButton.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;
                }
                else if (control is CheckBox checkBox)
                {
                    // For CheckBoxes, the background might need to be transparent or match parent
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
                    panel.BackColor = isDarkMode ? ThemeColors.Dark_Background : ThemeColors.Light_Background;
                    panel.ForeColor = isDarkMode ? ThemeColors.Dark_Foreground : ThemeColors.Light_Foreground;
                }

                if (control.HasChildren)
                {
                    ApplyThemeToControls(control.Controls, isDarkMode);
                }
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
            CurrentSettings.DarkModeEnabled = checkBoxDarkMode.Checked;

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