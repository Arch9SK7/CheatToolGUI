using System.Drawing;

namespace CheatToolUI
{
    public static class ThemeColors
    {
        // Light Theme PS. I fucking hate that i have to misspell Colours just for the code to work...
        public static Color Light_Background = SystemColors.Control;
        public static Color Light_Foreground = SystemColors.ControlText;
        public static Color Light_ControlBackground = SystemColors.Control;
        public static Color Light_TextBoxBackground = SystemColors.Window;
        public static Color Light_TextBoxForeground = SystemColors.WindowText;
        public static Color Light_ButtonBackground = SystemColors.Control;
        public static Color Light_ButtonForeground = SystemColors.ControlText;
        public static Color Light_InputBorder = SystemColors.ControlDark;
        public static Color Light_HighlightBackground = SystemColors.Highlight; // Default selection colour
        public static Color Light_HighlightForeground = SystemColors.HighlightText; // Default selection text colour
        public static Color Light_StatusStripBackground = SystemColors.ControlLight;
        public static Color Light_MenuBackground = SystemColors.MenuBar;
        public static Color Light_MenuForeground = SystemColors.MenuText;
        public static Color Light_ErrorText = Color.Red;
        public static Color Light_WarningText = Color.OrangeRed;
        public static Color Light_SuccessText = Color.DarkGreen;
        public static Color Light_CheatHeader = Color.Blue;

        // Dark Theme
        public static Color Dark_Background = Color.FromArgb(45, 45, 48); // Visual Studio dark theme background
        public static Color Dark_Foreground = Color.Gainsboro;           // Light gray text
        public static Color Dark_ControlBackground = Color.FromArgb(60, 60, 65); // Slightly lighter dark for controls
        public static Color Dark_TextBoxBackground = Color.FromArgb(30, 30, 30); // Darker for input fields
        public static Color Dark_TextBoxForeground = Color.WhiteSmoke;
        public static Color Dark_ButtonBackground = Color.FromArgb(70, 70, 75);
        public static Color Dark_ButtonForeground = Color.WhiteSmoke;
        public static Color Dark_InputBorder = Color.FromArgb(90, 90, 95);
        public static Color Dark_HighlightBackground = Color.FromArgb(0, 122, 204); // VS Code blue accent for selection
        public static Color Dark_HighlightForeground = Color.White;
        public static Color Dark_StatusStripBackground = Color.FromArgb(35, 35, 35);
        public static Color Dark_MenuBackground = Color.FromArgb(40, 40, 40);
        public static Color Dark_MenuForeground = Color.WhiteSmoke;
        public static Color Dark_ErrorText = Color.LightCoral; // Softer red for dark mode
        public static Color Dark_WarningText = Color.Gold;     // Brighter orange for dark mode
        public static Color Dark_SuccessText = Color.LightGreen; // Brighter green for dark mode
        public static Color Dark_CheatHeader = Color.Cyan;       // Bright cyan for dark mode cheat headers
    }
}