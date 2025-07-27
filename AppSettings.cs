using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CheatToolUI
{
    public class AppSettings
    {
        public string PythonPath { get; set; } = string.Empty;
        public string DefaultArchitecture { get; set; } = "ARM64";
        // New property for the "Show Raw Opcodes" checkbox state
        public bool ShowRawOpcodesInDisassembly { get; set; } = true; // Default to true (checked)

        [JsonIgnore]
        private static readonly string SettingsFileName = "settings.json";

        [JsonIgnore]
        private static string SettingsFilePath =>
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, SettingsFileName);

        public void Save()
        {
            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                string jsonString = JsonSerializer.Serialize(this, options);
                File.WriteAllText(SettingsFilePath, jsonString);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving settings: {ex.Message}");
            }
        }

        public static AppSettings Load()
        {
            if (File.Exists(SettingsFilePath))
            {
                try
                {
                    string jsonString = File.ReadAllText(SettingsFilePath);
                    AppSettings settings = JsonSerializer.Deserialize<AppSettings>(jsonString);
                    if (settings != null)
                    {
                        // Validate and set default for DefaultArchitecture
                        if (string.IsNullOrEmpty(settings.DefaultArchitecture) ||
                            (settings.DefaultArchitecture != "ARM64" && settings.DefaultArchitecture != "ARM32"))
                        {
                            settings.DefaultArchitecture = "ARM64";
                        }

                        // Ensure ShowRawOpcodesInDisassembly is initialized if it wasn't in the file
                        // The default value of 'true' on the property itself handles this for new loads.

                        return settings;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error loading settings, using defaults: {ex.Message}");
                }
            }
            return new AppSettings(); // Returns a new instance with default values if file doesn't exist or loading fails
        }
    }
}