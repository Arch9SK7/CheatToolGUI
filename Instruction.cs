using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace CheatToolUI
{
    public class Instruction
    {
        [JsonPropertyName("Name")]
        public string Name { get; set; }

        [JsonPropertyName("Architectures")]
        public List<string> Architectures { get; set; } = new List<string>();

        [JsonPropertyName("Syntax")]
        public List<string> Syntax { get; set; } = new List<string>();

        [JsonPropertyName("Description")]
        public string Description { get; set; }
    }
}