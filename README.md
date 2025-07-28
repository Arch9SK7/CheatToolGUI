# CheatToolGUI
# Cheat Tool - ARM Assembly/Disassembly Utility

## Table of Contents
- [About](#about)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [How to Use (Assembly/Disassembly)](#how-to-use-(assembly/disassembly))
- [How to Use (Nintendo Switch Injection)](#how-to-use-(nintendo-switch-injection))
- [Settings](#settings)
- [File Operations](#file-operations)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Credits](#credits)

## About
The **Cheat Tool** is a user-friendly Windows Desktop application designed to simplify ARM (ARM64 & ARM32) assembly and disassembly operations, now with added capabilities for Nintendo Switch memory injection. Built with C# for the graphical user interface and powered by Python scripting utilizing the powerful keystone-engine and capstone libraries, this tool provides a straightforward way to convert assembly instructions to Atmosphere codes and vice-versa, making it ideal for reverse engineering, cheat code creation, or binary analysis.

## Features
- **ARM64 Assembly:** Convert ARM64 assembly instructions (e.g., MOV X0, #0x1) into their corresponding hexadecimal opcodes.

- **ARM64 & ARM32 Disassembly:** Convert raw hexadecimal opcodes into readable ARM64 or ARM32 assembly instructions.

- **Nintendo Switch ARM Assembly (Opcode 0) Injection:** Directly "poke" values into the Nintendo Switch's memory using Opcode 0: Store Static. This allows for direct memory modification and applying cheats/patches.

- **Support for 32-bit (DWORD) and 64-bit (QWORD) Writes:** The injection intelligently handles both 32-bit and 64-bit values for versatile memory modifications.

- **Integrated VM Opcode Information:** A new JSON-based system provides detailed information on each supported opcode, including its purpose, correct syntax, and practical example usage, directly within the application.

- **Integrated Python Library Management:** Easily install or update necessary Python libraries (keystone-engine and capstone) directly from within the application with a single click. Includes automatic pip installation/upgrade.

- **User Settings:** Configure the Python executable path (useful if Python isn't in your system's PATH) and set a default architecture (ARM64/ARM32) for new sessions.

- **File Operations:** Load assembly code or opcodes from text files and save assembled/disassembled output or your current input to files for later use.

- **Clipboard Integration:** Dedicated "Copy Input" and "Copy Output" buttons for quickly copying content to your clipboard.

- **Intuitive GUI:** A clean and easy-to-navigate interface.

- **Version Numbering:** The application's version is displayed in the window title for easy reference.

## Prerequisites
Before running the application, ensure you have the following installed on your system:

1. **Windows Operating System:** This application is designed for Windows.
2. **Python 3.x:** A Python 3 installation is required. The tool will attempt to auto-detect Python in your system's PATH. If it fails, you can manually specify the Python executable path in the application's settings.
3. **sys-botbase (for Switch Injection):** If you intend to use the Nintendo Switch injection features, your Switch console must have sys-botbase installed and running. A link to its releases is provided within the application.
4. **.NET Desktop Runtime:** The specific version depends on how the application's executable is built. If you download the "self-contained" release, you might not need to install this separately (It is built with 9 inside). Otherwise, ensure you have a recent .NET Desktop Runtime (e.g., .NET Framework 4.7.2+ or .NET 6/7/8 Desktop Runtime).

## Installation
1. **Download the Release:**
* Download the latest release package (`.zip` file) from the [GitHub Releases page)(https://github.com/Arch9SK7/CheatToolGUI/releases).
2. **Extract Files:**
* Unzip the downloaded package to a directory of your choice (e.g., `C:\CheatTool`).
* You should find `CheatToolUI.exe` and two Python script files as well as a few other files: `assemble_cheats.py`, `ARMdisassemble_cheats.py` & `CheatToolUI.dll.config`, `CheatToolUI.pdb`, `InstructionData.json`, `settings.json`, `vm_opcodes.json`.
3. **Place Files:**
* **Ensure `assemble_cheats.py`, `ARMdisassemble_cheats.py`, `CheatToolUI.dll.config`, `CheatToolUI.pdb`, `InstructionData.json`, `settings.json`and `vm_opcodes.json` are all located in the same directory.** The C# application relies on these Python scripts being present alongside it.
4. **Install Python Libraries:**
* Run `CheatToolUI.exe`.
* Click the **"Install/Update Python Libs"** button.
* This will automatically install or upgrade `pip` (if needed), followed by `keystone-engine` and `capstone`. You'll see the progress and results in the output text box. An active internet connection is required for this step.

## How to Use (Assembly/Disassembly)
1. **Input Text Box:**
* For **Assembly:** Enter your ARM64 assembly instructions, one instruction per line (e.g., `MOV X0, #0x1`).
* For **Disassembly:** Enter your hexadecimal opcodes, one opcode (or a sequence of opcodes) per line (e.g., `E0030091`) There will be better examples in photos.
2. **Architecture Selection:**
* Use the **ARM64** or **ARM32** buttons to select the target architecture for **disassembly** or **assembly**.
* *Note: Assembly currently processes ARM64 instructions only.*
3. **Assemble Button:** Click to convert your ARM64 assembly input into hexadecimal opcodes. The results will appear in the output text box.
4. **Disassemble Button:** Click to convert your hexadecimal opcode input into assembly instructions (ARM64 or ARM32, based on your selection).
5. **Clear All Button:** Clears both the input and output text boxes.
6. **Copy Buttons:**
* **Copy Input:** Copies the entire content of the input text box to your clipboard.
* **Copy Output:** Copies the entire content of the output text box to your clipboard.

## How to Use (Nintendo Switch Injection)
The CheatToolUI now includes a dedicated interface for directly injecting opcode 0 (Store Static) commands to your Nintendo Switch, allowing for real-time memory modification.

1. Boot game holding `L button` to detach all clients so sysbot can connect properly.

2. **Connect to Switch:**
* Enter your Nintendo Switch's IP address into the designated text box.
* Click the "Connect to Switch" button. The status light will turn green upon a successful connection.
* **Important:** Your Switch must have sys-botbase running for this connection to succeed. A link to sys-botbase releases is provided in the application for your convenience.

3. **Input Opcode 0 Data:**
* In the large input text box, enter your Opcode 0 commands. The syntax for an Opcode 0 line is generally:
040A0000 01B75D3C 2A1F03E1 (for 32-bit write)
080A0000 006C99A4 D65F03C0 52800020 (for 64-bit write)
Where:
**040A0000:** Contains the opcode type (0), bit_width (e.g., 4 for 32-bit, 8 for 64-bit), and memory access type (e.g., MainNso).
**01B75D3C:** The lower 32-bits of the target memory address.
**52800020:** The value to write (for 32-bit).
**D65F03C0:** The upper 32-bits of the value to write (for 64-bit).
* The application includes built-in information on Opcode 0 syntax and examples via its JSON configuration, guiding you on proper formatting.

4. **Send Data:**
* Once your opcode lines are entered, click the "Send Data" button. The application will parse each line and attempt to write the specified value to the given address on your connected Switch.

## Settings

Click the **"Settings"** button to open the application's configuration dialog:

- **Python Executable Path:**
*By default, the tool tries to find `python.exe` or `py.exe` in your system's PATH.
*If Python is not detected, or you wish to use a specific Python installation, you can click "Browse..." and manually select the full path to your desired `python.exe` or `py.exe` file.
- **Default Architecture:**
* Choose whether **ARM64** or **ARM32** should be pre-selected in the main window's architecture radio buttons when the application starts.

Your settings will be automatically saved to a `settings.json` file in the application's directory and loaded each time you open the tool.

## File Operations

The tool provides convenient buttons for managing your input and output as files:

- **Load Input:** Opens a file dialog, allowing you to select a `.txt` or `.cheat` file. Its content will be loaded directly into the input text box.
- **Save Output:** Opens a file dialog to save the content of the output text box to a `.txt` or `.cheat` file of your choice.
- **Save Input:* Opens a file dialog to save the current content of the input text box to a `.txt` or `.cheat` file.

## Troubleshooting

- **"Python executable not found"**:
1. Ensure Python 3.x is correctly installed on your system.
2. During Python installation, make sure you check the option to "Add Python to PATH".
3. Alternatively, use the **Settings** button in the application to manually specify the full path to your `python.exe` or `py.exe`.
**"Failed to install/upgrade pip"** or **"Library installation/update finished with errors"**:
1. Verify you have an active internet connection.
2. Check the output text box for specific error messages provided by `pip`. These often give clues about what went wrong.
3. In rare cases, if `pip` encounters permission issues, you might need to run the `CheatToolUI.exe` as an administrator (right-click -> "Run as administrator"), though `pip` generally tries to install packages to user-specific directories without elevated privileges.
- **"Python script not found"**:
* This means the application cannot find `assemble_cheats.py` or `ARMdisassemble_cheats.py`. Ensure these Python script files are located in the *same directory* as your `CheatToolUI.exe`.
- **Incorrect Assembly/Disassembly Output**:
* Carefully double-check your input syntax. ARM assembly can be particular. Refer to the documentation for [Keystone Engine](https://www.keystone-engine.org/docs/) (for assembly) and [Capstone Engine](https://www.capstone-engine.org/documentation.html) (for disassembly) for supported syntax.
* For disassembly, ensure you have selected the correct architecture (ARM64 or ARM32) using the given buttons.
- **"Not connected to the Switch. Please connect first." (for Injection)**:
* Ensure your Switch's IP address is correct.
* Verify that sys-botbase is running on your Nintendo Switch.
* Check your network connection between your PC and Switch.

## License
This project is licensed under the [MIT License](https://opensource.org/licenses/MIT) - see the [LICENSE](LICENSE) file for details.

## Credits
- **Keystone Engine:** Used for assembly. ([Website](https://www.keystone-engine.org/))

- **Capstone Engine:** Used for disassembly. ([Website](https://www.capstone-engine.org/))

- **sys-botbase:** Essential for Nintendo Switch memory injection features. ([GitHub Releases](https://github.com/olliz0r/sys-botbase/releases))

- **UI Program** Developed by [Arch9SK7]

- **Python scripts** by [Tomvita]

<img width="1475" height="743" alt="Screenshot 2025-07-26 143316" src="https://github.com/user-attachments/assets/f7baed7a-ee2b-41e1-8d41-acceb038cdb0" />
<img width="1472" height="740" alt="Screenshot 2025-07-26 143125" src="https://github.com/user-attachments/assets/0487c97f-def3-4c57-87f5-8c2fb15c0edd" />
<img width="1472" height="860" alt="Screenshot 2025-07-27 223852" src="https://github.com/user-attachments/assets/f5ba8895-9006-4ce0-bcbc-ea438aba1c75" />
<img width="1473" height="835" alt="Screenshot 2025-07-27 223754" src="https://github.com/user-attachments/assets/8ff07f3f-91d3-464b-95ed-409c9774c042" />
<img width="1474" height="835" alt="Screenshot 2025-07-27 222911" src="https://github.com/user-attachments/assets/17aa1707-dd92-4412-8f0c-8225a32b79fc" />
