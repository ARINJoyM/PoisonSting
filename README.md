# PoisonSting Tool

![PoisonSting](https://github.com/ARINJoyM/PoisonSting/assets/92751372/afc52d8a-db89-43f7-8743-8a86c58f9a6e)




## Description
PoisonSting is a tool designed for crafting and serving various types of payloads for offensive security purposes. It supports generating payloads in multiple languages such as JavaScript (JS), HTML Application (HTA), Windows Script File (WSF), Shell Command File (SCT), and XML Stylesheet Language (XSL). Additionally, it provides options for creating payloads from PowerShell (PS) and DotNetToJScript (JScript).

## Requirements
- Python 3.x
- colorama
- jsmin
- argparse

## Usage
To use the PoisonSting tool, run the `PoisonSting.py` script with the appropriate command-line arguments. Below are the available options:

- `--ScriptMaker`: Select the script maker: PowerShell (P) or DotnettoJscript (J).
- `--InputAssemblyfile`: Path to the assembly file to be processed.
- `--Language`: Payload language (js, hta, sct, wsf, xsl).
- `--IP`: Enter your IP to serve the payload.
- `--Port`: Enter the port to serve the payload.
- `--ReversePort`: Enter the port for the reverse shell (for PowerShell payloads).

For example:
### For DotnettoJScript based payloads
```
python PoisonSting.py --ScriptMaker DotnettoJS --InputAssemblyfile [path_to_assembly_file] --Language [payload_language] --IP [your_ip] --Port [port_number] 
```

###  For Powerhell based reverse Shell payloads
```
python poisonsting.py --ScriptMaker Powershell --InputAssemblyfile --Language [payload_language] --IP [your_ip] --Port [port_number] --ReversePort [reverse_shell_port]

```



## Features
- Generates payloads in multiple languages.
- Supports PowerShell and DotNetToJScript formats.
- Allows customization of payload parameters.
- Utilizes Chameleon to dynamically obfuscate reverse shell payloads from Nishang.
- Starts a web server to serve the crafted payloads.
- Supports crafting payloads and reverse shells in multiple formats: js, hta, sct, wsf, xsl.
- Utilizes Invoke-PowerShellTcp by Nishang for crafting reverse shells.
- Utilizes DotNetToJavaScript to create payloads from .NET DLL files.

## Disclaimer
This tool is intended for educational and research purposes only. The authors will not be responsible for any misuse or damage caused by using this tool.

## Additional Resources
- [Chameleon ](https://github.com/klezVirus/chameleon)
- [DotNetToScript ](https://github.com/tyranid/DotNetToJScript)
- [Nishang Reverse Shell Script](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)


