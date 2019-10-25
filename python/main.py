
#!/usr/bin/env python3

"""
ZetCode Tkinter tutorial

In this example, we use the pack
manager to create a review example.

Author: Jan Bodnar
Last modified: April 2019
Website: www.zetcode.com
"""

from tkinter import Tk, Text, TOP, BOTH, X, N, LEFT
from tkinter.ttk import Frame, Label, Entry, Button
import tkinter as tk
from tkinter import filedialog
import getpass  # for username
import hashlib

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

str = hashlib.sha3_512(b"hi")

print(str.hexdigest())


dk = hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 100000)
print(dk.hex())



# hashlib.scrypt()



def to_seconds(timestr):
    seconds = 0
    for part in timestr.split(':'):
        seconds = seconds * 60 + int(part)
    return seconds


def seconds_to_hhmmss(seconds):
    r = seconds
    timestamp = ""

    hr = int(r / 3600)
    r = r % 3600
    print(r)
    print(hr)

    minute = int(r / 60)
    r = r % 60
    print(r)
    print(minute)

    return "{:2}:{:2}:{:2}".format(hr, minute, r)


def browse_file():
    print("button liecked : browse_file")


    return 0


class CrypterWindow(Frame):

    def __init__(self):
        super().__init__()

        self.algorithm_select = None
        self.entry1 = None
        self.password_entry = None
        self.selected_algorithm = tk.StringVar()
        self.password_txt = tk.StringVar()
        self.filename = tk.StringVar()
        self.Encryption_Algorithms = ["md5", "sha"]
        self.txt = None
        self.initUI()

    def initUI(self):
        self.master.title("Crypter")
        self.pack(fill=BOTH, expand=True)

        # Add timer frame
        frame1 = Frame(self)
        frame1.pack(fill=X)

        lbl1 = Label(frame1, text="File ", width=10)
        lbl1.pack(side=LEFT, padx=5, pady=5)

        self.entry1 = Entry(frame1, textvariable=self.filename)
        self.entry1.pack(side=LEFT, padx=5, pady=5)

        btn_browse = tk.Button(frame1, text='Browse', fg='red', command=self.browse_file)
        btn_browse.pack(padx=5, pady=5, side=tk.LEFT)

        # monitor frame
        frame2 = Frame(self)
        frame2.pack(fill=X)

        password = Label(frame2, text="Password", width=10)
        password.pack(side=LEFT, padx=5, pady=5)

        self.password_entry = Entry(frame2, textvariable=self.password_txt)
        self.password_entry.pack(side=LEFT, padx=5, pady=5, fill=X)

        # the constructor syntax is:
        # OptionMenu(master, variable, *values)

        self.algorithm_select = tk.ttk.Combobox(frame2, width=10, textvariable=self.selected_algorithm)
        self.selected_algorithm.set(self.Encryption_Algorithms[1])  # default value
        self.algorithm_select['values'] = tuple(self.Encryption_Algorithms)
        # combo.grid(column=1, row=0)
        self.algorithm_select.pack(padx=5, pady=5, side=tk.LEFT)

        btn_encrypt = tk.Button(frame2, text='Encrypt', fg='red', command=self.encrypt)
        btn_encrypt.pack(padx=0, pady=5, side=tk.LEFT)

        btn_decrypt = tk.Button(frame2, text='Decrypt', fg='red', command=self.decrypt)
        btn_decrypt.pack(padx=0, pady=5, side=tk.LEFT)

        frame4 = Frame(self)
        frame4.pack(fill=BOTH, expand=True)
        # lbl3 = Label(frame4, text="Output", width=6)
        # lbl3.pack(side=LEFT, anchor=N, padx=5, pady=5)

        self.txt = Text(frame4)
        scr = tk.Scrollbar(frame4, orient=tk.VERTICAL, command=self.txt.yview)
        self.txt.config(yscrollcommand=scr.set, font=('Arial', 12, 'normal'))
        self.txt.pack(fill=BOTH, pady=5, padx=5, expand=True)

        # btn_decrypt = tk.Button(frame4, text='Save', fg='red', command=browse_file)
        # btn_decrypt.pack(padx=5, pady=5, side=tk.LEFT)

        pass

    def encrypt(self):
        print('encrypt')
        print(self.algorithm_select.get())
        print(self.password_entry.get())
        lines = self.get_lines()
        # print(lines)
        passpord = self.password_entry.get()
        key, source, encode = passpord.encode(), lines.encode(), True

        key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
        IV = Random.new().read(AES.block_size)  # generate IV
        encryptor = AES.new(key, AES.MODE_CBC, IV)
        padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
        source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
        data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
        out = base64.b64encode(data).decode("utf-8") if encode else data

        self.txt.delete(1.0, tk.END)
        self.txt.insert(tk.END, out)
        pass

    def get_lines(self):
        with open(self.filename.get()) as f:
            line = f.readline()
            lines = line + "\n"
            while line:
                line = f.readline()
                lines += line + "\n"
                pass
            pass
        return lines

    def decrypt(self):
        print('decrypt')
        print(self.algorithm_select.get())
        print(self.password_entry.get())

        lines = self.get_lines()
        # print(lines)
        passpord = self.password_entry.get()
        key, source = passpord.encode(), lines.encode("utf-8")


        source = base64.b64decode(source)
        key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
        IV = source[:AES.block_size]  # extract the IV from the beginning
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        data = decryptor.decrypt(source[AES.block_size:])  # decrypt
        padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
        if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
            self.txt.delete(1.0, tk.END)
            self.txt.insert(tk.END, "Wrong password")
            raise ValueError("Invalid padding...")
        out = data[:-padding]  # remove the padding
        self.txt.delete(1.0, tk.END)
        self.txt.insert(tk.END, out)
        pass

    def browse_file(self):
        print('browse file')
        print(self.entry1.get())

        username = getpass.getuser()
        print(username)
        a = filedialog.askopenfilename(initialdir="/home/{}/".format(username), title="Select file",
                                   filetypes=(("Text files", "*.txt"), ("Encrypted files", "*.enc"), ("all files", "*.*")))
        print(a)
        self.filename.set(a)

        pass

    def save_file(self):
        username = getpass.getuser()
        print(username)
        a = filedialog.asksaveasfilename(initialdir="/home/{}/".format(username), title="Select file",
                                     filetypes=(("jpeg files", "*.jpg"), ("all files", "*.*")))
        print(a)
        pass

def donothing():
   x = 0

   pass


def main():
    root = Tk()
    # root.geometry("400x400+300+300")
    root.minsize(430, 300)
    menubar = tk.Menu(root)
    filemenu = tk.Menu(menubar, tearoff=0)
    filemenu.add_command(label="New", command=donothing)
    filemenu.add_command(label="Open", command=donothing)
    filemenu.add_command(label="Save", command=donothing)
    filemenu.add_separator()
    filemenu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="File", menu=filemenu)

    helpmenu = tk.Menu(menubar, tearoff=0)
    helpmenu.add_command(label="Help Index", command=donothing)
    helpmenu.add_command(label="About...", command=donothing)
    menubar.add_cascade(label="Help", menu=helpmenu)

    app = CrypterWindow()

    root.config(menu=menubar)
    root.mainloop()


if __name__ == '__main__':
    main()
