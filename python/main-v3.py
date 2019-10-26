
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
import glob
import os

def donothing():
   x = 0

   pass

class CrypterWindow:
    """
    Crypter Main Window

    """
    def __init__(self):
        # super().__init__()
        self.root = Tk()
        # root.geometry("400x400+300+300")
        self.root.minsize(500, 350)
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="New", command=donothing)
        filemenu.add_command(label="Open", command=donothing)
        filemenu.add_command(label="Save", command=donothing)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="Help Index", command=donothing)
        helpmenu.add_command(label="About...", command=donothing)
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.root.config(menu=menubar)

        self.algorithm_select = None
        self.entry1 = None
        self.password_entry = None
        self.selected_algorithm = tk.StringVar()
        self.password_txt = tk.StringVar()
        self.filename = tk.StringVar()
        self.Encryption_Algorithms = ["md5", "sha"]
        self.txt_in = None
        self.modes = ["Encrypt", "Decrypt"]
        self.selected_mode = tk.StringVar()
        # self.selected_mode.set(self.modes[0])
        self.files_only = None
        self.itemsforlistbox = None

        self.initUI()
        self.root.mainloop()

    def initUI(self):
        # self.master.title("Crypter")
        # self.pack(fill=BOTH, expand=True)

        # self.set_menubar()
        # sidebar
        self.set_sidebar()

        # Add next frame
        frame1 = Frame(self.root)
        frame1.pack(fill=X)

        lbl1 = tk.Label(frame1, text="Location ", width=10)
        lbl1.pack(side=LEFT, padx=5, pady=5)

        self.entry1 = Entry(frame1, textvariable=self.filename)
        self.entry1.pack(fill=X, padx=5, pady=5)

        btn_browse = tk.Button(frame1, text='Browse', fg='red', command=self.browse_file)
        btn_browse.pack(padx=5, pady=5, side=tk.RIGHT)

        # monitor frame
        frame2 = Frame(self.root)
        frame2.pack(fill=X)

        password = Label(frame2, text="Password", width=10)
        password.pack(side=LEFT, padx=5, pady=5)

        self.password_entry = Entry(frame2, textvariable=self.password_txt)
        self.password_entry.pack(side=LEFT, padx=5, pady=5, fill=X)

        self.algorithm_select = tk.ttk.Combobox(frame2, width=10, textvariable=self.selected_algorithm)
        self.selected_algorithm.set(self.Encryption_Algorithms[1])  # default value
        self.algorithm_select['values'] = tuple(self.Encryption_Algorithms)
        # combo.grid(column=1, row=0)
        self.algorithm_select.pack(padx=5, pady=5, side=tk.LEFT)

        mode = tk.Label(frame2, text='Mode', fg='blue')
        mode.pack(padx=5, pady=5, side=tk.LEFT)

        # the constructor syntax is:
        # OptionMenu(master, variable, *values)

        option_menu = tk.ttk.OptionMenu(frame2, self.selected_mode, self.modes[0], *self.modes)
        option_menu.pack(padx=5, pady=5, side=tk.LEFT)

        btn_run_cryption = tk.Button(frame2, text='Run', fg='red', command=self.run_cryption)
        btn_run_cryption.pack(padx=0, pady=5, side=tk.LEFT)

        frame_in_out_data = tk.Frame(self.root)
        frame_in_out_data.pack(fill=BOTH, expand=True)

        frame_in_data = tk.Frame(frame_in_out_data)
        frame_in_data.pack(fill=tk.Y, expand=True, side=tk.LEFT)
        lbl3 = Label(frame_in_data, text="Input", width=6, font=('Arial', 12, 'bold'))
        lbl3.pack(side=tk.TOP, anchor=N, padx=5, pady=5)

        self.txt_in = tk.Text(frame_in_data)
        scra = tk.Scrollbar(frame_in_data, orient=tk.VERTICAL, command=self.txt_in.yview)
        self.txt_in.config(yscrollcommand=scra.set, font=('Arial', 12, 'normal'))
        self.txt_in.pack(pady=5, padx=5, expand=True, side=tk.LEFT)

        frame_out_data = tk.Frame(frame_in_out_data)
        frame_out_data.pack(fill=tk.Y, expand=True, side=tk.RIGHT)
        lbl3 = Label(frame_out_data, text="Output", width=6, font=('Arial', 12, 'bold'))
        lbl3.pack(side=tk.TOP, anchor=N, padx=5, pady=5)

        self.txt_out = tk.Text(frame_out_data)
        scrb = tk.Scrollbar(frame_out_data, orient=tk.VERTICAL, command=self.txt_in.yview)
        self.txt_out.config(yscrollcommand=scrb.set, font=('Arial', 12, 'normal'))
        self.txt_out.pack(pady=5, padx=5, expand=True, side=tk.RIGHT)

        # btn_decrypt = tk.Button(frame_in_out_data, text='Save', fg='red', command=browse_file)
        # btn_decrypt.pack(padx=5, pady=5, side=tk.LEFT)

        pass

    def set_menubar(self):
        menubar = tk.Menu(self)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="New", command=donothing)
        filemenu.add_command(label="Open", command=donothing)
        filemenu.add_command(label="Save", command=donothing)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=filemenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="Help Index", command=donothing)
        helpmenu.add_command(label="About...", command=donothing)
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.config(menu=menubar)

        pass

    def set_sidebar(self):
        sidebar = tk.Frame(self.root, width=200, bg='white', height=500, relief='sunken', borderwidth=2)
        sidebar.pack(expand=True, fill='y', side='left', anchor='nw')

        lbl1 = tk.Label(sidebar, text="Files", font=('times', 12))
        lbl1.pack(fill=tk.X, side=tk.TOP)

        username = getpass.getuser()
        location = "/home/{}".format(username)
        # files = os.listdir(location)
        files_all = glob.glob(location + "/*")
        # itemsforlistbox=['one','two','three','four','five','six','seven']
        # list only files in the given directory
        self.files_only = [f for f in files_all if os.path.isfile(f)]
        print(self.files_only)
        self.itemsforlistbox = [f.split('/')[-1] for f in self.files_only]

        scrollx = tk.Scrollbar(sidebar, orient=tk.HORIZONTAL)
        scrollx.pack(side=tk.BOTTOM, fill=tk.X)

        scrolly = tk.Scrollbar(sidebar, orient=tk.VERTICAL)
        scrolly.pack(side=tk.RIGHT, fill=tk.Y)

        mylistbox = tk.Listbox(sidebar, width=20, font=('times', 12), yscrollcommand=scrolly.set,
                               xscrollcommand=scrollx.set)
        mylistbox.bind('<<ListboxSelect>>', self.select_from_sidebar)
        mylistbox.pack(fill=tk.Y, expand=True)
        # mylistbox.place(x=32,y=90)

        for items in self.itemsforlistbox:
            mylistbox.insert(tk.END, items)
        pass

    def select_from_sidebar(self, event):
        widget = event.widget
        selection = widget.curselection()
        print(selection)
        picked = widget.get(selection[0])
        print(picked)
        self.filename.set(self.files_only[selection[0]])
        pass

    def run_cryption(self):
        current_mode = self.selected_mode.get()
        print("selected mode ", current_mode)
        filename = self.filename.get()
        lines = self.get_lines()
        self.show_in_input(lines)

        if current_mode == self.modes[0]:
            self.encrypt(lines)
            pass
        elif current_mode == self.modes[1]:
            self.decrypt(lines)
            pass
        else:
            print("Unknown mode")

    def encrypt(self, lines):
        print('encrypt')
        print(self.algorithm_select.get())
        print(self.password_entry.get())
        print("selected mode ", self.selected_mode.get())
        if self.selected_mode.get() != self.modes[0]:
            print("Wrong mode is selected")
            return


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

        self.show_in_output(out)
        # self.txt_in.delete(1.0, tk.END)
        # self.txt_in.insert(tk.END, out)
        pass

    def get_lines(self):
        try:
            with open(self.filename.get()) as f:
                line = f.readline()
                lines = line + "\n"
                while line:
                    line = f.readline()
                    lines += line + "\n"
                    pass
                pass
        except FileNotFoundError as e:
            lines = self.load_from_input()
            print(e)
            pass

        if lines == "":
            print("No data found")
            return

        return lines

    def decrypt(self, lines):
        print('decrypt')
        print(self.algorithm_select.get())
        print(self.password_entry.get())
        print("selected mode ", self.selected_mode.get())
        if self.selected_mode.get() != self.modes[1]:
            print("Wrong mode is selected")
            return

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
            self.show_in_output("Wrong password")
            # self.txt_in.delete(1.0, tk.END)
            # self.txt_in.insert(tk.END, )
            raise ValueError("Invalid padding...")
        out = data[:-padding]  # remove the padding
        self.show_in_output(out)
        # self.txt_in.delete(1.0, tk.END)
        # self.txt_in.insert(tk.END, out)
        pass

    def browse_file(self):
        print('browse file')
        print(self.entry1.get())
        print("selected mode ", self.selected_mode.get())
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

    def load_from_input(self):
        lines = self.txt_in.get("1.0", 'end-1c')
        print(lines)
        return lines
        pass

    def show_in_input(self, lines):
        self.txt_in.delete(1.0, tk.END)
        self.txt_in.insert(tk.END, lines)
        pass

    def show_in_output(self, lines):
        self.txt_out.delete(1.0, tk.END)
        self.txt_out.insert(tk.END, lines)
        pass


def main():
    app = CrypterWindow()
    pass


if __name__ == '__main__':
    main()
