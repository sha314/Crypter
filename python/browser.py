import tkinter as tk
import os
import getpass
import glob

"""
File and Folder browser window
"""
root = tk.Tk()
root.minsize(200, 200)


# sidebar
sidebar = tk.Frame(root, width=200, bg='white', height=500, relief='sunken', borderwidth=2)
sidebar.pack(expand=True, fill='y', side='left', anchor='nw')

lbl1 = tk.Label(sidebar, text="Files", font=('times', 12))
lbl1.pack(fill=tk.X, side=tk.TOP)

username = getpass.getuser()
location = "/home/{}".format(username)
# files = os.listdir(location)
files = glob.glob(location + "/*")
# itemsforlistbox=['one','two','three','four','five','six','seven']
# list only files in the given directory
itemsforlistbox = [f.split('/')[-1] for f in files if os.path.isfile(f)]


def select_from_sidebar(event):
    widget = event.widget
    selection = widget.curselection()
    print(selection)
    picked = widget.get(selection[0])
    print(picked)
    pass


scrollx = tk.Scrollbar(sidebar, orient=tk.HORIZONTAL)
scrollx.pack(side=tk.BOTTOM, fill=tk.X)

scrolly = tk.Scrollbar(sidebar, orient=tk.VERTICAL)
scrolly.pack(side=tk.RIGHT, fill=tk.Y)


mylistbox=tk.Listbox(sidebar, width=20, font=('times', 12), yscrollcommand=scrolly.set, xscrollcommand=scrollx.set)
mylistbox.bind('<<ListboxSelect>>', select_from_sidebar)
mylistbox.pack(fill=tk.Y, expand=True)
# mylistbox.place(x=32,y=90)

for items in itemsforlistbox:
    mylistbox.insert(tk.END, items)




# main content area
mainarea = tk.Frame(root, bg='#CCC', width=500, height=500)
mainarea.pack(expand=True, fill='both', side='right')

root.mainloop()
