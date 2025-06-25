import sys
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import messagebox, font, filedialog, ttk
from argon2.low_level import hash_secret_raw, Type

MAGIC_HEADER = b"HKGAv1___"
ENCRYPTED_FLAG = b"\x01"
EMPTY_FLAG = b"\x00"
SALT_SIZE = 16


def derive_key(pw: str, salt: bytes) -> bytes:
    key = hash_secret_raw(
        secret=pw.encode('utf-8'),
        salt=salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )

    return key


def encrypt_data(data: bytes, pw: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(pw, salt)
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    flag = ENCRYPTED_FLAG if len(data) > 0 else EMPTY_FLAG
    payload = MAGIC_HEADER + flag + data

    ct, tag = cipher.encrypt_and_digest(payload)
    return salt + iv + tag + ct


def decrypt_data(blob: bytes, pw: str) -> bytes:
    if len(blob) < SALT_SIZE + 12 + 16:
        raise ValueError("File too short or not valid .hkga file")

    salt = blob[:SALT_SIZE]
    iv = blob[SALT_SIZE:SALT_SIZE+12]
    tag = blob[SALT_SIZE+12:SALT_SIZE+28]
    ct = blob[SALT_SIZE+28:]

    key = derive_key(pw, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    pt = cipher.decrypt_and_verify(ct, tag)

    if not pt.startswith(MAGIC_HEADER):
        raise ValueError("Wrong password or corrupted file")

    flag = pt[len(MAGIC_HEADER):len(MAGIC_HEADER)+1]
    data = pt[len(MAGIC_HEADER)+1:]

    if flag == EMPTY_FLAG:
        return b""
    elif flag == ENCRYPTED_FLAG:
        return data
    else:
        raise ValueError("Unknown encryption flag")


def ask_password(prompt="Enter password:", title="Password"):
    pw = None

    def confirm():
        nonlocal pw
        pw = entry.get()
        win.destroy()

    def toggle():
        entry.config(show="" if var.get() else "*")

    win = tk.Toplevel()
    win.title(title)
    win.geometry("350x160")
    win.configure(bg="#1E1E1E")
    win.resizable(False, False)

    center_x = win.winfo_screenwidth() // 2 - 175
    center_y = win.winfo_screenheight() // 2 - 80
    win.geometry(f"+{center_x}+{center_y}")

    tk.Label(win, text=prompt, bg="#1E1E1E", fg="#FFFFFF",
             font=("Segoe UI", 10)).pack(pady=(15, 0))

    entry = tk.Entry(win, show="*", bg="#000000", fg="#FFFFFF",
                     insertbackground="#FFFFFF", relief="flat",
                     font=("Consolas", 12), justify="center")
    entry.pack(pady=8, padx=20, fill="x")

    var = tk.IntVar()
    check = tk.Checkbutton(win, text="Show password", variable=var,
                           command=toggle, bg="#1E1E1E", fg="#CCCCCC",
                           activebackground="#1E1E1E", selectcolor="#1E1E1E")
    check.pack()

    ttk.Button(win, text="OK", command=confirm).pack(pady=8)

    entry.focus()
    win.grab_set()
    win.wait_window()
    return pw


class Editor(tk.Tk):
    def __init__(self, path, pw, decrypted_bytes):
        super().__init__()
        self.path, self.pw = path, pw
        self.title(f"HKGA Editor — {os.path.basename(path)}")
        self.configure(bg="#121212")
        self.geometry("700x520")
        self.resizable(True, True)
        self.attributes('-alpha', 0.9)

        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

        mono = font.Font(family="Consolas", size=13)
        frame = tk.Frame(self, bg="#1E1E1E", bd=2, relief="sunken")
        frame.pack(fill="both", expand=True, padx=15, pady=(15, 5))

        self.txt = tk.Text(frame, bg="#000000", fg="#D4D4D4",
                           insertbackground="#D4D4D4", font=mono,
                           wrap="word", relief="flat", bd=0, undo=True)
        self.txt.pack(fill="both", expand=True)

        convert_btn = tk.Button(self, text="Convert to .TXT",
                                bg="#222", fg="#D4D4D4", activebackground="#444",
                                font=("Segoe UI", 11, "bold"),
                                command=self.convert_txt)
        convert_btn.pack(pady=(0, 15), ipadx=10, ipady=5)

        try:
            self.txt.insert("1.0", decrypted_bytes.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", f"Could not decode text:\n{e}")
            self.destroy()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def convert_txt(self):
        out = filedialog.asksaveasfilename(defaultextension=".txt",
                                           filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not out:
            return
        data = self.txt.get("1.0", "end-1c").encode('utf-8')
        with open(out, 'wb') as f:
            f.write(data)
        messagebox.showinfo("Saved", f"Saved as:\n{out}")

    def on_close(self):
        data = self.txt.get("1.0", "end-1c").encode('utf-8')
        blob = encrypt_data(data, self.pw)
        with open(self.path, 'wb') as f:
            f.write(blob)
        self.destroy()


def main():
    root = tk.Tk()
    root.withdraw()

    if len(sys.argv) < 2:
        messagebox.showinfo("HKGA", "Open a file with this program.")
        return

    path = sys.argv[1]
    if not os.path.isfile(path):
        messagebox.showerror("Error", f"No such file:\n{path}")
        return

    with open(path, 'rb') as f:
        data = f.read()

    pw = ask_password(
        "Enter password to decrypt (or Cancel if not encrypted):")
    if pw:
        try:
            decrypted = decrypt_data(data, pw)
            root.destroy()
            Editor(path, pw, decrypted).mainloop()
            return
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")
            root.destroy()
            return
    else:
        pw = ask_password("Set password to encrypt this file:")
        if not pw:
            messagebox.showwarning("Cancelled", "No password entered.")
            root.destroy()
            return
        enc = encrypt_data(data, pw)
        with open(path, 'wb') as f:
            f.write(enc)
        messagebox.showinfo("Encrypted", f"File encrypted in place:\n{path}")
        root.destroy()


if __name__ == "__main__":
    main()
