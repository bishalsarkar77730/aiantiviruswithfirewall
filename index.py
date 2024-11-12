import tkinter as tk
from tkinter import messagebox
import hashlib
import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess

# Sample virus signatures database
SIGNATURES_DB = {
    "sample_virus": "5d41402abc4b2a76b9719d911017c592"  # Example MD5 hash of 'hello'
}

# Placeholder for user credentials
PASSWORD = "securepassword123"
WRONG_ATTEMPTS = 0


class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Custom Antivirus")

        # UI Elements
        self.scan_btn = tk.Button(root, text="Scan File", command=self.scan_file)
        self.scan_btn.pack(pady=10)

        self.block_ip_btn = tk.Button(root, text="Block IP", command=self.block_ip_prompt)
        self.block_ip_btn.pack(pady=10)

        self.auth_label = tk.Label(root, text="Enter Password to Deactivate Antivirus")
        self.auth_label.pack(pady=10)
        self.auth_entry = tk.Entry(root, show="*")
        self.auth_entry.pack(pady=5)
        self.auth_btn = tk.Button(root, text="Authenticate", command=self.authenticate)
        self.auth_btn.pack(pady=10)

    def scan_file(self):
        file_path = tk.filedialog.askopenfilename()
        if not file_path:
            return

        with open(file_path, "rb") as file:
            file_data = file.read()
            file_hash = hashlib.md5(file_data).hexdigest()

            for virus_name, signature in SIGNATURES_DB.items():
                if file_hash == signature:
                    messagebox.showwarning("Warning", f"Virus detected: {virus_name}")
                    return

        messagebox.showinfo("Scan Result", "No virus found")

    def block_ip_prompt(self):
        ip_address = tk.simpledialog.askstring("Block IP", "Enter IP Address to Block:")
        if ip_address:
            self.block_ip(ip_address)

    def block_ip(self, ip_address):
        subprocess.run(["powershell", "New-NetFirewallRule", "-DisplayName", f"Block IP {ip_address}",
                        "-Direction", "Inbound", "-RemoteAddress", ip_address, "-Action", "Block"])
        messagebox.showinfo("Firewall", f"IP {ip_address} has been blocked.")

    def authenticate(self):
        global WRONG_ATTEMPTS
        entered_password = self.auth_entry.get()

        if entered_password == PASSWORD:
            messagebox.showinfo("Authentication", "Password correct. Antivirus deactivated.")
            WRONG_ATTEMPTS = 0
        else:
            WRONG_ATTEMPTS += 1
            if WRONG_ATTEMPTS >= 3:
                new_password = self.reset_password()
                messagebox.showwarning("Authentication",
                                       "Too many failed attempts. Check your email for a new password.")
                self.send_email(new_password)
            else:
                messagebox.showwarning("Authentication", "Incorrect password. Try again.")

    def reset_password(self):
        global PASSWORD
        new_password = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
        PASSWORD = new_password
        return new_password

    def send_email(self, new_password):
        # Email credentials
        sender_email = "youremail@example.com"
        receiver_email = "receiver@example.com"
        password = "your_email_password"

        # Email content
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = receiver_email
        msg["Subject"] = "New Antivirus Password"
        msg.attach(MIMEText(f"Your new antivirus password is: {new_password}", "plain"))

        try:
            server = smtplib.SMTP("smtp.example.com", 587)  # Replace with your SMTP server
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            server.quit()
            print("Email sent successfully")
        except Exception as e:
            print(f"Failed to send email: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
