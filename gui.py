from tkinter import *
from tkinter import filedialog, messagebox, font
from threading import Thread
import time
import requests
import os

from backend import blockchain, compute_file_hash, run_flask_server, peers

def run_gui():
    def switch_view(view):
        for widget in main_frame.winfo_children():
            widget.destroy()
        view()

    def view_home():
        Label(main_frame, text="Welcome to Blockchain File Manager", font=("Segoe UI", 16)).pack(pady=20)

    def view_file_menu():
        Button(main_frame, text="➕ Add File to Blockchain", font=app_font, command=handle_add_files).pack(pady=10)
        Button(main_frame, text="🔍 Verify File", font=app_font, command=handle_verify_file).pack(pady=10)
        Button(main_frame, text="🌐 Verify File from Peer", font=app_font, command=handle_verify_file_from_peer).pack(pady=10)

    def view_connectivity_menu():
        Label(main_frame, text="🌐 Connectivity Options", font=("Segoe UI", 14, "bold")).pack(pady=10)

        Label(main_frame, text="Start New Peer Server (Enter Port):").pack()
        port_var = StringVar()
        Entry(main_frame, textvariable=port_var, font=app_font).pack(pady=5)

        def start_server_from_input():
            port = port_var.get()
            if port.isdigit():
                Thread(target=run_flask_server, args=(int(port),), daemon=True).start()
                messagebox.showinfo("Server Started", f"Server started on port {port}")
            else:
                messagebox.showerror("Invalid Input", "Enter valid port number")

        Button(main_frame, text="🚀 Start Server", font=app_font, command=start_server_from_input).pack(pady=10)

        Label(main_frame, text="Connect to Peer (e.g., 127.0.0.1:5001):").pack()
        peer_var = StringVar()
        Entry(main_frame, textvariable=peer_var, font=app_font).pack(pady=5)

        def connect_to_peer_input():
            peer = peer_var.get().strip()
            if not peer:
                return
            try:
                res = requests.post("http://127.0.0.1:5000/connect", json={"peer": peer})
                if res.status_code == 201:
                    peers.add(peer)
                    messagebox.showinfo("Connected", f"Connected to peer: {peer}")
                else:
                    messagebox.showerror("Failed", f"Peer connection failed: {res.text}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to connect to peer: {e}")

        Button(main_frame, text="🔗 Connect", font=app_font, command=connect_to_peer_input).pack(pady=10)

    def view_blockchain():
        text = Text(main_frame, wrap='word', font=("Consolas", 10), bg="#f4f4f4", fg="#333")
        scrollbar = Scrollbar(main_frame, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)

        for block in blockchain.chain:
            text.insert(END, f"🧱 Block {block.index}\n")
            text.insert(END, f"⏱ Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block.timestamp))}\n")
            text.insert(END, f"📁 File Hash: {block.file_hash}\n")
            text.insert(END, f"🔗 Previous Hash: {block.previous_hash}\n")
            text.insert(END, f"✅ Current Hash: {block.current_hash}\n")
            text.insert(END, "-" * 60 + "\n\n")

        text.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

    def handle_add_files():
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        file_hash = compute_file_hash(filepath)
        if blockchain.is_file_in_chain(file_hash):
            messagebox.showinfo("File Exists", "This file already exists in the blockchain.")
        else:
            blockchain.add_block(file_hash)
            messagebox.showinfo("Success", "File added to blockchain successfully.")

    def handle_verify_file():
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        file_hash = compute_file_hash(filepath)
        exists = blockchain.is_file_in_chain(file_hash)
        if exists:
            messagebox.showinfo("Verified", "This file is verified in the blockchain.")
        else:
            messagebox.showwarning("Not Verified", "This file is NOT in the blockchain.")

    def handle_verify_file_from_peer():
        filepath = filedialog.askopenfilename()
        if not filepath or not peers:
            return messagebox.showerror("Error", "No file selected or no peers connected.")
        file_hash = compute_file_hash(filepath)
        for peer in peers:
            try:
                res = requests.post(f"http://{peer}/verify", json={"file_hash": file_hash})
                if res.status_code == 200 and res.json().get("is_in_chain"):
                    return messagebox.showinfo("Verified", f"This file is verified by peer {peer}.")
            except:
                continue
        messagebox.showwarning("Not Verified", "This file is NOT verified by any peer.")

    root = Tk()
    root.title("🌐 Blockchain File Manager")
    root.geometry("900x600")
    root.configure(bg='#ffffff')
    root.rowconfigure(0, weight=1)
    root.columnconfigure(1, weight=1)

    app_font = font.Font(family="Segoe UI", size=11, weight="bold")

    sidebar = Frame(root, bg="#83bfca", width=200)
    sidebar.grid(row=0, column=0, sticky="ns")

    Label(sidebar, text="Dashboard", bg="#83bfca", fg="white", font=("Segoe UI", 14, "bold")).pack(pady=20)
    Button(sidebar, text="🏠 Home", font=app_font, width=20, bg="white", command=lambda: switch_view(view_home)).pack(pady=5)
    Button(sidebar, text="📁 File", font=app_font, width=20, bg="white", command=lambda: switch_view(view_file_menu)).pack(pady=5)
    Button(sidebar, text="🌐 Connectivity", font=app_font, width=20, bg="white", command=lambda: switch_view(view_connectivity_menu)).pack(pady=5)
    Button(sidebar, text="📊 View Blockchain", font=app_font, width=20, bg="white", command=lambda: switch_view(view_blockchain)).pack(pady=5)
    Button(sidebar, text="❌ Exit", font=app_font, width=20, bg="#ff5252", fg="white", command=root.quit).pack(pady=20)

    main_frame = Frame(root, bg="#e0f7fa")
    main_frame.grid(row=0, column=1, sticky="nsew")

    # Start default Flask server
    Thread(target=run_flask_server, args=(5000,), daemon=True).start()

    switch_view(view_home)
    root.mainloop()

if __name__ == "__main__":
    run_gui()
