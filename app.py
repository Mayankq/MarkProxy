import customtkinter as ctk
import tkinter as tk
import subprocess
import signal
import os

# Set the appearance mode and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Create the main window
root = ctk.CTk()
root.iconbitmap("favicon.ico")
root.geometry("1100x770")
root.title("MarkProxy Dashboard")
root.resizable(False, False)

# Configure grid for the root window to make it responsive
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=0)  # Sidebar width is fixed
root.grid_columnconfigure(1, weight=1)  # Main content area

# Sidebar frame with navigation
sidebar_frame = ctk.CTkFrame(root, width=250, corner_radius=0)
sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")

sidebar_label = ctk.CTkLabel(sidebar_frame, text="MarkProxy", font=("Helvetica", 20, "bold"))
sidebar_label.grid(row=0, column=0, padx=20, pady=20)

# Sidebar button dimensions
button_width = 200
button_height = 50

# Colors
default_fg_color = "#3B3B3B"
activated_fg_color = "#238efa"
hover_color = "#61b0ff"

# Function to activate the selected button
def activate_button(button):
    for btn in buttons:
        btn.configure(fg_color=default_fg_color, hover_color=hover_color)
    button.configure(fg_color=activated_fg_color)

# Define the show_frame function
def show_frame(frame):
    frame.tkraise()

proxy_running = False  # Variable to track proxy server status
proxy_process = None

def start_proxy_server():
    global proxy_running, proxy_process
    if not proxy_running:
        log_file = open("logs_text.txt", "w")
        proxy_process = subprocess.Popen(
            ["mitmdump", "-s", "proxy_addon.py"],
            stdout=log_file,
            stderr=log_file
        )
        proxy_running = True

def stop_proxy_server():
    global proxy_running, proxy_process
    if proxy_running and proxy_process:
        os.kill(proxy_process.pid, signal.SIGTERM)
        proxy_process.wait()  # Ensure the process has terminated before continuing
        proxy_running = False
        if os.path.exists("logs_text.txt"):
            os.remove("logs_text.txt")

def toggle_proxy_server():
    if proxy_running:
        stop_proxy_server()
    else:
        start_proxy_server()

def toggle_content_filtering():
    if os.path.exists("content_filtering_enabled.txt"):
        os.remove("content_filtering_enabled.txt")
    else:
        with open("content_filtering_enabled.txt", "w") as f:
            f.write("enabled")

def toggle_script_filtering():
    if os.path.exists("script_filtering.txt"):
        os.remove("script_filtering.txt")
    else:
        with open("script_filtering.txt", "w") as f:
            f.write("enabled")

def toggle_image_filtering():
    if os.path.exists("image_filtering.txt"):
        os.remove("image_filtering.txt")
    else:
        with open("image_filtering.txt", "w") as f:
            f.write("enabled")

# Define buttons
buttons = []

dashboard_button = ctk.CTkButton(sidebar_frame, text="Dashboard", corner_radius=60, fg_color=activated_fg_color, hover_color=hover_color, width=button_width, height=button_height, command=lambda: [show_frame(dashboard_frame), activate_button(dashboard_button)])
dashboard_button.grid(row=1, column=0, padx=20, pady=10)
buttons.append(dashboard_button)

ad_list_button = ctk.CTkButton(sidebar_frame, text="Ad Lists", corner_radius=60, fg_color=default_fg_color, hover_color=hover_color, width=button_width, height=button_height, command=lambda: [show_frame(ad_list_frame), activate_button(ad_list_button)])
ad_list_button.grid(row=2, column=0, padx=20, pady=10)
buttons.append(ad_list_button)

logs_button = ctk.CTkButton(sidebar_frame, text="Logs", corner_radius=60, fg_color=default_fg_color, hover_color=hover_color, width=button_width, height=button_height, command=lambda: [show_frame(logs_frame), activate_button(logs_button)])
logs_button.grid(row=4, column=0, padx=20, pady=10)
buttons.append(logs_button)

# Create frames for each section
dashboard_frame = ctk.CTkFrame(root)
ad_list_frame = ctk.CTkFrame(root)
cache_list_frame = ctk.CTkFrame(root)
logs_frame = ctk.CTkFrame(root)

for frame in (dashboard_frame, ad_list_frame, cache_list_frame, logs_frame):
    frame.grid(row=0, column=1, sticky="nsew")
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)

# Dashboard Frame Content
web_frame = ctk.CTkFrame(dashboard_frame)
web_frame.grid(row=0, column=0, pady=20, padx=15, sticky="nsew")
web_frame.grid_rowconfigure(0, weight=1)
web_frame.grid_rowconfigure(1, weight=1)
web_frame.grid_rowconfigure(2, weight=0)
web_frame.grid_rowconfigure(3, weight=1)
web_frame.grid_columnconfigure(0, weight=1)

web_label = ctk.CTkLabel(web_frame, text="Block Website", font=("Helvetica", 12, "bold"))
web_label.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

web_entry = ctk.CTkEntry(web_frame, placeholder_text="Website URL")
web_entry.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

submit_button = ctk.CTkButton(web_frame, text="SUBMIT", corner_radius=60, fg_color="#238efa", hover_color="#FF81A6")
submit_button.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

remove_button = ctk.CTkButton(web_frame, text="REMOVE", corner_radius=60, fg_color="#238efa", hover_color="#FF81A6")
remove_button.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

web_listbox = tk.Listbox(web_frame, bg="#2C2C34", fg="white", bd=0, highlightthickness=0, font=("Helvetica", 12))
web_listbox.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")

# Function to update the website listbox and file
def update_web_listbox():
    web_listbox.delete(0, tk.END)  # Clear existing URLs
    try:
        with open('blocked_websites.txt', 'r') as file:
            urls = file.readlines()
        for url in urls:
            web_listbox.insert(tk.END, url.strip())
    except FileNotFoundError:
        web_listbox.insert(tk.END, "No websites blocked yet.")

# Initial update of the website listbox
update_web_listbox()

# Function to block a website URL
def block_website():
    url = web_entry.get()
    if url:
        with open('blocked_websites.txt', 'a') as file:
            file.write(url + '\n')
        update_web_listbox()
        web_entry.delete(0, tk.END)  # Clear the entry after adding

# Function to remove a blocked website URL
def remove_website():
    selected = web_listbox.curselection()
    if selected:
        selected_url = web_listbox.get(selected[0])
        with open('blocked_websites.txt', 'r') as file:
            urls = file.readlines()
        with open('blocked_websites.txt', 'w') as file:
            for url in urls:
                if url.strip() != selected_url:
                    file.write(url)
        update_web_listbox()

# Link the functions to the buttons
submit_button.configure(command=block_website)
remove_button.configure(command=remove_website)

# Features Frame Content
features_frame = ctk.CTkFrame(dashboard_frame)
features_frame.grid(row=0, column=1, pady=20, padx=20, sticky="nsew")
features_frame.grid_rowconfigure(0, weight=1)
features_frame.grid_rowconfigure(1, weight=1)
features_frame.grid_rowconfigure(2, weight=1)
features_frame.grid_rowconfigure(3, weight=1)
features_frame.grid_rowconfigure(4, weight=1)
features_frame.grid_rowconfigure(5, weight=1)
features_frame.grid_columnconfigure(0, weight=1)

features_label = ctk.CTkLabel(features_frame, text="Features", font=("Helvetica", 12, "bold"))
features_label.grid(row=0, column=0, pady=10, sticky="nsew")

proxy_switch = ctk.CTkSwitch(features_frame, text="Proxy", command=toggle_proxy_server)
proxy_switch.grid(row=1, column=0, padx=20, pady=5, sticky="w")

script_filter_switch = ctk.CTkSwitch(features_frame, text="Script Filtering", command=toggle_script_filtering)
script_filter_switch.grid(row=2, column=0, padx=20, pady=5, sticky="w")

image_filter_switch = ctk.CTkSwitch(features_frame, text="Image Filtering", command=toggle_image_filtering)
image_filter_switch.grid(row=3, column=0, padx=20, pady=5, sticky="w")

ad_blocking_switch = ctk.CTkSwitch(features_frame, text="Ad Blocking", onvalue="on", offvalue="off")
ad_blocking_switch.select()
ad_blocking_switch.grid(row=4, column=0, padx=20, pady=5, sticky="w")
ad_blocking_switch.configure(state=tk.DISABLED)  # Disable ad_blocking_switch

caching_switch = ctk.CTkSwitch(features_frame, text="Caching", onvalue="on", offvalue="off")
caching_switch.select()
caching_switch.grid(row=5, column=0, padx=20, pady=5, sticky="w")
caching_switch.configure(state=tk.DISABLED)  # Disable caching_switch

# IP Address Frame Content
ip_frame = ctk.CTkFrame(dashboard_frame)
ip_frame.grid(row=1, column=0, pady=20, padx=15, sticky="nsew")
ip_frame.grid_rowconfigure(0, weight=1)
ip_frame.grid_rowconfigure(1, weight=1)
ip_frame.grid_rowconfigure(2, weight=0)
ip_frame.grid_rowconfigure(3, weight=1)
ip_frame.grid_rowconfigure(4, weight=0)
ip_frame.grid_columnconfigure(0, weight=1)

ip_label = ctk.CTkLabel(ip_frame, text="Block IP Address", font=("Helvetica", 12, "bold"))
ip_label.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

ip_entry = ctk.CTkEntry(ip_frame, placeholder_text="IP Address")
ip_entry.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

ip_submit_button = ctk.CTkButton(ip_frame, text="SUBMIT", corner_radius=60, fg_color="#238efa", hover_color="#FF81A6")
ip_submit_button.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

ip_remove_button = ctk.CTkButton(ip_frame, text="REMOVE", corner_radius=60, fg_color="#238efa", hover_color="#FF81A6")
ip_remove_button.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

ip_listbox = tk.Listbox(ip_frame, bg="#2C2C34", fg="white", bd=0, highlightthickness=0, font=("Helvetica", 12))
ip_listbox.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")

# Function to update the IP listbox and file
def update_ip_listbox():
    ip_listbox.delete(0, tk.END)  # Clear existing IPs
    try:
        with open('blocked_ips.txt', 'r') as file:
            ips = file.readlines()
        for ip in ips:
            ip_listbox.insert(tk.END, ip.strip())
    except FileNotFoundError:
        ip_listbox.insert(tk.END, "No IPs blocked yet.")

# Initial update of the IP listbox
update_ip_listbox()

# Function to block an IP address
def block_ip():
    ip_address = ip_entry.get()
    if ip_address:
        with open('blocked_ips.txt', 'a') as file:
            file.write(ip_address + '\n')
        update_ip_listbox()
        ip_entry.delete(0, tk.END)  # Clear the entry after adding

# Function to remove a blocked IP address
def remove_ip():
    selected = ip_listbox.curselection()
    if selected:
        selected_ip = ip_listbox.get(selected[0])
        with open('blocked_ips.txt', 'r') as file:
            ips = file.readlines()
        with open('blocked_ips.txt', 'w') as file:
            for ip in ips:
                if ip.strip() != selected_ip:
                    file.write(ip)
        update_ip_listbox()

# Link the functions to the buttons
ip_submit_button.configure(command=block_ip)
ip_remove_button.configure(command=remove_ip)

# Ad List frame content
ad_list_label = ctk.CTkLabel(ad_list_frame, text="Ad Lists", font=("Helvetica", 12, "bold"))
ad_list_label.grid(row=1, column=0, pady=20, padx=20, sticky="nsew")

ad_listbox = tk.Listbox(ad_list_frame, bg="#2C2C34", fg="white", bd=0, highlightthickness=0, font=("Helvetica", 12))
ad_listbox.grid(row=0, column=0, pady=10, padx=20, sticky="nsew")

def update_ads_listbox():
    if os.path.exists("ad_domains.txt"):
        with open("ad_domains.txt", "r") as file:
            lines = file.readlines()
        for line in lines:
            ad_listbox.insert(tk.END, line.strip())

    root.after(5000, update_ads_listbox)  # Schedule to run every 1000ms (1 second)

update_ads_listbox()    

# Cache List frame content
cache_list_label = ctk.CTkLabel(cache_list_frame, text="Cache List", font=("Helvetica", 12, "bold"))
cache_list_label.grid(row=1, column=0, pady=20, padx=20, sticky="nsew")

cache_listbox = tk.Listbox(cache_list_frame, bg="#2C2C34", fg="white", bd=0, highlightthickness=0, font=("Helvetica", 12))
cache_listbox.grid(row=0, column=0, pady=10, padx=20, sticky="nsew")

# Logs frame content
logs_label = ctk.CTkLabel(logs_frame, text="Logs", font=("Helvetica", 12, "bold"))
logs_label.grid(row=1, column=0, pady=10, padx=20, sticky="nsew")

logs_listbox = tk.Listbox(logs_frame, bg="#2C2C34", fg="white", bd=0, highlightthickness=0, font=("Helvetica", 12))
logs_listbox.grid(row=0, column=0, pady=20, padx=20, sticky="nsew")

def update_logs_listbox():
    logs_listbox.delete(0, tk.END)  # Clear existing logs
    if os.path.exists("logs_text.txt"):
        with open("logs_text.txt", "r") as file:
            lines = file.readlines()
        for line in lines:
            logs_listbox.insert(tk.END, line.strip())

    root.after(1000, update_logs_listbox)  # Schedule to run every 1000ms (1 second)

update_logs_listbox()    

# Display the dashboard frame initially
show_frame(dashboard_frame)

# Start the main event loop
root.mainloop()
