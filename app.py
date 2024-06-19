# gui.py
import customtkinter as ctk
import tkinter as tk
import threading
import socket
from proxy_server import start_proxy_server as start_proxy, ThreadedHTTPServer, ProxyHTTPRequestHandler
import logging

# Set the appearance mode and color theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Create the main window
root = ctk.CTk()
root.iconbitmap("favicon.ico")
root.geometry("1100x600")
root.title("MarkProxy Dashboard")
root.resizable(False, False) 

# Configure grid for the root window to make it responsive
root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)
root.grid_rowconfigure(2, weight=1)
root.grid_rowconfigure(3, weight=1)
root.grid_columnconfigure(0, weight=0)  # Sidebar width is fixed
root.grid_columnconfigure(1, weight=1)
root.grid_columnconfigure(2, weight=1)
root.grid_columnconfigure(3, weight=1)

# Sidebar frame with navigation
sidebar_frame = ctk.CTkFrame(root, width=400, corner_radius=0)
sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")

sidebar_label = ctk.CTkLabel(sidebar_frame, text="MarkProxy", font=("Helvetica", 16, "bold"))
sidebar_label.grid(row=0, column=0, padx=20, pady=20)

button_width = 250  # Setting the button width
button_height = 50

# Colors
default_fg_color = "#3B3B3B"
activated_fg_color = "#238efa"
hover_color = "#61b0ff"

# Function to activate the selected button
def activate_button(button):
    # Reset all buttons to default color
    for btn in buttons:
        btn.configure(fg_color=default_fg_color, hover_color=hover_color)
    # Set the selected button to activated color
    button.configure(fg_color=activated_fg_color)

# Define the show_frame function
def show_frame(frame):
    frame.tkraise()

proxy_running = False  # Variable to track proxy server status

def toggle_proxy_server():
    proxy_thread = threading.Thread(target=start_proxy_server, daemon=True)
    proxy_thread.start()

proxy_server_instance = None

def start_proxy_server():
    global proxy_server_instance, proxy_thread, proxy_running
    if not proxy_running:
        proxy_server_instance = ThreadedHTTPServer(('0.0.0.0', 8080), ProxyHTTPRequestHandler)
        proxy_thread = threading.Thread(target=proxy_server_instance.serve_forever, daemon=True)
        proxy_thread.start()
        proxy_running = True

def stop_proxy_server():
    global proxy_server_instance, proxy_running
    if proxy_running and proxy_server_instance:
        proxy_server_instance.shutdown()
        proxy_server_instance.server_close()
        proxy_running = False


# Define buttons
buttons = []

dashboard_button = ctk.CTkButton(sidebar_frame, text="Dashboard", corner_radius=60, fg_color=activated_fg_color, hover_color=hover_color, width=button_width, height=button_height, command=lambda: [show_frame(dashboard_frame), activate_button(dashboard_button)])
dashboard_button.grid(row=1, column=0, padx=20, pady=10)
buttons.append(dashboard_button)

ad_list_button = ctk.CTkButton(sidebar_frame, text="Ad Lists", corner_radius=60, fg_color=default_fg_color, hover_color=hover_color, width=button_width, height=button_height, command=lambda: [show_frame(ad_list_frame), activate_button(ad_list_button)])
ad_list_button.grid(row=2, column=0, padx=20, pady=10)
buttons.append(ad_list_button)

cache_list_button = ctk.CTkButton(sidebar_frame, text="Cache List", corner_radius=60, fg_color=default_fg_color, hover_color=hover_color, width=button_width, height=button_height, command=lambda: [show_frame(cache_list_frame), activate_button(cache_list_button)])
cache_list_button.grid(row=3, column=0, padx=20, pady=10)
buttons.append(cache_list_button)

logs_button = ctk.CTkButton(sidebar_frame, text="Logs", corner_radius=60, fg_color=default_fg_color, hover_color=hover_color, width=button_width, height=button_height, command=lambda: [show_frame(logs_frame), activate_button(logs_button)])
logs_button.grid(row=4, column=0, padx=20, pady=10)
buttons.append(logs_button)

# Create all frames in a loop
frames = {}
for F in ("dashboard_frame", "ad_list_frame", "cache_list_frame", "logs_frame"):
    frames[F] = ctk.CTkFrame(root)
    frames[F].grid(row=0, column=1, rowspan=4, columnspan=3, sticky="nsew", padx=20, pady=20)

dashboard_frame = frames["dashboard_frame"]
ad_list_frame = frames["ad_list_frame"]
cache_list_frame = frames["cache_list_frame"]
logs_frame = frames["logs_frame"]

# Configure grid for the frames to make them responsive
for frame in frames.values():
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_rowconfigure(1, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    frame.grid_columnconfigure(1, weight=1)
    frame.grid_columnconfigure(2, weight=1)

# Dashboard frame content
data_usage_frame = ctk.CTkFrame(dashboard_frame)
data_usage_frame.grid(row=0, column=0, columnspan=2, pady=20, padx=20, sticky="nsew")
data_usage_frame.grid_rowconfigure(0, weight=1)
data_usage_frame.grid_columnconfigure(0, weight=1)
data_usage_label = ctk.CTkLabel(data_usage_frame, text="Data Usage (GB)", font=("Helvetica", 12, "bold"))
data_usage_label.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

features_frame = ctk.CTkFrame(dashboard_frame)
features_frame.grid(row=0, column=2, pady=20, padx=20, sticky="nsew")
features_frame.grid_rowconfigure(0, weight=1)
features_frame.grid_rowconfigure(1, weight=1)
features_frame.grid_rowconfigure(2, weight=1)
features_frame.grid_rowconfigure(3, weight=1)
features_frame.grid_rowconfigure(4, weight=1)
features_frame.grid_columnconfigure(0, weight=1)

features_label = ctk.CTkLabel(features_frame, text="Features", font=("Helvetica", 12, "bold"))
features_label.grid(row=0, column=0, pady=10, sticky="nsew")

proxy_switch = ctk.CTkSwitch(features_frame, text="Proxy", command=toggle_proxy_server)
proxy_switch.grid(row=1, column=0, padx=20, pady=5, sticky="w")

content_filter_switch = ctk.CTkSwitch(features_frame, text="Content Filtering")
content_filter_switch.grid(row=2, column=0, padx=20, pady=5, sticky="w")

ad_blocking_switch = ctk.CTkSwitch(features_frame, text="Ad Blocking", onvalue="on", offvalue="off")
ad_blocking_switch.select()
ad_blocking_switch.grid(row=3, column=0, padx=20, pady=5, sticky="w")

caching_switch = ctk.CTkSwitch(features_frame, text="Caching")
caching_switch.grid(row=4, column=0, padx=20, pady=5, sticky="w")

# Authorize IP Address Frame
ip_frame = ctk.CTkFrame(dashboard_frame)
ip_frame.grid(row=1, column=0, pady=20, padx=15, sticky="nsew")
ip_frame.grid_rowconfigure(0, weight=1)
ip_frame.grid_rowconfigure(1, weight=1)
ip_frame.grid_rowconfigure(2, weight=0)
ip_frame.grid_rowconfigure(3, weight=1)
ip_frame.grid_columnconfigure(0, weight=1)

ip_label = ctk.CTkLabel(ip_frame, text="Block IP Address", font=("Helvetica", 12, "bold"))
ip_label.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

ip_entry = ctk.CTkEntry(ip_frame, placeholder_text="IP Address")
ip_entry.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

sub_button_height = 40

submit_button = ctk.CTkButton(ip_frame, text="SUBMIT", corner_radius=60, fg_color="#238efa", hover_color="#FF81A6", height=sub_button_height)
submit_button.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

ip_listbox = tk.Listbox(ip_frame, bg="#2C2C34", fg="white", bd=0, highlightthickness=0, font=("Helvetica", 12))
ip_listbox.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")

# Function to update the IP listbox and file
def update_ip_listbox():
    ip_listbox.delete(0, tk.END)  # Clear existing IPs
    try:
        with open('blocked_ips.txt', 'r') as file:
            ips = file.readlines()
        for ip in ips:
            ip_listbox.insert(tk.END, ip.strip())
    except FileNotFoundError:
        ip_listbox.insert(tk.END, "Error: blocked_ips.txt not found")

# Function to add an IP to the list and file
def add_ip_to_list():
    new_ip = ip_entry.get()
    if new_ip:
        ip_listbox.insert(tk.END, new_ip)
        with open('blocked_ips.txt', 'a') as file:
            file.write(new_ip + "\n")
        ip_entry.delete(0, tk.END)

submit_button.configure(command=add_ip_to_list)

# Initial update of IP listbox
update_ip_listbox()

# Content Filter Frame
content_filter_frame = ctk.CTkFrame(dashboard_frame)
content_filter_frame.grid(row=1, column=1, pady=20, padx=15, sticky="nsew")
content_filter_frame.grid_rowconfigure(0, weight=1)
content_filter_frame.grid_rowconfigure(1, weight=1)
content_filter_frame.grid_rowconfigure(2, weight=1)
content_filter_frame.grid_rowconfigure(3, weight=1)
content_filter_frame.grid_rowconfigure(4, weight=1)
content_filter_frame.grid_columnconfigure(0, weight=1)

content_filter_label = ctk.CTkLabel(content_filter_frame, text="Content Filter", font=("Helvetica", 12, "bold"))
content_filter_label.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

ads_check = ctk.CTkCheckBox(content_filter_frame, text="Ads")
ads_check.grid(row=1, column=0, padx=10, pady=5, sticky="w")

images_check = ctk.CTkCheckBox(content_filter_frame, text="Images")
images_check.grid(row=2, column=0, padx=10, pady=5, sticky="w")

videos_check = ctk.CTkCheckBox(content_filter_frame, text="Videos")
videos_check.grid(row=3, column=0, padx=10, pady=5, sticky="w")

scripts_check = ctk.CTkCheckBox(content_filter_frame, text="Scripts")
scripts_check.grid(row=4, column=0, padx=10, pady=5, sticky="w")

update_button = ctk.CTkButton(content_filter_frame, corner_radius=60, text="UPDATE", fg_color="#238efa", hover_color="#FF81A6", height=sub_button_height)
update_button.grid(row=5, column=0, padx=10, pady=10, sticky="nsew")

# Ads Blocked Frame
ads_blocked_frame = ctk.CTkFrame(dashboard_frame)
ads_blocked_frame.grid(row=1, column=2, pady=20, padx=15, sticky="nsew")
ads_blocked_frame.grid_rowconfigure(0, weight=0)
ads_blocked_frame.grid_rowconfigure(1, weight=0)
ads_blocked_frame.grid_rowconfigure(2, weight=1)  # Changed the weight to 1 for the listbox
ads_blocked_frame.grid_columnconfigure(0, weight=1)

ads_blocked_label = ctk.CTkLabel(ads_blocked_frame, text="Ads Blocked", font=("Helvetica", 12, "bold"))
ads_blocked_label.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

ads_count_label = ctk.CTkLabel(ads_blocked_frame, text="512 Ads Blocked", text_color="#22ff00")
ads_count_label.grid(row=1, column=0, padx=10, pady=0, sticky="nsew")

ads_listbox = tk.Listbox(ads_blocked_frame, bg="#2C2C34", fg="white", bd=0, highlightthickness=0, font=("Helvetica", 12))
ads_listbox.grid(row=2, column=0, padx=10, pady=0, sticky="nsew")

# Inserting ads into the listbox
ads = ["44.50.666.7080", "9.30.564.892.29900", "10.0.0.227:52900", "88.520.360.66:2100"]
for ad in ads:
    ads_listbox.insert(tk.END, ad)


# Logs frame content
logs_frame.grid_rowconfigure(0, weight=1)
logs_frame.grid_columnconfigure(0, weight=1)

logs_listbox = tk.Listbox(logs_frame, bg="#2C2C34", fg="white", bd=0, highlightthickness=0, font=("Helvetica", 12))
logs_listbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

def update_logs():
    logs_listbox.delete(0, tk.END)  # Clear existing logs
    try:
        with open('server.log', 'r') as file:
            logs = file.readlines()
        for log in logs:
            logs_listbox.insert(tk.END, log.strip())
    except FileNotFoundError:
        logs_listbox.insert(tk.END, "Error: server.log not found")

# Function to auto-update logs periodically
def auto_update_logs():
    update_logs()
    root.after(5000, auto_update_logs)  # Update every 5 seconds

# Initial log update
update_logs()

# Start auto-updating logs
auto_update_logs()

# Cache frame content
cache_list_frame.grid_rowconfigure(0, weight=1)
cache_list_frame.grid_rowconfigure(1, weight=1)
cache_list_frame.grid_rowconfigure(2, weight=1)
cache_list_frame.grid_rowconfigure(3, weight=1)
cache_list_frame.grid_rowconfigure(4, weight=1)
cache_list_frame.grid_rowconfigure(5, weight=1)
cache_list_frame.grid_rowconfigure(6, weight=1)
cache_list_frame.grid_rowconfigure(7, weight=1)
cache_list_frame.grid_rowconfigure(8, weight=1)

cache_listbox = tk.Listbox(cache_list_frame, bg="#2C2C34", fg="white", bd=0, highlightthickness=0, font=("Helvetica", 12))
cache_items = ["Cached Item 1", "Cached Item 2", "Cached Item 3"]
for item in cache_items:
    cache_listbox.insert(tk.END, item)
cache_listbox.grid(row=0, column=0, columnspan=3, rowspan=8, padx=10, pady=5, sticky="nsew")

def delete_cache_item():
    selected_items = cache_listbox.curselection()
    for item in selected_items[::-1]:
        cache_listbox.delete(item)

delete_cache_button = ctk.CTkButton(cache_list_frame, corner_radius=60, text="DELETE", fg_color="#238efa", hover_color="#FF81A6", command=delete_cache_item)
delete_cache_button.grid(row=8, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

# Ad Lists frame content
ad_list_frame.grid_rowconfigure(0, weight=1)  # Main row for input
ad_list_frame.grid_rowconfigure(1, weight=1)  # Main row for listbox
ad_list_frame.grid_rowconfigure(2, weight=1)  # Additional row
ad_list_frame.grid_rowconfigure(3, weight=1)  # Additional row
ad_list_frame.grid_rowconfigure(4, weight=1)  # Additional row
ad_list_frame.grid_rowconfigure(5, weight=1)  # Additional row
ad_list_frame.grid_rowconfigure(6, weight=1)
ad_list_frame.grid_rowconfigure(7, weight=1)  
ad_list_frame.grid_rowconfigure(8, weight=1)

ad_list_input = ctk.CTkEntry(ad_list_frame, placeholder_text="Add new ad domain", corner_radius=50)
ad_list_input.grid(row=0, column=0, columnspan=2, padx=5, pady=10, sticky="nsew")

ad_listbox = tk.Listbox(ad_list_frame, bg="#2C2C34", fg="white", bd=0, highlightthickness=0, font=("Helvetica", 12))
ad_domains = []

def update_ad_listbox():
    ad_listbox.delete(0, tk.END)  # Clear existing IPs
    try:
        with open('ad_domains.txt', 'r') as file:
            ads = file.readlines()
        for ad in ads:
            ad_listbox.insert(tk.END, ad.strip())
    except FileNotFoundError:
        ad_listbox.insert(tk.END, "Error: ad_domains.txt not found")

# def update_ad_listbox():
#     ad_listbox.delete(0, tk.END)  # Clear existing ad domains
#     try:
#         with open('ad_domains.txt', 'r') as file:
#             ad_domains.clear()  # Clear existing list
#             for line in file:
#                 domain = line.strip()
#                 if domain:  # Ensure the domain is not empty
#                     ad_domains.append(domain)
#                     ad_listbox.insert(tk.END, domain)
#                     print(f"Added domain from file: {domain}")  # Debugging info
#     except FileNotFoundError:
#         ad_listbox.insert(tk.END, "Error: ad_domains.txt not found")
#         print("Error: ad_domains.txt not found")  # Debugging info

# Initial update of ad listbox
update_ad_listbox()

# Function to add an ad domain to the list and file
def add_ad_list():
    new_ad = ad_list_input.get().strip()  # Remove leading/trailing whitespace
    if new_ad and new_ad not in ad_domains:  # Ensure non-empty and not a duplicate
        ad_listbox.insert(tk.END, new_ad)
        ad_domains.append(new_ad)
        ad_list_input.delete(0, tk.END)  # Clear the entry field after adding
        with open('ad_domains.txt', 'a') as file:
            file.write(new_ad + "\n")
        print(f"Added new domain: {new_ad}")  # Debugging info

add_ad_button = ctk.CTkButton(ad_list_frame, corner_radius=60, text="ADD", fg_color="#238efa", hover_color="#FF81A6", command=add_ad_list)
add_ad_button.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")

# Raise the initial frame
dashboard_frame.tkraise()

# Run the main loop
root.mainloop()
