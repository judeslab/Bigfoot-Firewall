#!/usr/bin/env python3
import subprocess
import tkinter as tk
from tkinter import ttk

def execute_subprocess_command(command, expect_output=False):
    """
    Execute a subprocess command securely and handle output.
    """
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if expect_output:
            return result.stdout.splitlines()
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error executing command '{command}': {e}")
        return None

def refresh_iptables_rules():
    iptables_rules_table.delete(*iptables_rules_table.get_children())
    load_iptables_rules()

def load_iptables_rules():
    chains = ['INPUT', 'OUTPUT', 'FORWARD']
    for chain in chains:
        lines = execute_subprocess_command(['sudo', 'iptables', '-L', chain, '--line-numbers', '-n'], expect_output=True)
        if lines:
            for line in lines[2:]:  # Skip the headers
                parts = line.split()
                rule_number, action, protocol = parts[0], parts[1], parts[2]
                source, destination = "any", "any"  # Defaults
                src_port, dest_port = "all", "all"  # Defaults

                if "spt:" in line:
                    src_port = line.split("spt:")[1].split()[0]
                if "dpt:" in line:
                    dest_port = line.split("dpt:")[1].split()[0]
                
                source = parts[4] if parts[4] != '0.0.0.0/0' else 'any'
                destination = parts[5] if parts[5] != '0.0.0.0/0' else 'any'

                iptables_rules_table.insert('', 'end', values=(rule_number, chain, protocol, source, src_port, destination, dest_port, action))

def validate_input(input_str, default):
    """
    Validate user inputs for IP addresses, ports, etc.
    Placeholder for actual validation logic.
    """
    return input_str if input_str.lower() not in ['any', 'anything'] else default

def add_rule():
    protocol = protocol_var.get()
    source_ip = validate_input(source_ip_entry.get(), '0.0.0.0/0')
    destination_ip = validate_input(destination_ip_entry.get(), '0.0.0.0/0')
    direction = direction_var.get().upper()
    accept_reject = accept_reject_var.get().upper()

    command = ['sudo', 'iptables', '-A', direction, '-p', protocol, '-s', source_ip, '-d', destination_ip, '-j', accept_reject]

    # Only add port specifications for TCP or UDP protocols
    if protocol in ['tcp', 'udp']:
        source_port = validate_input(source_port_entry.get(), '0:65535')
        destination_port = validate_input(destination_port_entry.get(), '0:65535')
        command.extend(['--sport', source_port, '--dport', destination_port])

    execute_subprocess_command(command)
    refresh_iptables_rules()

def delete_rule():
    selected_item = iptables_rules_table.selection()
    if selected_item:
        item = iptables_rules_table.item(selected_item[0])
        rule_number, chain = item['values'][0], item['values'][1]
        command = ['sudo', 'iptables', '-D', chain, str(rule_number)]
        result = execute_subprocess_command(command)
        if result is None:
            refresh_iptables_rules()
        else:
            print("Error deleting rule.")

def delete_all_rules():
    command = ['sudo', 'iptables', '-F']
    execute_subprocess_command(command)
    refresh_iptables_rules()

# GUI Setup
window = tk.Tk()
window.title("Bigfoot Firewall")
window.configure(background='black')  # Set window background to black

# Darker theme with green
style = ttk.Style()
style.theme_use('clam')  # Change 'clam' to another theme if desired

# Define custom colors
style.configure('Treeview', background='#334d4d', foreground='white', fieldbackground='#334d4d')
style.map('Treeview', background=[('selected', '#134d4d')])

container = tk.Frame(window, background='black')  # Set container frame background to black
container.pack(fill=tk.BOTH, expand=True)

container.grid_columnconfigure(0, weight=1)
container.grid_rowconfigure(0, weight=1)  # Gives table frame ability to expand vertically
container.grid_rowconfigure(1, weight=0)  # Keeps input options fixed height
container.grid_rowconfigure(2, weight=0)  # Keeps buttons fixed height

# Table Frame
iptables_rules_table_frame = tk.Frame(container, background='black')  # Set table frame background to black
iptables_rules_table_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

scrollbar = ttk.Scrollbar(iptables_rules_table_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

iptables_rules_table = ttk.Treeview(iptables_rules_table_frame, columns=('Rule No.', 'Direction', 'Protocol', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Accept or Reject'), yscrollcommand=scrollbar.set, show='headings', style='Treeview')
for heading in iptables_rules_table['columns']:
    iptables_rules_table.heading(heading, text=heading)
iptables_rules_table.pack(fill=tk.BOTH, expand=True)

scrollbar.config(command=iptables_rules_table.yview)

# Input Options Frame
input_options_frame = tk.Frame(container, background='black')  # Set input options frame background to black
input_options_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
container.grid_columnconfigure(0, weight=1)

# Direction Button for INPUT/OUTPUT/FORWARD
direction_label = tk.Label(input_options_frame, text="Direction:", background='black', foreground='white')  # Set label background to black
direction_label.pack(side='left')
direction_var = tk.StringVar(value="INPUT")
direction_option = tk.OptionMenu(input_options_frame, direction_var, "INPUT", "OUTPUT", "FORWARD")
direction_option.pack(side='left', padx=5)

# Protocol Button for TCP/UDP/ICMP
protocol_label = tk.Label(input_options_frame, text="Protocol:", background='black', foreground='white')  # Set label background to black
protocol_label.pack(side='left')
protocol_var = tk.StringVar(value="tcp")
protocol_option = tk.OptionMenu(input_options_frame, protocol_var, "tcp", "udp", "icmp")
protocol_option.pack(side='left', padx=5)

# Source IP Entry
source_ip_label = tk.Label(input_options_frame, text="Source IP:", background='black', foreground='white')  # Set label background to black
source_ip_label.pack(side='left')
source_ip_entry = tk.Entry(input_options_frame)
source_ip_entry.pack(side='left', padx=5)

# Source Port Entry
source_port_label = tk.Label(input_options_frame, text="Source Port:", background='black', foreground='white')  # Set label background to black
source_port_label.pack(side='left')
source_port_entry = tk.Entry(input_options_frame)
source_port_entry.pack(side='left', padx=5)

# Destination IP Entry
destination_ip_label = tk.Label(input_options_frame, text="Destination IP:", background='black', foreground='white')  # Set label background to black
destination_ip_label.pack(side='left')
destination_ip_entry = tk.Entry(input_options_frame)
destination_ip_entry.pack(side='left', padx=5)

# Destination Port Entry
destination_port_label = tk.Label(input_options_frame, text="Destination Port:", background='black', foreground='white')  # Set label background to black
destination_port_label.pack(side='left')
destination_port_entry = tk.Entry(input_options_frame)
destination_port_entry.pack(side='left', padx=5)

# ACCEPT / REJECT Traffic Button
accept_reject_label = tk.Label(input_options_frame, text="Action:", background='black', foreground='white')  # Set label background to black
accept_reject_label.pack(side='left')
accept_reject_var = tk.StringVar(value="ACCEPT")
accept_reject_option = tk.OptionMenu(input_options_frame, accept_reject_var, "ACCEPT", "REJECT")
accept_reject_option.pack(side='left', padx=5)

# Button Frame
button_frame = tk.Frame(container, background='black')  # Set button frame background to black
button_frame.grid(row=2, column=0, sticky="ew")
button_frame.grid_columnconfigure(0, weight=1)
button_frame.grid_columnconfigure(1, weight=1)

# Left-aligned buttons container
left_button_frame = tk.Frame(button_frame, background='black')  # Set left button frame background to black
left_button_frame.grid(row=0, column=0, sticky="w", padx=5)

# Right-aligned buttons container
right_button_frame = tk.Frame(button_frame, background='black')  # Set right button frame background to black
right_button_frame.grid(row=0, column=1, sticky="e", padx=5)

# Delete Rule Button
delete_rule_button = tk.Button(right_button_frame, text="Delete Rule")
delete_rule_button.pack(side='right', padx=5)

# Add Rule Button
add_rule_button = tk.Button(right_button_frame, text="Add Rule")
add_rule_button.pack(side='right', padx=5)

# Delete ALL RULES Button
delete_all_button = tk.Button(left_button_frame, text="Delete All Rules")
delete_all_button.pack(side='left', padx=5)

# Placeholder functions
def delete_rule():
    pass

def add_rule():
    pass

def delete_all_rules():
    pass

def load_iptables_rules():
    pass

load_iptables_rules()

window.mainloop()