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
    """
    Clear existing items from the iptables rules table and reload them.
    """
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

container = tk.Frame(window)
container.pack(fill=tk.BOTH, expand=True)

iptables_rules_table_frame = tk.Frame(container)
iptables_rules_table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

scrollbar = ttk.Scrollbar(iptables_rules_table_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

iptables_rules_table = ttk.Treeview(iptables_rules_table_frame, columns=('Rule No.', 'Direction', 'Protocol', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Accept or Reject'), yscrollcommand=scrollbar.set, show='headings')
for heading in iptables_rules_table['columns']:
    iptables_rules_table.heading(heading, text=heading)
iptables_rules_table.pack(fill=tk.BOTH, expand=True)

scrollbar.config(command=iptables_rules_table.yview)

input_options_frame = tk.Frame(container)
input_options_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

direction_label = tk.Label(input_options_frame, text="Direction:")
direction_label.pack(side='left')
direction_var = tk.StringVar()
direction_var.set("Input")
direction_option = tk.OptionMenu(input_options_frame, direction_var, "Input", "Output", "Forward")
direction_option.pack(side='left')

protocol_label = tk.Label(input_options_frame, text="Protocol:")
protocol_label.pack(side='left')
protocol_var = tk.StringVar()
protocol_var.set("tcp")
protocol_option = tk.OptionMenu(input_options_frame, protocol_var, "tcp", "udp", "icmp")  # Added "icmp"
protocol_option.pack(side='left')

# Main container for buttons
button_frame = tk.Frame(container)
button_frame.pack(fill=tk.X, expand=True, side='bottom')

# Left-aligned buttons container
left_button_frame = tk.Frame(button_frame)
left_button_frame.pack(side='left', padx=5, pady=5)

# Right-aligned buttons container
right_button_frame = tk.Frame(button_frame)
right_button_frame.pack(side='right', padx=5, pady=5)

# Delete All Rules Button (Far Bottom Left)
delete_all_button = tk.Button(left_button_frame, text="Delete All Rules", command=delete_all_rules, relief="raised", bd=2)
delete_all_button.pack(side='left')

# Delete Rule Button (Far Bottom Right)
delete_rule_button = tk.Button(right_button_frame, text="Delete Rule", command=delete_rule, relief="raised", bd=2)
delete_rule_button.pack(side='right')

# Add Rule Button (To the left of "Delete Rule")
add_rule_button = tk.Button(right_button_frame, text="Add Rule", command=add_rule, relief="raised", bd=2)
add_rule_button.pack(side='right')

source_ip_label = tk.Label(input_options_frame, text="Source IP:")
source_ip_label.pack(side='left')
source_ip_entry = tk.Entry(input_options_frame, relief="solid", bd=2)
source_ip_entry.pack(side='left')

source_port_label = tk.Label(input_options_frame, text="Source Port (optional):")
source_port_label.pack(side='left')
source_port_entry = tk.Entry(input_options_frame, relief="solid", bd=2)
source_port_entry.pack(side='left')

destination_ip_label = tk.Label(input_options_frame, text="Destination IP:")
destination_ip_label.pack(side='left')
destination_ip_entry = tk.Entry(input_options_frame, relief="solid", bd=2)
destination_ip_entry.pack(side='left')

destination_port_label = tk.Label(input_options_frame, text="Destination Port (optional):")
destination_port_label.pack(side='left')
destination_port_entry = tk.Entry(input_options_frame, relief="solid", bd=2)
destination_port_entry.pack(side='left')

accept_reject_label = tk.Label(input_options_frame, text="Accept or Reject:")
accept_reject_label.pack(side='left')
accept_reject_var = tk.StringVar()
accept_reject_var.set("ACCEPT")
accept_reject_option = tk.OptionMenu(input_options_frame, accept_reject_var, "ACCEPT", "REJECT")
accept_reject_option.pack(side='left')

load_iptables_rules()

container.grid_columnconfigure(0, weight=1)
container.grid_rowconfigure(0, weight=1)

window.mainloop()
