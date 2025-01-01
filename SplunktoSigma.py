import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext, filedialog
import re
import os
import traceback
import logging
from uuid import uuid4
from datetime import date

# Configure logging
logging.basicConfig(
    filename="sigma_converter.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

DEFAULT_SIGMA_TEMPLATE = """
title: {title}
id: {id}
status: stable
description: {description}
references:
  - {references}
author: {author}
date: {date}
logsource:
  product: {product}
  service: {service}
detection:
  selection:
{fields}
  filter:
{filter_fields}
  condition: {condition}
falsepositives:
  - Unknown
level: {level}
"""

def load_template(template_file="sigma_template.txt"):
    if os.path.exists(template_file):
        with open(template_file, "r") as file:
            return file.read()
    return DEFAULT_SIGMA_TEMPLATE

def parse_eval_assigned_fields(query: str):
    assigned_fields = set()
    eval_statements = re.findall(r'\|\s*eval\s+([^\|]+)', query, re.IGNORECASE)
    for statement in eval_statements:
        potential_assignments = re.findall(r'(\w+)\s*=', statement)
        for field in potential_assignments:
            assigned_fields.add(field.strip())
    return assigned_fields

def parse_logsource(query):
    product = ", ".join(parse_field(query, "index"))
    service = ", ".join(parse_field(query, "sourcetype"))
    return product, service

def parse_field(query, field):
    values = set()
    eq_pattern = rf'{field}\s*=\s*["\']?([\w:]+)["\']?'
    eq_match = re.search(eq_pattern, query, re.IGNORECASE)
    if eq_match:
        values.add(eq_match.group(1).strip())
    in_pattern = rf'{field}\s+IN\s*\(\s*([^)]+)\s*\)'
    in_match = re.search(in_pattern, query, re.IGNORECASE)
    if in_match:
        for item in in_match.group(1).split(","):
            values.add(item.strip())
    return sorted(values)

def parse_selection_and_filter(query, eval_assigned_fields=None):
    if eval_assigned_fields is None:
        eval_assigned_fields = set()

    selection = {}
    filter_conditions = {}

    in_pattern = r'(\bNOT\s+)?(\w+)\s+IN\s*\(\s*([^)]+)\s*\)'
    all_in_matches = re.findall(in_pattern, query, re.IGNORECASE)
    for not_part, field, values_str in all_in_matches:
        values_list = [v.strip() for v in values_str.split(",")]
        if not_part and not_part.strip().upper() == "NOT":
            filter_conditions.setdefault(field, set()).update(values_list)
        else:
            if field not in eval_assigned_fields:
                selection.setdefault(field, set()).update(values_list)

    eq_pattern = r'(\w+)\s*=\s*["\']?([\w:]+)["\']?'
    eq_matches = re.findall(eq_pattern, query)
    for field, value in eq_matches:
        if field.lower() in ["index", "sourcetype"]:
            continue
        if field not in eval_assigned_fields:
            selection.setdefault(field, set()).add(value.strip())

    for k in selection:
        selection[k] = sorted(selection[k])
    for k in filter_conditions:
        filter_conditions[k] = sorted(filter_conditions[k])

    return selection, filter_conditions

def parse_eval(query):
    return re.findall(r'\|\s*eval\s+([^\|]+)', query, re.IGNORECASE)

def parse_stats_and_table(query):
    stats_matches = re.findall(r'\|\s*stats\s+([^\|]+)', query, re.IGNORECASE)
    table_matches = re.findall(r'\|\s*table\s+([^\|]+)', query, re.IGNORECASE)
    return stats_matches, table_matches

def convert_to_sigma(splunk_query, template_file="sigma_template.txt"):
    try:
        sigma_template = load_template(template_file)

        title = "Converted Splunk Detection"
        rule_id = str(uuid4())
        description = "Automatically converted Splunk detection rule."
        references = "https://example.com/reference"
        author = "Sigma Parser"
        date_created = date.today().isoformat()
        level = "medium"

        eval_assigned_fields = parse_eval_assigned_fields(splunk_query)
        product, service = parse_logsource(splunk_query)
        selection, filter_conditions = parse_selection_and_filter(
            splunk_query,
            eval_assigned_fields
        )
        eval_statements = parse_eval(splunk_query)

        # We won't include stats in final output, but we parse them anyway
        stats_statements, table_statements = parse_stats_and_table(splunk_query)

        # Build YAML for selection
        fields_lines = []
        for field, values in selection.items():
            fields_lines.append(f"    {field}:")
            for value in values:
                fields_lines.append(f"      - '{value}'")
        fields_yaml = "\n".join(fields_lines)

        # Build YAML for filter
        if filter_conditions:
            filter_lines = []
            for field, values in filter_conditions.items():
                filter_lines.append(f"    {field}:")
                for value in values:
                    filter_lines.append(f"      - '{value}'")
            filter_yaml = "\n".join(filter_lines)
            condition = "selection and not filter"
        else:
            filter_yaml = "    - 'none'"
            condition = "selection"

        # Build YAML for eval
        eval_yaml_lines = []
        if eval_statements:
            eval_yaml_lines.append("    eval:")
            for expr in eval_statements:
                eval_yaml_lines.append(f"      - {expr}")
        eval_yaml = "\n".join(eval_yaml_lines)

        # Combine selection + eval (no stats)
        blocks = []
        if fields_yaml.strip():
            blocks.append(fields_yaml)
        if eval_yaml.strip():
            blocks.append(eval_yaml)

        final_fields_yaml = "\n".join(blocks)
        if final_fields_yaml:
            final_fields_yaml = "\n" + final_fields_yaml
        if filter_yaml.strip():
            filter_yaml = "\n" + filter_yaml

        sigma_rule = sigma_template.format(
            title=title,
            id=rule_id,
            description=description,
            references=references,
            author=author,
            date=date_created,
            product=product or "generic",
            service=service or "generic",
            fields=final_fields_yaml,
            filter_fields=filter_yaml,
            condition=condition,
            level=level
        )

        return sigma_rule

    except Exception as e:
        logging.error("Error in convert_to_sigma: %s", traceback.format_exc())
        raise ValueError(f"Error in conversion: {e}")

def convert_action():
    try:
        input_text = input_box.get("1.0", tk.END).strip()
        if input_text:
            sigma_rule = convert_to_sigma(input_text)
            output_box.delete("1.0", tk.END)
            output_box.insert(tk.END, sigma_rule)
        else:
            output_box.delete("1.0", tk.END)
            output_box.insert(tk.END, "No input provided to convert.")
    except Exception as e:
        logging.error("Error in convert_action: %s", traceback.format_exc())
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, "An error occurred during conversion. Please check the logs.")

def save_action():
    try:
        output_text = output_box.get("1.0", tk.END).strip()
        if output_text:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".yml",
                filetypes=[("YAML files", "*.yml"), ("All files", "*.*")]
            )
            if file_path:
                with open(file_path, "w") as file:
                    file.write(output_text)
        else:
            output_box.insert(tk.END, "\nNo output to save.")
    except Exception as e:
        logging.error("Error in save_action: %s", traceback.format_exc())
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, "An error occurred while saving the file. Please check the logs.")

def load_action():
    try:
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            with open(file_path, "r") as file:
                input_text = file.read()
                input_box.delete("1.0", tk.END)
                input_box.insert(tk.END, input_text)
    except Exception as e:
        logging.error("Error in load_action: %s", traceback.format_exc())
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, "An error occurred while loading the file. Please check the logs.")

# ----------------------------
# Modern GUI Setup
# ----------------------------
root = tk.Tk()
root.title("Splunk to Sigma Converter")
root.geometry("900x600")   # Increase width for a more spacious layout
root.minsize(600, 400)

# Use a modern theme
style = ttk.Style()
# 'clam', 'default', 'alt', 'classic', 'vista', 'xpnative' are built-in
style.theme_use("clam")

# Set a dark background for root
root.configure(bg="#1f1f1f")

# Configure TFrame with a dark background
style.configure("TFrame", background="#1f1f1f")

# Configure the TButton for a modern dark style
style.configure(
    "TButton",
    background="#344955",
    foreground="#ffffff",
    borderwidth=0,
    font=("Helvetica", 10, "bold"),
    focuscolor="none"
)
style.map(
    "TButton",
    background=[("active", "#4a6572")],
    relief=[("pressed", "groove"), ("!pressed", "ridge")]
)

# If you had labels, you'd style them like this:
style.configure(
    "TLabel",
    background="#1f1f1f",
    foreground="#ffffff",
    font=("Arial", 12)
)

# Frame to hold the text boxes
main_frame = ttk.Frame(root)
main_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)

# Create a modern ScrolledText for input
input_box = scrolledtext.ScrolledText(
    main_frame,
    wrap=tk.WORD,
    bg="#2b2b2b",
    fg="#ffffff",
    font=("Arial", 12),
    insertbackground="white",
    borderwidth=0
)
input_box.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

# Create a modern ScrolledText for output
output_box = scrolledtext.ScrolledText(
    main_frame,
    wrap=tk.WORD,
    bg="#2b2b2b",
    fg="#ffffff",
    font=("Arial", 12),
    insertbackground="white",
    borderwidth=0
)
output_box.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

# Button frame
button_frame = ttk.Frame(root)
button_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=10)

convert_button = ttk.Button(button_frame, text="Convert", command=convert_action)
convert_button.pack(side="left", padx=5)

copy_button = ttk.Button(
    button_frame,
    text="Copy",
    command=lambda: root.clipboard_append(output_box.get("1.0", tk.END))
)
copy_button.pack(side="left", padx=5)

save_button = ttk.Button(button_frame, text="Save", command=save_action)
save_button.pack(side="left", padx=5)

load_button = ttk.Button(button_frame, text="Load", command=load_action)
load_button.pack(side="left", padx=5)

# Make the text boxes resize with the window
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(0, weight=1)

# Also make the main_frame expand
main_frame.grid_rowconfigure(0, weight=1)
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=1)

root.mainloop()
