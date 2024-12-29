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
    """
    Loads a Sigma template from a file or defaults to the hardcoded template.
    """
    if os.path.exists(template_file):
        with open(template_file, "r") as file:
            return file.read()
    return DEFAULT_SIGMA_TEMPLATE

def parse_eval_assigned_fields(query: str):
    """
    Extracts all fields that are assigned within eval statements.
    e.g. '| eval name = last . "," . first, user=if(user,user,"none")'
    returns {'name', 'user'}
    """
    assigned_fields = set()
    eval_statements = re.findall(r'\|\s*eval\s+([^\|]+)', query, re.IGNORECASE)
    for statement in eval_statements:
        potential_assignments = re.findall(r'(\w+)\s*=', statement)
        for field in potential_assignments:
            assigned_fields.add(field.strip())
    return assigned_fields

def parse_logsource(query):
    """
    Extracts `index` and `sourcetype` for the logsource section.
    """
    product = ", ".join(parse_field(query, "index"))
    service = ", ".join(parse_field(query, "sourcetype"))
    return product, service

def parse_field(query, field):
    """
    Looks for <field>= or <field> IN(...) 
    specifically for logsource fields (index, sourcetype).
    """
    values = set()

    # <field>=<value>
    eq_pattern = rf'{field}\s*=\s*["\']?([\w:]+)["\']?'
    eq_match = re.search(eq_pattern, query, re.IGNORECASE)
    if eq_match:
        values.add(eq_match.group(1).strip())

    # <field> IN(...)
    in_pattern = rf'{field}\s+IN\s*\(\s*([^)]+)\s*\)'
    in_match = re.search(in_pattern, query, re.IGNORECASE)
    if in_match:
        for item in in_match.group(1).split(","):
            values.add(item.strip())

    return sorted(values)

def parse_selection_and_filter(query, eval_assigned_fields=None):
    """
    Extracts fields for selection and filter sections.
      - Values from <field>=<value> or <field> IN(...) => selection
      - Values from NOT <field> IN(...) => filter
      - Fields in eval_assigned_fields are skipped from selection
    """
    if eval_assigned_fields is None:
        eval_assigned_fields = set()

    selection = {}
    filter_conditions = {}

    # 1) "[NOT ] <field> IN(...)"
    in_pattern = r'(\bNOT\s+)?(\w+)\s+IN\s*\(\s*([^)]+)\s*\)'
    all_in_matches = re.findall(in_pattern, query, re.IGNORECASE)
    for not_part, field, values_str in all_in_matches:
        values_list = [v.strip() for v in values_str.split(",")]
        if not_part and not_part.strip().upper() == "NOT":
            filter_conditions.setdefault(field, set()).update(values_list)
        else:
            # Skip if field is assigned via eval
            if field not in eval_assigned_fields:
                selection.setdefault(field, set()).update(values_list)

    # 2) <field>=<value>
    eq_pattern = r'(\w+)\s*=\s*["\']?([\w:]+)["\']?'
    eq_matches = re.findall(eq_pattern, query)
    for field, value in eq_matches:
        # Skip known logsource fields
        if field.lower() in ["index", "sourcetype"]:
            continue
        # Skip if assigned in eval
        if field not in eval_assigned_fields:
            selection.setdefault(field, set()).add(value.strip())

    # Convert sets to sorted lists
    for k in selection:
        selection[k] = sorted(selection[k])
    for k in filter_conditions:
        filter_conditions[k] = sorted(filter_conditions[k])

    return selection, filter_conditions

def parse_eval(query):
    """
    Extracts eval expressions from the query.
    """
    return re.findall(r'\|\s*eval\s+([^\|]+)', query, re.IGNORECASE)

def parse_stats_and_table(query):
    """
    Extracts stats and table statements from the query.
    Returns (stats_statements, table_statements).
    """
    stats_matches = re.findall(r'\|\s*stats\s+([^\|]+)', query, re.IGNORECASE)
    table_matches = re.findall(r'\|\s*table\s+([^\|]+)', query, re.IGNORECASE)
    return stats_matches, table_matches

def convert_to_sigma(splunk_query, template_file="sigma_template.txt"):
    """
    Converts a Splunk detection query into a Sigma rule format with correct YAML indentation.
    """
    try:
        sigma_template = load_template(template_file)

        # == Metadata fields ==
        title = "Converted Splunk Detection"
        rule_id = str(uuid4())
        description = "Automatically converted Splunk detection rule."
        references = "https://example.com/reference"
        author = "Sigma Parser"
        date_created = date.today().isoformat()
        level = "medium"

        # == 1) Evals assigned fields ==
        eval_assigned_fields = parse_eval_assigned_fields(splunk_query)

        # == 2) Parse logsource ==
        product, service = parse_logsource(splunk_query)

        # == 3) Build selection/filter ==
        selection, filter_conditions = parse_selection_and_filter(
            splunk_query,
            eval_assigned_fields
        )

        # == 4) Extract eval statements ==
        eval_statements = parse_eval(splunk_query)

        # == 5) Extract stats statements (ignore table in final YAML) ==
        stats_statements, table_statements = parse_stats_and_table(splunk_query)

        # ---------------------------------------------------
        # Build the YAML for selection fields
        # ---------------------------------------------------
        # We want each field to start 4 spaces in, list items 6 spaces in.
        #
        # Example:
        # detection:
        #   selection:
        #     EventCode:
        #       - '4688'
        #     ComputerName:
        #       - 'laptop'
        #
        fields_lines = []
        for field, values in selection.items():
            fields_lines.append(f"    {field}:")
            for value in values:
                fields_lines.append(f"      - '{value}'")

        # Join them with newlines
        fields_yaml = "\n".join(fields_lines)

        # ---------------------------------------------------
        # Build the YAML for filter fields
        # ---------------------------------------------------
        if filter_conditions:
            filter_lines = []
            for field, values in filter_conditions.items():
                filter_lines.append(f"    {field}:")
                for value in values:
                    filter_lines.append(f"      - '{value}'")
            filter_yaml = "\n".join(filter_lines)
            condition = "selection and not filter"
        else:
            # Indent consistently under 'filter:'
            filter_yaml = "    - 'none'"
            condition = "selection"

        # ---------------------------------------------------
        # Build the YAML for eval statements
        # ---------------------------------------------------
        # Similar indentation: 4 spaces for the key, 6 spaces for the list item.
        eval_yaml_lines = []
        if eval_statements:
            eval_yaml_lines.append("    eval:")
            for expr in eval_statements:
                eval_yaml_lines.append(f"      - {expr}")
        eval_yaml = "\n".join(eval_yaml_lines)

        # ---------------------------------------------------
        # Build the YAML for stats statements
        # ---------------------------------------------------
        stats_yaml_lines = []
        if stats_statements:
            stats_yaml_lines.append("    stats:")
            for stat in stats_statements:
                stats_yaml_lines.append(f"      - {stat}")
        stats_yaml = "\n".join(stats_yaml_lines)

        # ---------------------------------------------------
        # Combine selection, eval, stats into final selection block
        # ---------------------------------------------------
        # We'll place them in the order: fields -> eval -> stats.
        blocks = []
        if fields_yaml.strip():
            blocks.append(fields_yaml)
        if eval_yaml.strip():
            blocks.append(eval_yaml)
        if stats_yaml.strip():
            blocks.append(stats_yaml)

        # Now we combine them with a newline separating each block
        final_fields_yaml = "\n".join(blocks)

        # IMPORTANT: Prepend a newline so that the first line 
        # appears on the next line after "selection:" in the template.
        if final_fields_yaml:
            final_fields_yaml = "\n" + final_fields_yaml

        # Similarly, prepend a newline for filter, so it appears under "filter:"
        if filter_yaml.strip():
            filter_yaml = "\n" + filter_yaml

        # Insert into the template
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
    """
    Triggered by the "Convert" button.
    """
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
    """
    Saves the converted Sigma rule to a file.
    """
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
    """
    Loads a Splunk detection query from a file into the input box.
    """
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

# GUI Setup
root = tk.Tk()
root.title("Splunk to Sigma Converter")
root.configure(bg="#2c2c2c")
root.geometry("800x600")
root.minsize(600, 400)

style = ttk.Style()
style.theme_use("default")
style.configure(
    "TButton",
    background="#228B22",
    foreground="#ffffff",
    font=("Arial", 12),
    padding=5,
    borderwidth=0
)
style.map("TButton", background=[("active", "#006400")])

input_box = scrolledtext.ScrolledText(
    root, wrap=tk.WORD,
    bg="#3b3b3b",
    fg="#ffffff",
    font=("Arial", 12),
    insertbackground="white"
)
input_box.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

output_box = scrolledtext.ScrolledText(
    root, wrap=tk.WORD,
    bg="#3b3b3b",
    fg="#ffffff",
    font=("Arial", 12),
    insertbackground="white"
)
output_box.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

button_frame = tk.Frame(root, bg="#2c2c2c")
button_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky="ew")

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

root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(0, weight=1)

root.mainloop()
