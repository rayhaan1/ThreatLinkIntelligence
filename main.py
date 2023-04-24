import os
import re
import sys
import tkinter as tk
from tkinter import ttk
import csv
import json

# Create a new tkinter window
window = tk.Tk()

# Set the title of the window
window.title("Select Profile")

# Set the size of the window
window.geometry("550x350")

# Create a label with a welcome message
label = tk.Label(window, text="Welcome to ThreatLink Intelligence", font=("Arial Bold", 20))
label.pack(pady=20)

# Define the path to the CSV files
CTI_DATA_FILE = "CTIData.csv"
APT_DATA_FILE = "APTData.csv"

# Use regular expression to match any file ending in ".json"
json_pattern = re.compile(r'.+\.json$')

# Specify the directory containing the JSON files
app_dir = os.path.dirname(sys.argv[0])
json_dir = os.path.join(app_dir)

# Find all files in the directory that match the pattern
INCIDENT_DATA_FILES = [f for f in os.listdir(json_dir) if json_pattern.match(f)]


def get_headers(profile):
    return {
        "Analyst": {
            "cti": ["Attack Name", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol",
                    "Attack Reference"],
            "apt": ["Common Name", "Toolset"],
        },
        "Management": {
            "cti": ["Attack Name", "Attack category"],
            "apt": ["Common Name", "Other Names", "Targets", "Modus Operandi", "Comment", "Link 1", "Link 2"],
        },
        "CSIRT": {
            "cti": ["Attack Name", "Attack category", "Attack subcategory", "Attack Reference"],
            "apt": ["Common Name", "Other Names", "Operations", "Targets", "Modus Operandi", "Comment", "Link 1",
                    "Link 2"],
        }
    }.get(profile, {})


def load_csv_data(file, headers):
    data = []

    with open(file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            data.append({header: row[header] for header in headers})

    return data


def load_json_data(files, user_role):
    all_objects = []
    type_mapping = {
        "Analyst": ["indicator", "malware", "vulnerability", "infrastructure"],
        "Management": ["attack-pattern", "identity", "location", "threat-actor", "campaign"],
        "CSIRT": ["attack-pattern", "identity", "incident", "malware", "threat-actor", "location", "vulnerability", "indicator", "infrastructure"],
    }

    types_to_display = type_mapping.get(user_role, [])

    for file in files:
        with open(file, 'r') as jsonfile:
            incident_data = json.load(jsonfile)
        objects = [obj for obj in incident_data.get("objects", []) if obj.get("type") in types_to_display]
        all_objects.extend(objects)

    return all_objects


def create_treeview(parent, headers):
    tree = ttk.Treeview(parent, columns=headers, show="headings", height=20)
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    num_headers = len(headers)
    for header in headers:
        tree.heading(header, text=header, anchor=tk.W)
        tree.column(header, anchor=tk.W, stretch=True)

    v_scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
    v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    tree.configure(yscrollcommand=v_scrollbar.set)

    h_scrollbar = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
    h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
    tree.configure(xscrollcommand=h_scrollbar.set)

    # Bind a function to update the column widths when the window is resized
    def on_treeview_resize(event):
        new_width = tree.winfo_width()
        for treeHeader in headers:
            tree.column(treeHeader, width=(new_width // num_headers) - 2)

    tree.bind("<Configure>", on_treeview_resize)

    return tree


def display_data_in_treeview(treeview, data, headers):
    for row in data:
        values = tuple(row[header] for header in headers)
        treeview.insert("", tk.END, values=values)


def preprocess_stix_data(stix_data):
    headers = ["Type", "Name", "ID", "Description", "Created", "Modified", "Aliases", "Region", "Sophistication",
               "Resource Level", "Primary Motivation"]

    processed_data = []

    for obj in stix_data:
        row_data = {}
        for field in headers:
            key = field.lower().replace(" ", "_")
            row_data[field] = obj.get(key, "")
        processed_data.append(row_data)

    return processed_data, headers


def select_profile(profile):
    # Create a new window to display the data
    data_window = tk.Toplevel(window)
    data_window.title(profile + " Data")
    data_window.geometry("800x400")
    # data_window.rowconfigure(0, weight=1)  # Make the row expandable
    # data_window.columnconfigure(0, weight=1)  # Make the column expandable

    headers = get_headers(profile)
    cti_headers = headers["cti"]
    apt_headers = headers["apt"]

    notebook = ttk.Notebook(data_window)
    notebook.pack(fill=tk.BOTH, expand=True)

    cti_frame = ttk.Frame(notebook)
    apt_frame = ttk.Frame(notebook)
    stix_frame = ttk.Frame(notebook)

    notebook.add(cti_frame, text="CTI Data")
    notebook.add(apt_frame, text="APT Data")
    notebook.add(stix_frame, text="STIX Incident Data")

    cti_tree = create_treeview(cti_frame, cti_headers)
    apt_tree = create_treeview(apt_frame, apt_headers)

    try:
        cti_data = load_csv_data(CTI_DATA_FILE, cti_headers)
        apt_data = load_csv_data(APT_DATA_FILE, apt_headers)
        stix_data = load_json_data(INCIDENT_DATA_FILES, profile)

        display_data_in_treeview(cti_tree, cti_data, cti_headers)
        display_data_in_treeview(apt_tree, apt_data, apt_headers)

        processed_stix_data, stix_headers = preprocess_stix_data(stix_data)
        stix_tree = create_treeview(stix_frame, stix_headers)
        display_data_in_treeview(stix_tree, processed_stix_data, stix_headers)

    except (FileNotFoundError, csv.Error) as e:
        print("Error: " + str(e))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print("Error: " + str(e))


# Create buttons for profiles
button_frame = tk.Frame(window)
button_frame.pack(pady=20)

analyst_button = tk.Button(button_frame, text="Analyst", command=lambda: select_profile("Analyst"),
                           font=("Arial", 16), width=12)
analyst_button.grid(row=0, column=0, padx=5, pady=5)

management_button = tk.Button(button_frame, text="Management", command=lambda: select_profile("Management"),
                              font=("Arial", 16), width=12)
management_button.grid(row=0, column=1, padx=5, pady=5)

csirt_button = tk.Button(button_frame, text="CSIRT", command=lambda: select_profile("CSIRT"),
                         font=("Arial", 16), width=12)
csirt_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

# start tkinter loop
window.mainloop()
