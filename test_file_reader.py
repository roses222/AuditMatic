# CC - Creating a test script to try and make the Audit tool more universal. 
# file_reader.py is the original script 

import pandas as pd
import sys
import re

try:
    from test_utils import get_x  # type: ignore[reportMissingImports]
except Exception:
    def get_x(_df):
        return {}

def extract_path(version_location):
    # Regex pattern to match a drive letter and the rest of a file path leading up to the '>' symbol
    match = re.match(r'([A-Za-z]:[\\/].*?)(?=\s*>)', version_location)
    if match:
        return match.group(1)  # Return the matching path
    else:
        return 

def read_software_list(file_path):
    # SBL name
    # Include the SBL name the report was run based off of.
    print(file_path)


    # Columns of interest from SBL
    # CC - Change to a dict to allow adding or subtracting of columns of interest?
    id_number = 'CM TOOL ID NUMBER'
    software_component = 'SOFTWARE COMPONENT'

    # CC - temp test to see which way will make the script more general will little mutation. Assigning displayed_name with software component bc there will 
    # always be a software component column. Will compare with registry display names and update later if component name percent matches display name
    # displayed_name = 'DISPLAYED NAME'
    displayed_name = software_component
    # version_location = 'VERSION LOCATION'
    version_location = 'VERSION LOCATIONS'

    # # CC - Since column names can be different we need to find a way to grab the important ones from each excel
    # SBL_ColumnsOI = dict(id_number = 'CM TOOL ID NUMBER',
    # software_component = 'SOFTWARE COMPONENT',
    # displayed_name = 'DISPLAYED NAME',
    # version_location = 'VERSION LOCATION')

    print("Reading Software Build List")
    software_list = []
    
    # Read the excel file, drop rows with missing values, trim whitespace, and get the path to the file
    if file_path.endswith('.xlsx'):
        df = pd.read_excel(file_path, header=1)
        get_xs= get_x(df)
        if get_xs:
            
            print("Columns with 'x' or 'X' and their corresponding rows:")
            for column, rows in get_xs.items():
                print(f"  Column: {column}, Rows: {rows} \n")
        else:
            print("No 'x' or 'X' found in the Excel file.")
            
        df = df.dropna(subset=[id_number, software_component])
        ## CC - Capture all header names.
        df_headers = list(df.columns)
        normalized_headers = [str(h).lower() for h in df_headers]

        ## Find columns of interest by finding headers that contain key words. Location, Version, etc
        keywords = ["location", "component", "name", "id"]

        matching_headers = [og for og, norm in zip(df_headers, normalized_headers) if any(k in norm for k in keywords)]
        print(matching_headers)

        # Find columns with

        df[software_component] = df[software_component].str.strip()
        # CC - Different xlsx have different styles of path instructions. As of rn extract_path will not work with all.
        # CC - Testing process without this location since it looks like script runs a registry search. 
        # df[version_location] = df[version_location].apply(extract_path)
         
        df[displayed_name] = df[displayed_name].str.strip()
        
    else:
        print(f"Unsupported file format: {file_path}")
        sys.exit(1)
    
    # Match the column that contains the version number
    pattern = r'.*CURRENT CI VERSION.*'
    matching_column = next((col for col in df.columns if re.match(pattern, col, re.IGNORECASE)), None)

    # If the matching column is found, process the rows 
    if matching_column:
        for _, row in df.iterrows():
            software_list.append({
                'name': row[software_component],
                'displayed_name': row[displayed_name],
                'expected_version': row[matching_column],
                'version_location': row[version_location]
            })
    else:
        print("No column found with 'CURRENT CI VERSION' in the name.")

    return software_list

