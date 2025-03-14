import argparse
import csv
import json
from collections import Counter

def main():

    # Prompt for input
    input_filename = input("Input CSV filename with T-numbers: ")
    output_filename = input("Output JSON filename for ATT&CK Navigator layer: ")

    if not input_filename:
        raise ValueError("No input file name provided. Please run the script again and provide a valid file name.")
    if not output_filename:
        raise ValueError("No output file name provided. Please run the script again and provide a valid file name.")

    # read the CSV file and count the techniques
    techniques = []
    with open(input_filename, 'r') as f:
        reader = csv.reader(f)
        for sublist in reader:
            for item in sublist:
                item = item.strip()
                techniques.append(item)
                if '.' in item:  # the technique has a sub-technique
                    parent_technique = item.split('.')[0]
                    techniques.append(parent_technique)

        counter = Counter(techniques)

    # create the base data structure for the Navigator layer
    data = {
	    "name": "Michiel",
        "versions": {
			" attack": "13",
			"navigator": "4.8.2",
			"layer": "4.4"
		},
        "domain": "enterprise-attack",
        "description": "Michiel Moermans - Mitre ATT&CK script",
		"filters": {
			"platforms": [
				"Linux",
				"macOS",
				"Windows",
				"Network",
				"PRE",
				"Containers",
				"Office 365",
				"SaaS",
				"Google Workspace",
				"IaaS",
				"Azure AD"
			]
		},
		"sorting": 0,
		"layout": {
			"layout": "side",
			"aggregateFunction": "average",
			"showID": False,
			"showName": True,
			"showAggregateScores": False,
			"countUnscored": False
		},
		"hideDisabled": False,
        "techniques": [
            {
                "techniqueID": technique,
                "score": score,
                "color": "",
				"enabled": True,
				"metadata": [],
				"links": [],
				"showSubtechniques": True
            } for technique, score in counter.items()
        ],
        "gradient": {
            "colors": [
                "#92d050",
                "#ff0000"
            ],
            "minValue": 0,
            "maxValue": 4
        },
        "legendItems": [],
        "metadata": [],
		"links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#cccccc",
        "selectTechniquesAcrossTactics": True,
		"selectSubtechniquesWithParent": False
    }

    # write the JSON data to the output file
    with open(output_filename, 'w') as f:
        json.dump(data, f, indent=4)

if __name__ == "__main__":
    main()
