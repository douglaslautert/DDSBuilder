import json

def write_to_json(data, filename):
    """
    Write vulnerability data to a JSON file.
    """
    with open(filename, mode="w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
