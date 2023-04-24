import csv
import io
import unittest
from unittest.mock import patch

from main import get_headers, load_csv_data, load_json_data, preprocess_stix_data


class TestApp(unittest.TestCase):

    def setUp(self):
        self.headers = {
            "Analyst": {
                "cti": ["Attack Name", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol",
                        "Attack Reference"],
                "apt": ["Common Name", "Toolset"],
            }
        }
        self.csv_data = [
            {"Attack Name": "APT1", "Source IP": "192.168.1.1", "Destination IP": "10.0.0.1", "Source Port": "80",
             "Destination Port": "443", "Protocol": "TCP", "Attack Reference": "APT1-2022-04-11-001"},
            {"Attack Name": "APT2", "Source IP": "192.168.1.2", "Destination IP": "10.0.0.2", "Source Port": "443",
             "Destination Port": "80", "Protocol": "TCP", "Attack Reference": "APT2-2022-04-11-001"}
        ]
        self.json_data = [
            {
                "type": "attack-pattern",
                "name": "Phishing",
                "id": "attack-pattern--01234567",
                "created": "2022-04-11T12:34:56.000Z",
                "modified": "2022-04-11T12:34:56.000Z",
                "description": "Phishing is a social engineering technique...",
                "aliases": ["spear-phishing", "whaling"],
                "x_sophistication_level": "intermediate",
                "x_resource_level": "individual",
                "x_primary_motivation": "espionage"
            },
            {
                "type": "indicator",
                "name": "Suspicious IP",
                "id": "indicator--01234567",
                "created": "2022-04-11T12:34:56.000Z",
                "modified": "2022-04-11T12:34:56.000Z",
                "description": "IP address that is associated with malicious activity",
                "pattern": "ipv4-addr:value = '192.168.1.1'"
            }
        ]

    def test_get_headers(self):
        expected_result = {
            "cti": ["Attack Name", "Attack category"],
            "apt": ["Common Name", "Other Names", "Targets", "Modus Operandi", "Comment", "Link 1", "Link 2"],
        }
        self.assertEqual(get_headers("Management"), expected_result)

    def test_load_csv_data(self):
        csv_file = io.StringIO()
        writer = csv.DictWriter(csv_file, fieldnames=self.headers["Analyst"]["cti"])
        writer.writeheader()
        for row in self.csv_data:
            writer.writerow(row)
        csv_data_str = csv_file.getvalue()
        with patch('builtins.open', return_value=io.StringIO(csv_data_str)):
            loaded_data = load_csv_data("fake_file_path", self.headers["Analyst"]["cti"])
        self.assertEqual(loaded_data, self.csv_data)

    def test_load_json_data(self):
        def test_load_json_data(self):
            with open('Incident43.json', 'r') as f:
                loaded_data = load_json_data(f)
            # Define required STIX object types
            required_types = {'identity', 'location', 'campaign', 'incident'}
            # Get the set of STIX object types present in loaded data
            loaded_types = {obj['type'] for obj in loaded_data['objects']}
            # Check if all the required types are present in loaded data
            self.assertTrue(required_types.issubset(loaded_types))

    def test_preprocess_stix_data(self):
        def test_load_json_data(self):
            with open('Incident43.json', 'r') as f:
                loaded_data = load_json_data(f)
            # Define required STIX object types
            required_types = {'identity', 'location', 'campaign', 'incident'}
            # Get the set of STIX object types present in loaded data
            loaded_types = {obj['type'] for obj in loaded_data['objects']}
            # Check if all the required types are present in loaded data
            self.assertTrue(required_types.issubset(loaded_types))

