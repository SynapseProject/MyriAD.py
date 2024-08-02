from Zephyr_Directory_Ldap_Python.Classes.LdapResponse import LdapResponse
from io import StringIO
import json
import io
import csv

class CSVTools():
    def parse_data(self, data, csv_columns):
        new_data = {}
        for i in csv_columns:
            if i == "dn":
                new_data[i] = data[i]
            else:
                try:
                    new_data[i] = data["attributes"][i]
                except:
                    continue
        return new_data
    
    def convert_to_csv(self, response: LdapResponse):
        csv_columns = ["dn"]
        csv_columns.extend(response[0]['attributes'].keys())
        csv_string = ''
        try:
            with io.StringIO() as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
                writer.writeheader()
                for data in response:
                    input = self.parse_data(data, csv_columns)
                    writer.writerow(input)
                csv_string = csvfile.getvalue()
        except Exception as e:
            print("Error:", e)
        response = csv_string
        return response