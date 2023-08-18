import sys
import json
from Zephyr_Directory_Ldap_Python.Classes.LdapObjects import LdapObject
class LdapResponse():
    def __init__(self, response:dict = None):
        if response != None:
            self.success = response.get("success")  if response.get("success") else True
            self.server = response.get("server") if response.get("server") else None
            self.searchBase = response.get("searchBase") if response.get("searchBase") else None
            self.searchFilter = response.get("searchFilter") if response.get("searchFilter") else None
            self.message = response.get("message") if response.get("message") else None
            self.totalRecords = response.get("totalRecords") if response.get("totalRecords") else 0
            self.nextToken = response.get("nextToken") if response.get("nextToken") else None
            self.records = response.get("records") if response.get("records") else []
        else:
            self.success = True
            self.server = None
            self.searchBase = None
            self.searchFilter = None
            self.message = None
            self.totalRecords = 0
            self.nextToken = None
            self.records = []

    def Message(self):
        message = self.message
        return message
    
    def Print_entries(self):
        count = 0
        for i in self.records:
            # print(count)
            print(i.dn)
            print(i.attributes)
            # print(i.Print())
            # count += 1
    
    # def toJson(self):
    #     return json.dumps(self, default=lambda o: o.__dir__)

    def Record(self):
        obj = LdapObject(self.records)
        return obj

    def Print(self):
        print(f"{self.success}: {self.server}, {self.searchBase}, {self.searchFilter}, {self.message}, {self.totalRecords}, {self.nextToken}, {self.records}")
        # for i in self.records:
        #     for j in i.attributes.values():
        #         print(i.dn, ": ", j)
