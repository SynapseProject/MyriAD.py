import sys
import json
from Zephyr_Directory_Ldap_Python.Classes.LdapObjects import LdapObject
from enum import Enum

class StatusCode(Enum):
    Success = 1,
    Failure = 2,
    SuccessWithWarnings = 3

class LdapResponse():
    def __init__(self, response:dict = None):
        if response != None:
            self.success = response.get("success")  if response.get("success") else True
            self.server = response.get("server") if response.get("server") else None
            self.searchBase = response.get("searchBase") if response.get("searchBase") else None
            self.searchBases = response.get("searchBases") if response.get("searchBases") else None
            self.searchFilter = response.get("searchFilter") if response.get("searchFilter") else None
            self.searchFilters = response.get("searchFilters") if response.get("searchFilters") else None
            self.message = response.get("message") if response.get("message") else {}
            self.status = response.get('status') if response.get('status') else None
            self.totalRecords = response.get("totalRecords") if response.get("totalRecords") else 0
            self.nextToken = response.get("nextToken") if response.get("nextToken") else None
            self.nextTokens = response.get("nextTokens") if response.get("nextTokens") else None
            self.records = response.get("records") if response.get("records") else []
        else:
            self.success = True
            self.server = None
            self.searchBase = None
            self.searchBases = None
            self.searchFilter = None
            self.searchFilters = None
            self.message = {}
            self.status = None
            self.totalRecords = 0
            self.nextToken = None
            self.nextTokens = None
            self.records = []

    def Message(self):
        message = self.message
        return message

    def Record(self):
        obj = LdapObject(self.records)
        return obj

