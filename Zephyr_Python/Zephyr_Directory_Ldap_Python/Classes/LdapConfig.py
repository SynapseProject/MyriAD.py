import sys
from enum import Enum

class LdapAttributeTypes(Enum):
    Unknown = 0,
    String = 1, 
    StringArray = 3,
    Bytes = 4
    BytesArray = 5,
    Guid = 6,
    GuidArray = 7,
    Sid = 8,
    SidArray = 9,
    Number = 10,
    NumberArray = 11,
    Boolean = 12,
    BooleanArray = 13


class LdapConfig():
    def __init__(self, config: dict = None):
        if config != None:
            self.server_name = config.get("server") if config.get("server") else None
            self.port = config.get("port") if config.get("port") else None
            self.ssl = config.get("ssl") if config.get("ssl") else None
            self.username = config.get("username") if config.get("username") else None
            self.password = config.get("password") if config.get("password") else None
            self.maxRetries = config.get("maxRetries") if config.get("maxRetries") != None else None
            self.maxPageSize = config.get("maxPageSize") if config.get("maxPageSize") else None
            self.followReferrals = config.get("followReferrals") if config.get("followReferrals") else False
            self.returnTypes = config.get("returnTypes") if config.get("returnTypes") else {}
        else:
            self.server_name = None
            self.port = None
            self.ssl = None
            self.username = None
            self.password = None
            self.maxRetries = None
            self.maxPageSize = None
            self.followReferrals = None
            self.returnTypes = None
    def Print(self):
        print(self.server_name, self.ssl, self.username)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
        print(self.password, self.port, self.maxRetries, self.maxPageSize)
        print(self.followReferrals, self.returnTypes)                      
    def is_Null(self):
        properties = [self.server_name, self.port, self.ssl ,self.username, self.password, self.maxRetries, self.maxPageSize, self.followReferrals, self.returnTypes]
        bool_flag = True
        for i in properties:
            if i != None:
                bool_flag = False
        return bool_flag