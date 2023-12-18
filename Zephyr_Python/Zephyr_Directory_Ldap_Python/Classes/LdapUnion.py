class LdapUnion():
    def __init__(self, union: dict = None):
        if union != None:
            self.searchValue = union.get("searchValue") if union.get("searchValue") else None
            self.searchBase = union.get("searchBase") if union.get("searchBase") else None
        else:
            self.searchValue = None
            self.searchBase = None