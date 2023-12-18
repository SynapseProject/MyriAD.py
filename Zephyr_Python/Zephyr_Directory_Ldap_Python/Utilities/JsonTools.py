import json

class JsonTools():
    _FILE = ""
    def __init__(self, path = None):
        if path == None:
            return
        self._FILE = open(path)
    
    def Deserialize(self, var:str = None):
        if var == None:
            data = json.load(self._FILE)
        else:
            data = json.loads(var)
        return data
    
    def Serialize(self, data, indent:bool = False):
        if indent == True:
            return json.dumps(obj=data, indent=4)
        return json.dumps(obj=data, indent=0)
    