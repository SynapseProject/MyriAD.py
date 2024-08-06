import xml.etree.ElementTree as ET
import xmltodict
class XMLTools():
    def dict_to_xml(self, dictionary, parent=None):
        if parent is None:
            parent = ET.Element('root')
        for key, value in dictionary.items():
            if isinstance(value, dict):
                child = ET.SubElement(parent, key)
                self.dict_to_xml(value, parent=child)
            else:
                ET.SubElement(parent, key).text = str(value)
        return parent
    
    def convert_to_xml(response: dict):
        xml_output = xmltodict.unparse({'root': response}, pretty=True)
        return xml_output
    
    def parse_json_data(self, parent, data):
        for key, value in data.items():
            if isinstance(value, list):
                if all(isinstance(item, dict) for item in value):
                    element = ET.Element(key)
                    for item in value:
                        self.dict_to_xml(dictionary=item, parent=element)
                    parent.append(element)
                else:    
                    element = ET.Element(key)
                    element.text = str(value)
                    parent.append(element)
            elif isinstance(value, dict):
                # If value is a dictionary, recursively parse
                element = ET.Element(key)
                parent.append(element)
                self.parse_json_data(element, value)
            else:
                # If value is not a dictionary, add as text
                element = ET.Element(key)
                element.text = str(value)
                parent.append(element)
    
    def json_to_xml(self, json_data):
        root = ET.Element("root")
        self.parse_json_data(root, json_data)
        xml_str = ET.tostring(root, encoding='utf8', method='xml')
        return xml_str