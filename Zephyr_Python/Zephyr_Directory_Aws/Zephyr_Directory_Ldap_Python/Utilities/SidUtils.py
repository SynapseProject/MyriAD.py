import os
import sys
import struct

class SidUtils():
    def CopyBufferArray(self, src, src_ind, dest, dest_ind, count):
        for i in range(count):
            dest[dest_ind] = src[src_ind]
        return dest
        
    def Convert_Str_to_Bool(self, ignoreWarnings):
        if type(ignoreWarnings) == str:
            ignoreWarnings = eval(ignoreWarnings.capitalize())
        return(ignoreWarnings)
    
    def Integer_to_Bytes(val, little_endian = True, size = 4):
        if little_endian:
            return struct.pack('<q', val)[0:size]
        else:
            return struct.pack('>q', val)[8-size:]

    def New_String_to_Bytes(sidstr:str):
        sid = sidstr.split('-')
        ret = bytearray()
        sid.remove('S')
        for i in range(len(sid)):
            sid[i] = int(sid[i])
        
        sid.insert(1, len(sid)-2)
        ret += SidUtils.Integer_to_Bytes(sid[0], size=1)
        ret += SidUtils.Integer_to_Bytes(sid[1], size=1)
        ret += SidUtils.Integer_to_Bytes(sid[2], False, size=6)
        for i in range(3, len(sid)):
            ret += SidUtils.Integer_to_Bytes(sid[i])
        return ret

    def Bytes_to_int(byte: bytearray, little_endian = True):
        if len(byte) > 8:
            raise Exception('Bytes too long.')
        else:
            if little_endian:
                a = byte.ljust(8, b'\x00')
                return struct.unpack('<q', a)[0]
            else:
                a =  byte.rjust(8, b'\x00')
                return struct.unpack('>q', a)[0]
    
    def New_Bytes_To_SID(sidBytes):
        ret = 'S'
        sid = []
        sid.append(SidUtils.Bytes_to_int(sidBytes[0:1]))
        sid.append(SidUtils.Bytes_to_int(sidBytes[2:2+6], little_endian=False))
        for i in range(8, len(sidBytes), 4):
            sid.append(SidUtils.Bytes_to_int(sidBytes[i:i+4]))
        for i in sid:
            ret += '-' + str(i)
        return ret


    def IsSid_str(sid):
        isSid = False
        if sid != None or sid != '':
            try:
                bytes = SidUtils.New_String_to_Bytes(sid)
                newSid = SidUtils.New_Bytes_To_SID(bytes)
                isSid = (sid.upper() == newSid.upper())
            except Exception as e:
                print("Catch", e)
        return isSid
    
    def IsSid(bytes: bytearray):
        isSid = False
        if bytes is not None:
            try:
                sid = SidUtils.New_String_to_Bytes(bytes)
                newBytes = SidUtils.New_Bytes_To_SID(sid)
                isSid = (bytes == newBytes)
            except Exception as e:
                print("Catch", e)
                pass
        return isSid