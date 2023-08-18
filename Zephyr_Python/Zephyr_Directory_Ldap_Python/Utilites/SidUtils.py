import os
import sys
import struct
import binascii

class SidUtils():
    def CopyBufferArray(self, src, src_ind, dest, dest_ind, count):
        for i in range(count):
            dest[dest_ind] = src[src_ind]
        return dest
    
    # Continue working on this!!!!!
    # def ConvertStringSidToBytes(sid: str):
    #     bytes = []
    #     sidParts = sid.split('-')
    #     print(sidParts)
    #     if not sidParts[0].upper.__eq__("S"):
    #         raise Exception(f"String [{sid}] Is Not A Properly Formatted Security Identifier String.")
    #     b = int(sidParts[1]).to_bytes(8)
    #     bytes.append(b)
    #     b = (len(sidParts) -3).to_bytes(8)
    #     bytes.append(b)

    #     barr = int(sidParts[2]).to_bytes()
    #     print(barr)
    #     if sys.byteorder == "little":
    #         barr = barr[::-1]
    #     i = len(barr)-6
    #     for i in range(len(barr)):
    #         bytes.append(barr[i])
    #     j =3
    #     for j in range(len(sidParts)):
    #         barr = int(sidParts[j]).to_bytes()
    #         if not sys.byteorder == "little":
    #             barr = barr[::-1]
    #         for k in range(len(barr)):
    #             if k == 4:
    #                 break
    #             bytes.append(barr[k])
    #     bytes_new = bytes
    #     print(bytes_new)
    #     return bytes_new
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



    # Continue working on this!!!!!!
    # def ConvertByteToStringSid(sidBytes):
    #     str_ = "S-"
    #     str_ = str_ + sidBytes[0] +"-"
    #     subIdCount = (len(sidBytes)-8)/4

    #     idBytes = []
    #     SidUtils().CopyBufferArray(sidBytes, 2, idBytes, 2, 6)
    #     if sys.byteorder:
    #         idBytes[::-1]
    #     l = int(idBytes)
    #     str_ = str_ + l + ""

    #     for i in range(subIdCount):
    #         subIdBytes = bytearray
    #         offset = 8 + (i*4)
    #         SidUtils.CopyBufferArray(sidBytes, offset, subIdBytes, 0, 4)
    #         if not sys.byteorder == "little":
    #             subIdBytes = subIdBytes[::-1]
    #         l = int(subIdBytes)
    #         str_ = str_ + "-" + l
    #     new_str = str_
    #     return new_str

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



    # def IsSid_str(sid: str):
    #     print("IDSID")
    #     isSid = False
    #     if sid != None or sid != '':
    #         try:
    #             bytes = SidUtils.ConvertStringSidToBytes(sid)
    #             newSid = SidUtils.ConvertByteToStringSid(bytes)
    #             isSid = sid.upper() == newSid.upper()
    #         except:
    #             print("Catch")
    #     return isSid
    
    # def IsSid(bytes: bytearray):
    #     isSid = False
    #     if bytes is not None:
    #         try:
    #             sid = SidUtils.ConvertByteToStringSid(bytes)
    #             newBytes = SidUtils.ConvertStringSidToBytes(sid)
    #             isSid = (bytes == newBytes)
    #         except Exception as e:
    #             print("Catch", e)
    #             pass
    #     return isSid

    def IsSid_str(sid):
        print("IDSID")
        isSid = False
        print(sid)
        if sid != None or sid != '':
            try:
                bytes = SidUtils.New_String_to_Bytes(sid)
                newSid = SidUtils.New_Bytes_To_SID(bytes)
                isSid = (sid.upper() == newSid.upper())
                print(isSid)
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