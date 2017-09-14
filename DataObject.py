from collections import namedtuple
import struct

class DexTypeHelper():
    @staticmethod
    def CalcDecUnsignedLEB128(value):
        if value < (0x80):
            return 1
        elif value < (0x80 << 7):
            return 2
        elif value < (0x80 << 14):
            return 3
        return 4

    @staticmethod
    def readUnsignedLEB128(mm, offset):
        value = struct.unpack('<i', mm[offset:offset+4])[0]
        result = 0
        for i in range(4):
            curr = value & (0x000000ff << (i*8))
            curr = curr >> (i*8)
            result = result | ((curr & 0x7f) << (i * 7))
            if ((curr & 0x80) != 0x80): break
        return result

    @staticmethod
    def readSignedLed128(mm, offset):
        value = struct.unpack('<i', mm[offset:offset + 4])[0]
        result = 0
        signBits = -1
        for i in range(4):
            curr = value & (0x000000ff << (i * 8))
            curr = curr >> (i * 8)
            signBits <<= 7
            result = result | ((curr & 0x7f) << (i * 7))
            if ((curr & 0x80) != 0x80): break

        if (((signBits >> 1) & result) != 0):
            result |= signBits
        return result

class DexItem:
    def __init__(self):
        self.tag = "Abstract Item"
        self.offset = 0
        self.size = 0
        self.items = []

    def getItems(self):
        return self.items

    def printAllEls(self):
        print(self.tag)
        print("[ItemOffset] " + format(self.offset, '08X'))
        print("[ItemSize]   " + format(self.size, '08X'))
        for i in range(len(self.items)):
            item = self.items[i]
            print('[%4d] %s' % (i, item))

class TypeItems(DexItem):
    TypeItem = namedtuple("TypeItem", "type_off type_idx")

    def __init__(self):
        DexItem.__init__(self)
        self.tag = "Type Item"

    def type_id_list(self, mm, dexHeader):
        type_ids_size = dexHeader.type_ids_size
        type_ids_off = dexHeader.type_ids_off
        self.size = type_ids_size
        self.offset = type_ids_off
        for idx in range(type_ids_size):
            type_idx = struct.unpack('<L', mm[type_ids_off + (idx * 4):type_ids_off + (idx * 4) + 4])[0]
            type_off = type_ids_off + (idx * 4)
            aTypeItem = self.TypeItem(type_off, type_idx)
            self.items.append(aTypeItem)  # index into the string_ids

class StringItems(DexItem):
    def __init__(self):
        DexItem.__init__(self)
        self.tag = "String Item"

    def string_id_list(self, mm, dexHeader):
        string_ids_size = dexHeader.string_ids_size
        string_ids_off = dexHeader.string_ids_off
        self.size = string_ids_size
        self.offset = string_ids_off
        for idx in range(string_ids_size):
            off = struct.unpack('<L', mm[string_ids_off + (idx * 4):string_ids_off + (idx * 4) + 4])[0]
            utf16_size = (DexTypeHelper.readUnsignedLEB128(mm, off))
            if utf16_size <= 0:
                c_char = " "
            else:
                utf16_size_len = DexTypeHelper.CalcDecUnsignedLEB128(utf16_size)
                c_char = mm[off + utf16_size_len:off + utf16_size_len + utf16_size]
            self.items.append(c_char)


class FieldItems(DexItem):
    FieldItem = namedtuple("FieldItem", "class_idx type_idx name_idx")
    def __init__(self):
        DexItem.__init__(self)
        self.tag = "Field Item"

    def field_id_list(self, mm, dexHeader):
        field_ids_size = dexHeader.field_ids_size
        field_ids_off = dexHeader.field_ids_off
        for idx in range(field_ids_size):
            class_idx = struct.unpack('<H', mm[field_ids_off + (idx * 8):field_ids_off + (idx * 8) + 2])[0]  # index into the type_ids
            type_idx = struct.unpack('<H', mm[field_ids_off + (idx * 8) + 2:field_ids_off + (idx * 8) + 4])[0]  # index into the type_ids
            name_idx = struct.unpack('<L', mm[field_ids_off + (idx * 8) + 4:field_ids_off + (idx * 8) + 8])[0]  # index into the string_ids
            aFieldItem = self.FieldItem(class_idx, type_idx, name_idx)
            self.items.append(aFieldItem)


class ProtoItems(DexItem):
    ProtoItem = namedtuple("ProtoItem", "shorty_idx return_type_idx parameters_off")

    def __init__(self):
        DexItem.__init__(self)
        self.tag = "Proto Item"

    def proto_id_list(self, mm, dexHeader):
        proto_ids_size = dexHeader.proto_ids_size
        proto_ids_off = dexHeader.proto_ids_off
        self.size = proto_ids_size
        self.offset = proto_ids_off
        for idx in range(proto_ids_size):
            # index into the string_ids
            shorty_idx = struct.unpack('<L', mm[proto_ids_off + (idx * 12):proto_ids_off + (idx * 12) + 4])[0]
            # index into the type_ids
            return_type_idx = struct.unpack('<L', mm[proto_ids_off+(idx*12)+4:proto_ids_off+(idx*12)+ 8])[0]
            param_off = struct.unpack('<L', mm[proto_ids_off + (idx * 12) + 8:proto_ids_off + (idx * 12) + 12])[0]
            aProtoItem = self.ProtoItem(shorty_idx, return_type_idx, param_off)
            self.items.append(aProtoItem)

class MethodItems(DexItem):
    ClassDefItem = namedtuple("MethodItem", "class_idx proto_idx name_idx")

    def __init__(self):
        DexItem.__init__(self)
        self.tag = "Method Item"

    def method_id_list(self, mm, dexHeader):
        method_ids_size = dexHeader.method_ids_size
        method_ids_off = dexHeader.method_ids_off
        self.size = method_ids_size
        self.offset = method_ids_off

        for idx in range(method_ids_size):
            class_idx = struct.unpack('<H', mm[method_ids_off + (idx * 8):method_ids_off + (idx * 8) + 2])[0]  # index into the type_ids
            proto_idx = struct.unpack('<H', mm[method_ids_off + (idx * 8) + 2:method_ids_off + (idx * 8) + 4])[0]  # index into the proto_ids
            name_idx = struct.unpack('<L', mm[method_ids_off + (idx * 8) + 4:method_ids_off + (idx * 8) + 8])[0]  # index into the string_ids
            aClassDefItem = self.ClassDefItem(class_idx, proto_idx, name_idx)
            self.items.append(aClassDefItem)


class ClassDefItems(DexItem):
    ClassDefItem = namedtuple("ClassDefItem", "class_idx access_flags superclass_idx interfaces_off " +
                                              "source_file_idx annotations_off class_data_off static_values_off")
    def __init__(self):
        DexItem.__init__(self)
        self.tag = "Class Def Item"

    def class_def_list(self, mm, dexHeader):
        class_size = dexHeader.class_defs_size
        class_off = dexHeader.class_defs_off
        self.size = class_size
        self.offset = class_off
        for idx in range(class_size):
            # index into the type_ids
            class_idx = struct.unpack('<L', mm[class_off + (idx * 0x20) + 0:class_off + (idx * 0x20) + 4])[0]
            # access_flags
            access_flags = struct.unpack('<L', mm[class_off + (idx * 0x20) + 4:class_off + (idx * 0x20) + 8])[0]
            # index into the type_ids
            superclass_idx = struct.unpack('<L', mm[class_off + (idx * 0x20) + 8:class_off + (idx * 0x20) + 12])[0]
            # offset in data section below "type_list"
            interfaces_off = struct.unpack('<L', mm[class_off + (idx * 0x20) + 12:class_off + (idx * 0x20) + 16])[0]
            # index into the string_ids
            source_file_idx = struct.unpack('<L', mm[class_off + (idx * 0x20) + 16:class_off + (idx * 0x20) + 20])[0]
            # offset in data section "annotations_directory_item" below
            annotations_off = struct.unpack('<L', mm[class_off + (idx * 0x20) + 20:class_off + (idx * 0x20) + 24])[0]
            # offset in data section "class_data_item" below
            class_data_off = struct.unpack('<L', mm[class_off + (idx * 0x20) + 24:class_off + (idx * 0x20) + 28])[0]
            # offset in data section "encoded_array_item" below
            static_values_off = struct.unpack('<L', mm[class_off + (idx * 0x20) + 28:class_off + (idx * 0x20) + 32])[0]

            aClassDefItem = self.ClassDefItem(class_idx, access_flags, superclass_idx, interfaces_off,
                                              source_file_idx, annotations_off, class_data_off, static_values_off)
            self.items.append(aClassDefItem)


class CodeItem:

    code_item = namedtuple("CodeItem", "registersSize insSize outSize tries_size debug_info_off insns_size insns")
    try_item = namedtuple("TryItem", "startAddr insnCount handlerOff")
    encoded_catch_handler_list = namedtuple("HandlerList", "startAddr insnCount handlerOff")
    dex_catch_handler = namedtuple("DexCatchHandler", "size typeIdx address")

    def __init__(self, mm, aDexMethod):
        self.mm = mm
        self.DexMethod = aDexMethod
        self.tryItems = []
        self.handlers = []
        self.parseCodeItemHeader(self.mm, self.DexMethod)

    def parseCodeItemHeader(self, mm, DexMethod):
        offset = DexMethod.codeOff
        registers_size = struct.unpack('<H', mm[offset:offset + 2])[0]
        ins_size = struct.unpack('<H', mm[offset + 2:offset + 4])[0]
        outs_size = struct.unpack('<H', mm[offset + 4:offset + 6])[0]
        tries_size = struct.unpack('<H', mm[offset + 6:offset + 8])[0]
        debug_info_off = struct.unpack('<I', mm[offset + 8:offset + 12])[0]
        insns_size = struct.unpack('<I', mm[offset + 12:offset + 16])[0]
        insns = mm[offset+16: offset+16+(insns_size * 2)]

        self.codeItem = self.code_item(registers_size, ins_size, outs_size,
                                        tries_size, debug_info_off, insns_size, insns)

        offset = offset + 16 + (insns_size * 2)
        if offset & 3 != 0:
            offset = offset + 2

        for i in range(tries_size):
            try_startAddr = struct.unpack('<I', mm[offset:offset+4])[0]
            insn_count = struct.unpack('<H', mm[offset+4:offset+6])[0]
            handler_off = struct.unpack('<H', mm[offset+6:offset+8])[0]
            aTryitem = self.try_item(try_startAddr, insn_count, handler_off)
            self.tryItems.append(aTryitem)
            offset = offset + 8

        for i in range(len(self.tryItems)):
            item = self.tryItems[i]
            handlerOff = item.handlerOff
            catchesAll = False

            """
            offset = offset + handlerOff
            encoded_catch_handler_list_size = DexTypeHelper.readUnsignedLEB128(mm, offset)
            for idx in range(encoded_catch_handler_list_size):
                encoded_catch_handler_list_size_len = \
                    DexTypeHelper.CalcDecUnsignedLEB128(encoded_catch_handler_list_size)

                offset = offset + encoded_catch_handler_list_size_len
                encoded_catch_handler_size = DexTypeHelper.readSignedLed128(mm, offset)

                if encoded_catch_handler_size <= 0:
                    catchesAll = True
                    encoded_catch_handler_size *= -1
                else:
                    catchesAll = False

                for encoded_idx in range(encoded_catch_handler_size):
                    encoded_catch_handler_size_len = DexTypeHelper.CalcDecUnsignedLEB128(encoded_catch_handler_size)
                    offset = offset + encoded_catch_handler_size_len

                    typeIdx = DexTypeHelper.readUnsignedLEB128(mm, offset)
                    typeIdx_size = DexTypeHelper.CalcDecUnsignedLEB128(typeIdx)
                    offset = offset + typeIdx_size
                    handler_address = DexTypeHelper.readUnsignedLEB128(mm, offset)

            """

            count = DexTypeHelper.readSignedLed128(mm, offset + handlerOff)
            count_size = DexTypeHelper.CalcDecUnsignedLEB128(count)

            if count <= 0:
                catchesAll = True
                count *= -1
            else:
                catchesAll = False

            for idx in range(count, -1, -1):
                if idx == 0:
                    if catchesAll == True:
                        catchesAll = False
                        typeIdx = 0xffffffff
                    else:
                        break
                else:
                    typeIdx = DexTypeHelper.readUnsignedLEB128(mm, offset + handlerOff + count_size)

                if typeIdx == 0xffffffff:
                    typeIdx_size = 0
                    handler_address = DexTypeHelper.readUnsignedLEB128(mm, offset + handlerOff + count_size)
                else:
                    typeIdx_size = DexTypeHelper.CalcDecUnsignedLEB128(typeIdx)
                    handler_address = DexTypeHelper.readUnsignedLEB128(mm, offset + handlerOff + count_size + typeIdx_size)

                handler_address_size = DexTypeHelper.CalcDecUnsignedLEB128(handler_address)
                self.handlers.append(self.dex_catch_handler(offset + handlerOff + count_size + typeIdx_size, typeIdx, handler_address))
                handlerOff = handlerOff + count_size + typeIdx_size + handler_address_size



    def printAllEl(self):
        print(self.codeItem)
        for i in range(len(self.tryItems)):
            item = self.tryItems[i]
            print("[%02d] : %04x - %04x  %04x" % (i, item.startAddr, item.startAddr + item.insnCount, item.handlerOff))

        for i in range(len(self.handlers)):
            item = self.handlers[i]
            print("[%02d] : %d  %04x  %04x" % (i, item.size, item.typeIdx, item.address))



class Clazz:

    DexClassDataHeader = namedtuple("DexClassDataHeader", "staticFieldSize instanceFieldsSize " +
                                                          "directMethodsSize virtualMethodsSize")
    DexField = namedtuple("DexField", "fieldIdx accessFlags")
    DexMethod = namedtuple("DexMethod", "methodIdx accessFlags codeOff")
    DexClassData = namedtuple("DexClassData", "DexClassDataHeader DexField_staticFields DexField_instanceFields " +
                              "DexMethod_directMethods DexMethod_virtualMethods")

    def __init__(self, mm, aClassDefItem):
        self.classDefinition = aClassDefItem
        self.staticFields = []
        self.instanceFields = []
        self.directMethods = []
        self.virtualMethods = []
        self.codeItems = []
        self.parseClasses(mm, aClassDefItem)
        if aClassDefItem.class_data_off != 0:
            self.parseCodes()
        else:
            self.parseClassWithNoData()

    def readUnsignedLEB128(self):
        value = DexTypeHelper.readUnsignedLEB128(self.mm, self.clazzOff)
        self.clazzOff = self.clazzOff + DexTypeHelper.CalcDecUnsignedLEB128(value)
        return value

    def parseClassWithNoData(self):
        static_fields_size = 0
        instance_fields_size = 0
        direct_methods_size = 0
        virtual_methods_size = 0

    def parseClasses(self, mm, aClassDefItem):
        clazzOff = aClassDefItem.class_data_off
        self.mm = mm
        self.clazzOff = clazzOff

        static_fields_size = self.readUnsignedLEB128()
        instance_fields_size = self.readUnsignedLEB128()
        direct_methods_size = self.readUnsignedLEB128()
        virtual_methods_size = self.readUnsignedLEB128()

        for idx in range(static_fields_size):
            fieldIdx = self.readUnsignedLEB128()
            accessFlags = self.readUnsignedLEB128()
            aDexField = self.DexField(fieldIdx, accessFlags)
            self.staticFields.append(aDexField)

        for idx in range(instance_fields_size):
            fieldIdx = self.readUnsignedLEB128()
            accessFlags = self.readUnsignedLEB128()
            aDexField = self.DexField(fieldIdx, accessFlags)
            self.instanceFields.append(aDexField)

        for idx in range(direct_methods_size):
            fieldIdx = self.readUnsignedLEB128()
            accessFlags = self.readUnsignedLEB128()
            codeOff = self.readUnsignedLEB128()
            aDexMethod = self.DexMethod(fieldIdx, accessFlags, codeOff)
            self.directMethods.append(aDexMethod)

        for idx in range(virtual_methods_size):
            fieldIdx = self.readUnsignedLEB128()
            accessFlags = self.readUnsignedLEB128()
            codeOff = self.readUnsignedLEB128()
            aDexMethod = self.DexMethod(fieldIdx, accessFlags, codeOff)
            self.virtualMethods.append(aDexMethod)

        # DexClassDataHeader
        aDexClassDataHeader = self.DexClassDataHeader(static_fields_size, instance_fields_size,
                                                      direct_methods_size, virtual_methods_size)

        self.dexClassData = self.DexClassData(aDexClassDataHeader, self.staticFields, self.instanceFields
                                              , self.directMethods, self.virtualMethods)

    def parseCodes(self):
        for i in range(len(self.directMethods)):
            method = self.directMethods[i]
            if method.codeOff != 0:
                aCodeItem = CodeItem(self.mm, self.directMethods[i])
                self.codeItems.append(aCodeItem)
        for i in range(len(self.virtualMethods)):
            method = self.virtualMethods[i]
            if method.codeOff != 0:
                aCodeItem = CodeItem(self.mm, self.virtualMethods[i])
                self.codeItems.append(aCodeItem)

    def printAllEl(self):
        print(self.dexClassData)
        for i in range(len(self.codeItems)):
            self.codeItems[i].printAllEl()
        print("")
