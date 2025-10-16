import os
import zlib
import struct
import argparse
from enum import Enum
from typing import Union, List, Dict

class JmdDataInfoProperty(Enum):
    None_ = 0
    Compressed = 2
    PartialEncrypted = 4
    FullEncrypted = 5
    CompressedEncrypted = 7

class JmdDataInfo:
    def __init__(self):
        self.index = 0
        self.offset = 0
        self.data_size = 0
        self.uncompressed_size = 0
        self.block_property = JmdDataInfoProperty.None_
        self.checksum = 0

class JmdFile:
    def __init__(self, name, prop_val):
        self.name = name
        self.property_value = prop_val
        self.size = 0
        self.data_index = 0
        self.key = 0
        self.data = None

class JmdFolder:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.files: List[JmdFile] = []
        self.folders: List['JmdFolder'] = []

class JmdCrypto:
    @staticmethod
    def get_jmd_key(file_name: str) -> int:
        string_data = file_name.encode('utf-16-le')
        return uint32(zlib.adler32(string_data, 0) + 0x3de90dc3)

    @staticmethod
    def get_directory_data_key(rhojmd_key: int) -> int:
        return uint32(rhojmd_key - 0x41014EBF)

    @staticmethod
    def get_file_key(jmd_key: int, file_name_without_ext: str, ext_num: int) -> int:
        str_data = file_name_without_ext.encode('utf-16-le')
        key = zlib.adler32(str_data, 0)
        key = uint32(key + ext_num)
        key = uint32(key + uint32(jmd_key - 0x7E2AF33D))
        return key

    @staticmethod
    def extend_key(original_key: int) -> bytearray:
        out_array = bytearray(64)
        cur_data = uint32(original_key ^ 0x8473fbc1)
        for i in range(16):
            out_array[i*4 : (i+1)*4] = struct.pack('<I', cur_data)
            cur_data = uint32(cur_data - 0x7b8c043f)
        return out_array

    @staticmethod
    def process_data(key: int, data: Union[bytes, bytearray]) -> bytearray:
        extended_key = JmdCrypto.extend_key(key)
        output = bytearray(data)
        for i in range(len(data)):
            output[i] ^= extended_key[i & 63]
        return output
    
    @staticmethod
    def process_data_info(key: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> bytearray:
        if len(data) != 0x20:
            raise ValueError("Data length must be 32 bytes")
        output = bytearray(32)
        for i in range(32):
            output[i] = data[i] ^ key[i]
        return output

def uint32(n):
    return n & 0xFFFFFFFF

class JmdArchive:
    def __init__(self):
        self.root_folder = JmdFolder(name="__ROOT__")
        self._data_info_map: Dict[int, JmdDataInfo] = {}

    def unpack(self, jmd_path, output_dir):
        jmd_filename_no_ext = os.path.splitext(os.path.basename(jmd_path))[0]
        jmd_key = JmdCrypto.get_jmd_key(jmd_filename_no_ext)
        
        with open(jmd_path, 'rb') as f:
            f.seek(0x80)
            encrypted_header = f.read(0x80)
            decrypted_header = JmdCrypto.process_data(jmd_key, encrypted_header)

            header_stream = memoryview(decrypted_header)
            info_checksum = struct.unpack_from('<I', header_stream, 0)[0]
            verify_checksum = zlib.adler32(header_stream[4:], 0)
            if info_checksum != verify_checksum:
                raise Exception("JMD header checksum mismatch!!!!")
            
            data_info_count = struct.unpack_from('<i', header_stream, 8)[0]
            data_info_key = header_stream[16:16+32].tobytes()

            f.seek(0x100)
            for _ in range(data_info_count):
                encrypted_info = f.read(0x20)
                decrypted_info = JmdCrypto.process_data_info(data_info_key, encrypted_info)
                
                info = JmdDataInfo()
                info.index, offset_shifted, info.data_size, info.uncompressed_size, prop_val, info.checksum = \
                    struct.unpack_from('<IiiIiI', memoryview(decrypted_info))
                
                info.offset = offset_shifted << 8
                info.block_property = JmdDataInfoProperty(prop_val)
                self._data_info_map[info.index] = info

            folder_key = JmdCrypto.get_directory_data_key(jmd_key)
            process_queue = [(0xFFFFFFFF, self.root_folder)]

            while process_queue:
                folder_data_index, current_folder = process_queue.pop(0)
                folder_data = self._get_data_block(f, folder_data_index, folder_key)
                folder_stream = memoryview(folder_data)
                offset = 0
                folder_count = struct.unpack_from('<i', folder_stream, offset)[0]
                offset += 4
                
                for _ in range(folder_count):
                    name_bytes, start_offset = b'', offset
                    while folder_stream[offset:offset+2] != b'\x00\x00': offset += 2
                    name = folder_stream[start_offset:offset].tobytes().decode('utf-16-le'); offset += 2
                    sub_folder_index = struct.unpack_from('<I', folder_stream, offset)[0]; offset += 4
                    sub_folder = JmdFolder(name, current_folder); current_folder.folders.append(sub_folder)
                    process_queue.append((sub_folder_index, sub_folder))

                file_count = struct.unpack_from('<i', folder_stream, offset)[0]
                offset += 4
                for _ in range(file_count):
                    name_bytes, start_offset = b'', offset
                    while folder_stream[offset:offset+2] != b'\x00\x00': offset += 2
                    file_name = folder_stream[start_offset:offset].tobytes().decode('utf-16-le'); offset += 2
                    ext_int, prop_val, data_index, file_size = struct.unpack_from('<IiIi', folder_stream, offset); offset += 16
                    ext_str = struct.pack('<I', ext_int).decode('ascii').strip('\x00')
                    full_file_name = f"{file_name}.{ext_str}" if ext_str else file_name
                    file_key = JmdCrypto.get_file_key(jmd_key, file_name, ext_int)
                    file_obj = JmdFile(full_file_name, prop_val)
                    file_obj.data_index = data_index
                    file_obj.size = file_size
                    file_obj.key = file_key
                    file_obj.data = self._get_data_block(f, file_obj.data_index, file_obj.key, file_obj.property_value)
                    current_folder.files.append(file_obj)

        self._save_tree(self.root_folder, output_dir)
    def _get_data_block(self, stream, data_index, key, prop_val=None):
        if data_index == 0xFFFFFFFF: data_index = 4294967295
        if data_index not in self._data_info_map:
            if len(self._data_info_map) > 0:
                first_key = next(iter(self._data_info_map))
                if self._data_info_map[first_key].block_property == JmdDataInfoProperty.FullEncrypted:
                    data_index = first_key
                else: raise Exception(f"Data index {data_index} not found in the map.")
            else: raise Exception(f"Data index {data_index} not found in the map.")
                 
        data_info = self._data_info_map[data_index]
        stream.seek(data_info.offset)
        data = stream.read(data_info.data_size)

        if data_info.block_property in [JmdDataInfoProperty.Compressed, JmdDataInfoProperty.CompressedEncrypted]:
            data = zlib.decompress(data)

        is_encrypted = (data_info.block_property.value & JmdDataInfoProperty.PartialEncrypted.value) != 0
        
        if is_encrypted:
            if prop_val == 5:
                decrypted_part = JmdCrypto.process_data(key, data)
                next_block_index = data_index + 1
                if next_block_index in self._data_info_map:
                    next_data_info = self._data_info_map[next_block_index]
                    stream.seek(next_data_info.offset)
                    plain_part = stream.read(next_data_info.data_size)
                    data = decrypted_part + plain_part
                else: 
                    data = decrypted_part
            else:
                data = JmdCrypto.process_data(key, data)
        
        return data

    def _save_tree(self, folder, current_path):
        if folder.name != "__ROOT__":
            current_path = os.path.join(current_path, folder.name)
        if not os.path.exists(current_path): os.makedirs(current_path)
        for file in folder.files:
            with open(os.path.join(current_path, file.name), 'wb') as f: f.write(file.data)
        for sub_folder in folder.folders:
            self._save_tree(sub_folder, current_path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="JMD Unpacker")
    parser.add_argument("jmd_file", help="Path to the JMD file to unpack.")
    parser.add_argument("-o", "--output", help="Output directory for unpacked files", default=None)
    
    args = parser.parse_args()
    archive = JmdArchive()

    try:
        output_dir = args.output
        if not output_dir:
            output_dir = os.path.splitext(args.jmd_file)[0]
        archive.unpack(args.jmd_file, output_dir)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error occurred: {e}")