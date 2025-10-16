import os
import zlib
import struct
import argparse
from enum import Enum
from typing import Union, List, Dict

def uint32(n):
    return n & 0xFFFFFFFF

class JmdFileProperty(Enum):
    None_ = 0x00
    Compressed = 0x01
    Encrypted = 0x04
    PartialEncrypted = 0x05
    CompressedEncrypted = 0x06

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

class DataSavingInfo:
    def __init__(self, data, file_obj=None):
        self.data_info = JmdDataInfo()
        self.data = data
        self.file = file_obj

class JmdFile:
    def __init__(self, name, full_path, property=JmdFileProperty.CompressedEncrypted):
        self.name = name
        self.name_without_ext, self.ext_str = os.path.splitext(name)
        self.ext_str = self.ext_str[1:]
        self.full_path = full_path
        self.property = property
        self.size = os.path.getsize(full_path) if full_path else 0

class JmdFolder:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.files: List[JmdFile] = []
        self.folders: List['JmdFolder'] = []
        self._folder_data_index = None

    @property
    def full_name(self):
        if self.parent is None or self.parent.parent is None:
            return self.name
        return f"{self.parent.full_name}/{self.name}"

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

class JmdArchive:
    def __init__(self):
        self.root_folder = JmdFolder(name="__ROOT__")

    def repack(self, input_dir, jmd_path):
        self._build_tree_from_fs(input_dir, self.root_folder)

        out_filename_no_ext = os.path.splitext(os.path.basename(jmd_path))[0]
        out_jmd_key = JmdCrypto.get_jmd_key(out_filename_no_ext)

        saving_queue = []
        used_indices = set()
        
        self._store_folder_and_files(self.root_folder, saving_queue, used_indices, out_jmd_key)

        current_offset = 0
        for info in saving_queue:
            info.data_info.offset = current_offset
            current_offset += len(info.data)
            current_offset = (current_offset + 0xFF) & ~0xFF

        data_info_size = (len(saving_queue) * 0x20 + 0xFF) & ~0xFF
        data_begin_offset = 0x100 + data_info_size

        with open(jmd_path, 'wb') as f:
            f.write(b"J\x002\x00m\x00 \x00D\x00a\x00t\x00a\x00 \x00F\x00o\x00r\x00m\x00a\x00t\x00 \x001\x00.\x000\x00\x00\x00".ljust(0x40, b'\0'))
            f.write(b"j\x002\x00m\x00 \x00&\x00 \x00r\x00a\x00y\x00c\x00i\x00t\x00y\x00 \x00f\x00l\x00i\x00g\x00h\x00t\x00i\x00n\x00g\x00!\x00!\x00\x00\x00".ljust(0x40, b'\0'))

            data_info_key = os.urandom(32)
            header_data = bytearray(0x80)
            
            file_name_with_ext = f"{out_filename_no_ext}.jmd"
            whitening_key_str = file_name_with_ext.encode('utf-16-le')
            whitening_key = uint32(0x6c0b8043 + zlib.adler32(whitening_key_str, 0))

            mem_stream = struct.pack('<II', 0x100, len(saving_queue))
            mem_stream += struct.pack('<I', whitening_key)
            mem_stream += data_info_key
            mem_stream += struct.pack('<II', 0xd24e8143, 1)
            
            header_data[4:4+len(mem_stream)] = mem_stream

            checksum = zlib.adler32(memoryview(header_data)[4:], 0)
            header_data[0:4] = struct.pack('<I', checksum)
            
            encrypted_header = JmdCrypto.process_data(out_jmd_key, header_data)
            f.seek(0x80)
            f.write(encrypted_header)
            
            f.seek(0x100)
            for info in saving_queue:
                offset_shifted = (info.data_info.offset + data_begin_offset) >> 8
                
                packed_data = struct.pack('<IiiIiI', 
                    info.data_info.index, offset_shifted, len(info.data), 
                    info.data_info.uncompressed_size, info.data_info.block_property.value, 
                    info.data_info.checksum
                )
                block_data = packed_data + (b'\x00' * 8)
                
                encrypted_block = JmdCrypto.process_data_info(data_info_key, block_data)
                f.write(encrypted_block)
            
            f.seek(data_begin_offset - (len(saving_queue) * 0x20))

            for info in saving_queue:
                f.seek(info.data_info.offset + data_begin_offset)
                f.write(info.data)

    def _build_tree_from_fs(self, current_dir, jmd_folder_node):
        for entry in os.scandir(current_dir):
            if entry.is_dir():
                sub_folder = JmdFolder(entry.name, jmd_folder_node)
                jmd_folder_node.folders.append(sub_folder)
                self._build_tree_from_fs(entry.path, sub_folder)
            elif entry.is_file():
                file_node = JmdFile(entry.name, entry.path)
                jmd_folder_node.files.append(file_node)

    def _get_folder_data_index(self, folder, used_indices):
        if folder.parent is None:
            return 0xFFFFFFFF
        if folder._folder_data_index is None:
            full_name_bytes = folder.full_name.encode('utf-16-le')
            index = zlib.adler32(full_name_bytes, 0)
            while index in used_indices:
                index = uint32(index + 0x5F03E367)
            folder._folder_data_index = index
        return folder._folder_data_index

    def _get_file_data_index(self, file_obj, folder_data_index, used_indices):
        name_bytes = file_obj.name_without_ext.encode('utf-16-le')
        ext_num = self._get_ext_num(file_obj.ext_str)
        base_index = uint32(zlib.adler32(name_bytes, 0) + ext_num)
        if folder_data_index == 0xFFFFFFFF:
             folder_data_index = 0
        index = uint32(base_index + folder_data_index)
        while index in used_indices or (index + 1) in used_indices:
             index = uint32(index + 0x4D21CB4F)
        return index

    def _get_ext_num(self, ext_str):
        ext_bytes = ext_str.encode('ascii')
        ext_num_bytes = bytearray(4)
        length = min(4, len(ext_bytes))
        ext_num_bytes[:length] = ext_bytes[:length]
        return struct.unpack('<I', ext_num_bytes)[0]
    
    def _store_folder_and_files(self, folder, saving_queue, used_indices, jmd_key):
        for sub_folder in folder.folders:
            self._store_folder_and_files(sub_folder, saving_queue, used_indices, jmd_key)
        
        file_saving_infos = []
        for file in folder.files:
            with open(file.full_path, 'rb') as f: file_data = f.read()
            ext_num = self._get_ext_num(file.ext_str)
            file_key = JmdCrypto.get_file_key(jmd_key, file.name_without_ext, ext_num)
            file_size, file_checksum = len(file_data), 0
            folder_idx = self._get_folder_data_index(folder, used_indices)
            file_data_index = self._get_file_data_index(file, folder_idx, used_indices)

            if file.property in [JmdFileProperty.Encrypted, JmdFileProperty.CompressedEncrypted]:
                file_checksum = zlib.adler32(file_data, 0)
                file_data = JmdCrypto.process_data(file_key, file_data)
            if file.property in [JmdFileProperty.Compressed, JmdFileProperty.CompressedEncrypted]:
                file_data = zlib.compress(file_data, level=9)

            info = DataSavingInfo(file_data, file)
            info.data_info.index, info.data_info.checksum, info.data_info.uncompressed_size = file_data_index, file_checksum, file_size
            prop_map = {
                JmdFileProperty.None_: JmdDataInfoProperty.None_,
                JmdFileProperty.Encrypted: JmdDataInfoProperty.FullEncrypted,
                JmdFileProperty.Compressed: JmdDataInfoProperty.Compressed,
                JmdFileProperty.CompressedEncrypted: JmdDataInfoProperty.CompressedEncrypted,
            }
            info.data_info.block_property = prop_map.get(file.property, JmdDataInfoProperty.CompressedEncrypted)
            used_indices.add(file_data_index)
            file_saving_infos.append(info)
            
        folder_idx = self._get_folder_data_index(folder, used_indices)
        folder_mem_stream = bytearray(struct.pack('<i', len(folder.folders)))
        for sub_folder in folder.folders:
            sub_folder_idx = self._get_folder_data_index(sub_folder, used_indices)
            folder_mem_stream += sub_folder.name.encode('utf-16-le') + b'\x00\x00'
            folder_mem_stream += struct.pack('<I', sub_folder_idx)

        folder_mem_stream += struct.pack('<i', len(folder.files))
        for i, file in enumerate(folder.files):
            info = file_saving_infos[i]
            ext_num = self._get_ext_num(file.ext_str)
            folder_mem_stream += file.name_without_ext.encode('utf-16-le') + b'\x00\x00'
            folder_mem_stream += struct.pack('<IiIi', ext_num, file.property.value, info.data_info.index, file.size)

        folder_data_checksum = zlib.adler32(folder_mem_stream, 0)
        dir_key = JmdCrypto.get_directory_data_key(jmd_key)
        encrypted_folder_data = JmdCrypto.process_data(dir_key, folder_mem_stream)
        
        folder_info = DataSavingInfo(encrypted_folder_data)
        folder_info.data_info.index = folder_idx if folder_idx != 0xFFFFFFFF else 4294967295
        folder_info.data_info.uncompressed_size = len(folder_mem_stream)
        folder_info.data_info.checksum = folder_data_checksum
        folder_info.data_info.block_property = JmdDataInfoProperty.FullEncrypted
        used_indices.add(folder_info.data_info.index)
        
        saving_queue.insert(0, folder_info)
        for file_info in reversed(file_saving_infos):
            saving_queue.insert(1, file_info)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="JMD Repacker")
    parser.add_argument("input_dir", help="Path to the folder to repack")
    parser.add_argument("-o", "--output", help="Output JMD file path", default=None)

    args = parser.parse_args()
    archive = JmdArchive()

    try:
        output_file = args.output
        if not output_file:
            output_file = f"{args.input_dir}.jmd"
        archive.repack(args.input_dir, output_file)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error occurred: {e}")