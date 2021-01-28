import math
import ctypes

from . utils import find_all, value_from_bytes


PROCESS_ALL_ACCESS = 0x1F0FFF

OpenProcess = ctypes.windll.kernel32.OpenProcess
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
CloseHandle = ctypes.windll.kernel32.CloseHandle


class MemoryReader():
    # Note: process names are extensionless
    def __init__(self, process_name=None, process_id=None):
        self.is_initialised = False
        if process_name is not None:
            self.hook_process_name(process_name)
        elif process_id is not None:
            self.hook_process_id(process_id)

    def hook_process_name(self, process_name, pid_index=0):
        self.process_name = process_name
        self.process_ids = self.get_process_ids()
        if self.process_ids is None:
            raise Exception('Process not found')
        self.process_id = self.process_ids[pid_index]
        self.process_handle = self.get_process_handle()
        self.module_bases = self.get_base_addresses()
        self.is_initialised = True

    def hook_process_id(self, process_id):
        self.process_id = process_id
        self.process_handle = self.get_process_handle()
        self.module_bases = self.get_base_addresses()
        self.is_initialised = True

    def get_process_ids(self):
        # Credit: http://code.activestate.com/recipes/303339-getting-process-information-on-windows/
        import win32pdh
        _, instances = win32pdh.EnumObjectItems(None, None, 'process', win32pdh.PERF_DETAIL_WIZARD)
        instance_count = instances.count(self.process_name)
        if instance_count == 0:
            return None
        pids = [ ]
        for inum in range(instance_count):
            hq = win32pdh.OpenQuery()
            path = win32pdh.MakeCounterPath((None,'process', self.process_name, None, inum, 'ID Process'))
            counter_handle = win32pdh.AddCounter(hq, path)
            win32pdh.CollectQueryData(hq)
            _, pid = win32pdh.GetFormattedCounterValue(counter_handle, win32pdh.PDH_FMT_LONG)
            win32pdh.CloseQuery(hq)
            pids.append(pid)
        return pids

    def get_process_handle(self):
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, int(self.process_id))
        return process_handle

    def get_base_addresses(self):
        import win32process
        modules = win32process.EnumProcessModules(self.process_handle)
        return modules

    def read_process_memory(self,
                            address,
                            data_type='int',
                            num_bytes=4,
                            byteorder='little'):
        bytes_buffer = b'.' * num_bytes
        bytes_read = ctypes.c_ulong(0)
        ReadProcessMemory(self.process_handle, address, bytes_buffer, num_bytes, ctypes.byref(bytes_read))
        value = value_from_bytes(bytes_buffer, 0x0, data_type, num_bytes, byteorder)
        return value

    def scan_process_memory(self,
                            search_value,
                            address_range=(0x00000000, 0xFFFFFFFF),
                            chunk_width=0x020000,
                            byteorder='little'):
        found_addresses = set()
        if type(search_value) == bytes:
            search_bytes = search_value
        elif type(search_value) == int:
            width = max(1, math.ceil(math.log(search_value, 2)/8))
            #width = int(math.ceil(width / 4)) * 4 # Round width up to nearest multiple of 4
            search_bytes = (search_value).to_bytes(width, byteorder)
        elif type(search_value) == str:
            search_bytes = bytes(search_value, encoding='utf-8')
        num_chunks = int(math.ceil((address_range[1] - address_range[0]) / chunk_width))
        last_scan, scan = None, None
        for chunk_id in range(num_chunks):
            last_scan = scan
            scan_address = address_range[0] + chunk_id * chunk_width
            scan = self.read_process_memory(scan_address, 'bytes', chunk_width)
            if last_scan is None:
                full_scan = scan
            else:
                full_scan = last_scan + scan
            for index in find_all(search_bytes, full_scan):
                match_address = scan_address - chunk_width + index
                if match_address < address_range[-1]:
                    found_addresses.add(match_address)
        return sorted(found_addresses)

    def resolve_pointer(self, base_pointer, offsets):
        pointer = base_pointer + offsets[0]
        for offset in offsets[1:]:
            pointer = self.read_process_memory(pointer) + offset
        return pointer
