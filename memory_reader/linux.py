import math
from subprocess import check_output, CalledProcessError

from . utils import find_all, value_from_bytes


class MemoryReader():
    def __init__(self, process_name=None, process_id=None):
        self.is_initialised = False
        if process_name is not None:
            self.hook_process_name(process_name)
        elif process_id is not None:
            self.hook_process_id(process_id)
        self.get_process_map()

    def hook_process_name(self, process_name, pid_index=0):
        self.process_name = process_name
        self.process_ids = self.get_process_ids()
        if self.process_ids is None:
            raise Exception('Process not found')
        self.process_id = self.process_ids[pid_index]
        self.is_initialised = True

    def hook_process_id(self, process_id):
        self.process_id = process_id
        self.process_handle = self.get_process_handle()
        self.module_bases = self.get_base_addresses()
        self.is_initialised = True

    def get_process_ids(self):
        output = [ ]
        try:
            output_bytes = check_output([ 'pidof', self.process_name ])
            output_str = output_bytes.decode('utf-8')
            pids = [ int(x) for x in output_str.strip().split(' ') ]
            return pids
        except CalledProcessError:
            return None

    def get_process_map(self):
        self.mapped_ranges = [ ]
        with open('/proc/' + str(self.process_id) + '/maps', 'r') as infile:
            for line in infile.readlines():
                splitline = line.split(' ')
                address_range = tuple([ int(x, 16) for x in splitline[0].split('-') ])
                self.mapped_ranges.append(address_range)

    def read_process_memory(self, address, data_type='int', num_bytes=4, byteorder='little'):
        with open('/proc/' + str(self.process_id) + '/mem', 'rb') as infile:
            try:
                infile.seek(address)
                bytes_buffer = infile.read(num_bytes)
            except ValueError:
                return None
            value = value_from_bytes(bytes_buffer, 0x0, data_type, num_bytes, byteorder)
            return value

    def scan_process_memory(self, search_value, byteorder='little'):
        found_addresses = set()
        if type(search_value) == bytes:
            search_bytes = search_value
        elif type(search_value) == int:
            width = max(1, math.ceil(math.log(search_value, 2)/8))
            #width = int(math.ceil(width / 4)) * 4 # Round width up to nearest multiple of 4
            search_bytes = (search_value).to_bytes(width, byteorder)
        elif type(search_value) == str:
            search_bytes = bytes(search_value, encoding='utf-8')
        for address_range in self.mapped_ranges:
            range_width = address_range[1] - address_range[0]
            scan_address = address_range[0]
            try:
                scan = self.read_process_memory(scan_address, 'bytes', range_width)
            except OSError:
                continue
            if scan is None:
                continue
            for index in find_all(search_bytes, scan):
                match_address = scan_address + index
                found_addresses.add(match_address)
        return sorted(found_addresses)
