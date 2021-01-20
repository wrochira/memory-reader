from memory_reader import MemoryReader

process_name = 'chrome'
search_value = 9999

print('Hooking process:', process_name)
mr = MemoryReader(process_name)

print('Searching for value:', search_value)
addresses = mr.scan_process_memory(search_value)

print('Found', len(addresses), 'results')

if len(addresses) > 0:
    first_address = addresses[0]
    first_value = mr.read_process_memory(first_address, 'int')
    print('First address:', hex(first_address))
    print('First value:', first_value)
