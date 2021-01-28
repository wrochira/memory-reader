# Finds all start indices of b0 in b1, where b0 and b1 are both of type 'bytes'
def find_all(b0, b1):
    indices = set()
    lens = len(b0), len(b1)
    if lens[1] < lens[0]:
        return indices
    i = 0
    while i < lens[1] - lens[0] + 1:
        i = b1.find(b0, i)
        if i == -1:
            break
        indices.add(i)
        i += 1
    return indices

# Convert array of bytes to another data type
def value_from_bytes(in_bytes,
                     start_index=0x0,
                     data_type='int',
                     num_bytes=4,
                     byteorder='little',
                     null_terminate=True,
                     escape_unicode=True):
    relevant_bytes = in_bytes[start_index:start_index+num_bytes]
    if data_type == 'bytes':
        return relevant_bytes
    elif data_type == 'int':
        return int.from_bytes(relevant_bytes, byteorder)
    elif data_type == 'string':
        if null_terminate:
            if b'\x00' in relevant_bytes:
                length = relevant_bytes.index(b'\x00')
                relevant_bytes = relevant_bytes[:length]
        if escape_unicode:
            return relevant_bytes.decode(encoding='unicode_escape')
        return relevant_bytes.decode(encoding='utf-8')
