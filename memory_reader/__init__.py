import platform

system = platform.system()
if system == 'Windows':
    from .windows import MemoryReader
elif system == 'Linux':
    from .linux import MemoryReader
else:
    print('Windows and Linux only, sorry.')
