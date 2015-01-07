import os
__all__ = ["reaver"]
_paths = ["/usr/local/bin", "/usr/sbin", "/usr/bin", "/usr/local/sbin"]

def check_binary(bin_):
    return any([os.path.exists(os.path.join(_path, bin_))for _path in _paths])

if check_binary('reaver'):
    import reaver
