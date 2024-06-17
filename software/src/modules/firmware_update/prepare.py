import os
import sys
import importlib.util
import importlib.machinery

software_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

def create_software_module():
    software_spec = importlib.util.spec_from_file_location('software', os.path.join(software_dir, '__init__.py'))
    software_module = importlib.util.module_from_spec(software_spec)

    software_spec.loader.exec_module(software_module)

    sys.modules['software'] = software_module

if 'software' not in sys.modules:
    create_software_module()

from software import util

try:
    with open('../../../signature_public_key.bin', 'rb') as f:
        signature_public_key = f.read()
except FileNotFoundError:
    signature_public_key = b''

util.embed_data_with_digest(signature_public_key, '.', 'signature_public_key', 'unsigned char')
