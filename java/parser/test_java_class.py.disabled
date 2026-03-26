import pytest
import zipfile

from .java_class import JavaClass

def load_java_class():
    zip_file = zipfile.ZipFile('samples/af_android_sdk_6.17.4_classes.jar')
    jclass_data = zip_file.read(zip_file.namelist()[5])
    JavaClass.from_bytes(jclass_data)

def test_loading_java_class():
    load_java_class()