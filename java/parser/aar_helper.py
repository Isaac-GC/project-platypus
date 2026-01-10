import io
import zipfile
from pathlib import Path

from kaitaistruct import KaitaiStream

from java.parser.java_class import JavaClass


class AarHelper:
    def __init__(self):
        self.loaded_aar_files = {}

    def load_aar_file(self, aar_file_path):
        try:
            zip_file = zipfile.ZipFile(aar_file_path)
            zip_file_name = Path(aar_file_path).stem

            if "classes.jar" in zip_file.namelist():
                classes_jar_content = zip_file.read("classes.jar")
                classes_jar_zipfile = zipfile.ZipFile(io.BytesIO(classes_jar_content))

                self.loaded_aar_files[zip_file_name] = []

                for entry in classes_jar_zipfile.namelist():
                    if entry.endswith(".class"):
                        jclass = JavaClass(KaitaiStream(io.BytesIO(classes_jar_zipfile.read(entry))))
                        self.loaded_aar_files[zip_file_name].append({
                            "name": entry,
                            "jclass": jclass
                        })


            else:
                print(f"No classes.jar file found in {aar_file_path}")


        except zipfile.BadZipFile as e:
            print(f"Error opening {aar_file_path}, bad zip file {e}")
        except FileNotFoundError as e:
            print(f"Error opening {aar_file_path}, file not found: {e}")
