#!/bin/bash

# Needs Kaitai Struct Compiler present
### https://doc.kaitai.io/serialization.html#_building_the_compiler_from_source

kaitai-struct-compiler --no-auto-read -t python $PWD/kaitai_struct_templates/java_class.ksy -d $PWD/../utils/java_library_helper

echo
echo
echo -e "######################\n######################\n"
echo -e "Please move the generated files to under the <root>/utils/java_library_helper directory\n"
echo -e "######################\n######################\n"
