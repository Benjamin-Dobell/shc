#
#	sed script to extract C code wrapped as a C string.
#
# Remove "s enclossing each line
s/^"\(.*\)"$/\1/
#
# Remove trailing new-line
s/^\(.*\)\\n$/\1/
#
# Unquote "
s/\\"/"/g
#
# Unduplicate \
s/\\\\/\\/g
#
# Quote unquoted and unduplicated %
s/\([^\\%]\)%\([^%]\)/\1\\%\2/g
#
# Unduplicate unquoted %
s/\([^\\]%\)%/\1/g
