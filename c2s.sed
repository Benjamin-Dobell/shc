#
#	sed script to wrapp C code as a C string.
#
# Duplicate unquoted %
s/[^\\]%/&%/g
#
# Unquote quoted %
s/\\%/%/g
#
# Duplicate \
s/\\/\\\\/g
#
# Quote "
s/"/\\"/g
#
# End each line with new-line
s/^.*$/&\\n/
#
# Enclose each line within "
s/^.*$/"&"/
#
