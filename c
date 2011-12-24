#!/usr/pkg/bin/bash

rm -f *.o
rm -f *.a
rm -f *.so*

for i in *.c
do
	BASE=$( basename "$i" .c )
	cc -g -ggdb -Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wno-sign-compare \
	-Wno-traditional -Wa,--fatal-warnings -Wreturn-type -Wswitch -Wshadow                        \
	-Wcast-qual -Wwrite-strings -Wextra -Wno-unused-parameter  -Werror  -fstack-protector        \
	-Wstack-protector --param ssp-buffer-size=1 -DOPENPAM_MODULES_DIR=\"/usr/lib/security\"      \
	-D_FORTIFY_SOURCE=2 -c -DNO_STATIC_MODULES -fPIC -DPIC -I/v/soft/yubico-c-client \
	"$i" -o "$BASE".o

done
ar cq pam_yubi_pic.a $( NM=nm lorder *.o | tsort -q )
ranlib pam_yubi_pic.a
cc  -Wl,-x -shared -Wl,-soname,pam_yubi.so.1 -Wl,--warn-shared-textrel         \
	-Wl,--fatal-warnings -o pam_yubi.so.1.0  -Wl,-rpath-link,/lib:/usr/lib \
	-L/lib  -Wl,--whole-archive pam_yubi_pic.a -Wl,--no-whole-archive
