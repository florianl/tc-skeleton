clean:
	-$(RM) drop 

drop:
	clang -O2 -g -Wall -Werror -emit-llvm -c drop.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o drop
