#pragma once

#include <stdint.h>
#include <linux/bpf.h>

#define __section(NAME)	__attribute__((section(NAME), used))
#define __inline 	inline __attribute__((always_inline))

#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

char __license[] __section("license") = "MIT";
