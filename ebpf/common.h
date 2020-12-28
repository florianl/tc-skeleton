#pragma once

#include <stdint.h>
#include <linux/bpf.h>

#define __section(NAME)	__attribute__((section(NAME), used))

char __license[] __section("license") = "MIT";
