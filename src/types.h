#ifndef EGALITO_TYPES_H
#define EGALITO_TYPES_H

#include <cstdint>  // for uint64_t
#include <cstddef>  // for size_t

#ifdef ARCH_ARM
typedef uint32_t address_t;
typedef int32_t diff_t;
#else
typedef uint64_t address_t;
typedef int64_t diff_t;
#endif
typedef std::size_t size_t;


#endif
