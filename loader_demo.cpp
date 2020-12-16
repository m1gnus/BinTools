#include <cstdio>
#include <cstdint>
#include <string>

#include "loader.h"

#define FAILURE 1

using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <binary>\n", argv[0]);
        return FAILURE;
    }

    string filename(argv[1]);
    Binary bin(filename);
    if (!bin.is_valid()) {
        puts(bin.get_error());
        return FAILURE;
    }

    printf("loaded binary '%s' %s %s (%u bits) entry@%#018zx\n", bin.filename.c_str(), bin.type_str.c_str(), bin.arch_str.c_str(), bin.bits, bin.entry);

    for (size_t i = 0; i < bin.sections.size(); i++) {
        Section &sec = bin.sections[i];
        printf("    %#018zx %-8ju %-20s %s\n", sec.vma, sec.size, sec.name.c_str(), sec.type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
    }

    putchar('\n');

    if (bin.symbols.size() > 0) {
        puts("scanned symbol tables");
        for(Symbol &sym : bin.symbols) {
            printf("    %-40s %#018zx", sym.name.c_str(), sym.addr);
            if (sym.type & Symbol::SYM_TYPE_FUNC) {
                puts(" FUNC");
            } else {
                putchar('\n');
            }
        }
    }

    return 0;
}
