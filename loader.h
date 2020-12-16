#ifndef LOADER_H
#define LOADER_H

#include <cstdint>
#include <string>
#include <vector>

#include "config.h"

extern "C" {
#include <bfd.h>
}

class Symbol {
public:
    enum SymbolType {
        SYM_TYPE_UNKN = 0,
        SYM_TYPE_FUNC = 1
    };

    std::string name;
    SymbolType type;
    size_t addr;

    Symbol(const std::string &name, SymbolType type, size_t addr);
};

class Section {
public:
    enum SectionType {
        SEC_TYPE_NONE = 0,
        SEC_TYPE_CODE = 1,
        SEC_TYPE_DATA = 2
    };

    std::string name;
    SectionType type;
    size_t vma;
    size_t size;
    std::vector<uint8_t> bytes;

    Section(const std::string &name, SectionType type, size_t vma, size_t size, uint8_t *bytes);

    bool contains(size_t addr);
};

class Binary {
private:
    bool valid;
    std::string error;

public:
    enum BinaryType {
        BIN_TYPE_AUTO = 0,
        BIN_TYPE_ELF = 1,
        BIN_TYPE_PE = 2
    };

    enum BinaryArch {
        ARCH_NONE = 0,
        ARCH_X86 = 1
    };

    std::string filename;
    BinaryType type;
    std::string type_str;
    BinaryArch arch;
    std::string arch_str;
    unsigned bits;
    size_t entry;
    std::vector<Symbol> symbols;
    std::vector<Section> sections;

private:
    bfd *open_bfd(const std::string &filename);
    int load_symbols_bfd(bfd *bfd_h);
    int load_dynsyms_bfd(bfd *bfd_h);
    int load_sections_bfd(bfd *bfd_h);

public:
    Binary(const std::string &filename);

    bool is_valid();
    const char *get_error();
    Section *get_text_section();
};

#endif /* LOADER_H */
