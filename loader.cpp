#include <sstream>
#include <memory>
#include <cstring>
#include <cerrno>

#include "loader.h"

Symbol::Symbol(const std::string &name, SymbolType type, size_t addr)
    : name(name), type(type), addr(addr) {}

Section::Section(const std::string &name, SectionType type, size_t vma, size_t size, uint8_t *bytes)
    : name(name), type(type), vma(vma), size(size), bytes(bytes, bytes+size) {}

bool Section::contains(size_t addr) {
    return (addr >= vma) && (addr - vma < size);
}

Binary::Binary(const std::string &filename)
{
    this->filename = filename;
    this->valid = false;
    this->error = "undefined error";

    bfd *bfd_h = open_bfd(filename);
    if (bfd_h == nullptr) {
        this->error = "open_bfd() failed";
        return;
    }

    std::unique_ptr<bfd, bfd_boolean (*)(bfd *)> bfd_unique_ptr(bfd_h, bfd_close);

    this->entry = bfd_get_start_address(bfd_h);
    this->type_str = bfd_h->xvec->name;

    switch(bfd_h->xvec->flavour) {
    case bfd_target_elf_flavour:
        this->type = BIN_TYPE_ELF;
        break;
    case bfd_target_coff_flavour:
        this->type = BIN_TYPE_PE;
        break;
    case bfd_target_unknown_flavour:
    default:
        std::ostringstream ss;
        ss << "unsupported binary type (" << bfd_h->xvec->name << ")";
        this->error = ss.str();
        return;
    }

    const bfd_arch_info_type *bfd_info = bfd_get_arch_info(bfd_h);
    this->arch_str = bfd_info->printable_name;

    switch(bfd_info->mach) {
    case bfd_mach_i386_i386:
        this->arch = ARCH_X86;
        this->bits = 32;
        break;
    case bfd_mach_x86_64:
        this->arch = ARCH_X86;
        this->bits = 64;
        break;
    default:
        std::ostringstream ss;
        ss << "unsupported architecture (" << bfd_info->printable_name << ")";
        this->error = ss.str();
        return;
    }

    if (load_symbols_bfd(bfd_h)
        || load_dynsyms_bfd(bfd_h)
        || load_sections_bfd(bfd_h)) return;

    this->symbols.shrink_to_fit();
    this->sections.shrink_to_fit();

    this->valid = true;
}

bool Binary::is_valid()
{
    return this->valid;
}

const char *Binary::get_error()
{
    return this->error.c_str();
}

Section *Binary::get_text_section() {
    for (auto &s : this->sections) {
        if (s.name == ".text") return &s;
    }

    return nullptr;
}

bfd *Binary::open_bfd(const std::string &filename) {
    static bool bfd_initialized = false;
    if (!bfd_initialized) {
        bfd_init();
        bfd_initialized = true;
    }

    bfd *bfd_h = bfd_openr(filename.c_str(), nullptr);
    if (bfd_h == nullptr) {
        std::ostringstream ss;
        ss << "failed to open binary: '" << filename.c_str() << "' (" << bfd_errmsg(bfd_get_error()) << ")";
        this->error = ss.str();
        return nullptr;
    }

    if (!bfd_check_format(bfd_h, bfd_object)) {
        std::ostringstream ss;
        ss << "file '" << filename.c_str() << "' does not look like an executable (" << bfd_errmsg(bfd_get_error()) << ")";
        this->error = ss.str();
        return nullptr;
    }

    bfd_set_error(bfd_error_no_error);
    if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {
        std::ostringstream ss;
        ss << "unrecognized format for binary '" << filename.c_str() << "' (" << bfd_errmsg(bfd_get_error()) << ")";
        this->error = ss.str();
        return nullptr;
    }

    return bfd_h;
}

int Binary::load_symbols_bfd(bfd *bfd_h) {
    long table_size = bfd_get_symtab_upper_bound(bfd_h);
    if (table_size < 0) {
        std::ostringstream ss;
        ss << "failed to read symtab (" << bfd_errmsg(bfd_get_error()) << ")";
        this->error = ss.str();
        return -1;
    }

    long n = table_size / sizeof(asymbol *);
    std::unique_ptr<asymbol *[]> bfd_symtab;
    try {
        bfd_symtab = std::make_unique<asymbol *[]>(n);
    } catch (const std::bad_alloc &) {
        std::ostringstream ss;
        ss << "failed to read symtab (" << strerror(errno) << ")";
        this->error = ss.str();
        return -1;
    }

    n = bfd_canonicalize_symtab(bfd_h, bfd_symtab.get());
    if (n < 0) {
        std::ostringstream ss;
        ss << "failed to read symtab (" << bfd_errmsg(bfd_get_error()) << ")";
        this->error = ss.str();
        return -1;
    }

    for (long i = 0; i < n; i++) {
        if (bfd_symtab[i]->flags & BSF_FUNCTION) {
            this->symbols.emplace_back(
                    std::string(bfd_symtab[i]->name),
                    Symbol::SYM_TYPE_FUNC,
                    bfd_asymbol_value(bfd_symtab[i]));
        }
    }

    return 0;
}

int Binary::load_dynsyms_bfd(bfd *bfd_h) {
    long table_size = bfd_get_dynamic_symtab_upper_bound(bfd_h);
    if (table_size < 0) {
        std::ostringstream ss;
        ss << "failed to read dynamic symtab (" << bfd_errmsg(bfd_get_error()) << ")";
        this->error = ss.str();
        return -1;
    }

    long n = table_size / sizeof(asymbol *);
    std::unique_ptr<asymbol *[]> bfd_dynsym;
    try {
        bfd_dynsym = std::make_unique<asymbol *[]>(n);
    } catch (const std::bad_alloc &) {
        std::ostringstream ss;
        ss << "failed to read dynamic symtab (" << strerror(errno) << ")";
        this->error = ss.str();
        return -1;
    }

    n = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym.get());
    if (n < 0) {
        std::ostringstream ss;
        ss << "failed to read dynamic symtab (" << bfd_errmsg(bfd_get_error()) << ")";
        this->error = ss.str();
        return -1;
    }

    for (long i = 0; i < n; i++) {
        if (bfd_dynsym[i]->flags & BSF_FUNCTION) {
            this->symbols.emplace_back(
                    std::string(bfd_dynsym[i]->name),
                    Symbol::SYM_TYPE_FUNC,
                    bfd_asymbol_value(bfd_dynsym[i]));
        }
    }

    return 0;
}

int Binary::load_sections_bfd(bfd *bfd_h) {
    for (asection *bfd_sec = bfd_h->sections;
            bfd_sec != nullptr;
            bfd_sec = bfd_sec->next) {

        int bfd_flags = bfd_section_flags(bfd_sec);

        Section::SectionType sectype =
            bfd_flags & SEC_CODE ? Section::SEC_TYPE_CODE :
            bfd_flags & SEC_DATA ? Section::SEC_TYPE_DATA :
                                   Section::SEC_TYPE_NONE;

        if (sectype == Section::SEC_TYPE_NONE) continue;

        const char *secname = bfd_section_name(bfd_sec);
        if (secname == nullptr) secname = "<unnamed>";

        size_t size = bfd_section_size(bfd_sec);
        uint8_t *bytes = new uint8_t[size];
        if (!bfd_get_section_contents(bfd_h, bfd_sec, bytes, 0, size)) {
            std::ostringstream ss;
            ss << "failed to read section '" << secname << "' (" << bfd_errmsg(bfd_get_error()) << ")";
            this->error = ss.str();
            return -1;
        }

        this->sections.emplace_back(
                std::string(secname), sectype,
                bfd_section_vma(bfd_sec),
                size, bytes);

        delete[] bytes;
    }

    return 0;
}
