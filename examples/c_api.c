#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "check.h"
#include "exe_c_api.h"
GENERATE_BINDINGS(rs_pe);

#define safe_rs_pe_free(h)     SAFE_FREE(h, NULL, pe.ops->free_exe)

char* show_flags(uint32_t flags) {
    static char str_flags[4] = "---";
    if ( flags & 4U ) { str_flags[0] = 'r'; } else { str_flags[0] = '-'; }
    if ( flags & 2U ) { str_flags[1] = 'w'; } else { str_flags[1] = '-'; }
    if ( flags & 1U ) { str_flags[2] = 'x'; } else { str_flags[2] = '-'; }
    return str_flags;
}

int main(int argc, char *const argv[]) {
    int fd = -1;
    void *ptr = MAP_FAILED;
    const uint8_t *data;
    struct stat sb;
    rs_pe_handle_t pe = { NULL, NULL };
    rs_handle_t section = NULL;
    size_t nsections;
    const char* section_name = NULL;
    size_t section_size;
    size_t section_off;
    uint32_t section_flags;
    int ret = EXIT_FAILURE;

    if ( argc != 2 ) {
        fprintf(stderr, "Usage : %s file\n", argv[0]);
        return EXIT_FAILURE;
    }

    CHK_NEG(fd = open(argv[1], O_RDONLY));
    CHK_NEG(fstat(fd, &sb));
    CHK_MMAP(ptr = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0));
    data = (const uint8_t *)ptr;
    CHK(rs_pe_parse_helper(&pe, data, sb.st_size), == false);
    nsections = pe.ops->get_number_of_sections(pe.handle);
    for ( size_t idx = 0; idx < nsections; idx++ ) {
        CHK_NULL(section = pe.ops->get_section_at(pe.handle, idx));
        CHK_NULL(section_name = pe.ops->get_section_name_at(pe.handle, idx));
        section_flags = pe.ops->get_flags(section);
        section_size = pe.ops->get_size(section);
        section_off = pe.ops->get_offset(section);

        printf(
            "Section %02lu / %s : flags=%s, offset=0x%lx, size%lu\n",
            idx, section_name, show_flags(section_flags), section_off, section_size
        );

    }

    ret = EXIT_SUCCESS;

    fail:
    safe_rs_pe_free(pe.handle);
    safe_munmap(ptr, sb.st_size);
    safe_close(fd);
    return ret;
}
