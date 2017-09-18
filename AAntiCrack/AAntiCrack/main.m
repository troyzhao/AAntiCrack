//
//  main.m
//  AAntiCrack
//
//  Created by apple on 2017/9/18.
//  Copyright © 2017年 troy. All rights reserved.
//


#import <Foundation/Foundation.h>
#include <getopt.h>
#include <sys/stat.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#define SwapIfNeed( x, magic ) (should_swap_bytes(magic)?OSSwapInt32(x):x)
#define print( format, ... )    printf( format"\n", ##__VA_ARGS__)

#define OPT_REPLACE_RESTRICT 1


struct option longopts[] = {
    { "inject-dylib",           required_argument,  NULL, 'i' },
    { "replace-restrict",       no_argument,        NULL, OPT_REPLACE_RESTRICT },
};

int should_swap_bytes(uint32_t magic) {
    return magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == FAT_CIGAM;
}

void print_usage();

int inject_dylib(FILE *pf, uint32_t offset, uint32_t magic, const char *dylib_path);

/**
 overwrite the __RESTRICT segment
 
 @param pf the file handler of binary
 @param offset cpu architecture offset in the binary file
 @param magic architecture code  MH_CIGAM,MH_CIGAM_64 etc.
 */
void overwriteRestrict(FILE *pf, uint32_t offset, uint32_t magic);


int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // insert code here...
        
        if (argc < 2) {
            print_usage();
            return 1;
        }
        
        char *dylib_path = NULL;
        
        int ch;
        int replace_restrict = 0;
        while ( (ch = getopt_long(argc, (char *const *)argv, "i:", longopts, NULL)) != -1) {
            switch (ch) {
                case 'i':
                    // injection
                    dylib_path = (char *)malloc(strlen(optarg) + 1);
                    strcpy(dylib_path, optarg);
                    break;
                case OPT_REPLACE_RESTRICT:
                    replace_restrict = 1;
                    break;
                default:
                    break;
            }
        }
        
        if (argc - optind < 1) {
            print("error: binary file dose not exist!");
            exit(1);
        }
        
        // get binary file
        const char *binary_file = argv[optind];
        
        struct stat s;
        
        if (stat(binary_file, &s) != 0) {
            perror(binary_file);
            exit(1);
        }
        
        FILE *f = fopen(binary_file, "r+");
        
        if(!f) {
            printf("Couldn't open file %s\n", binary_file);
            exit(1);
        }
        
        uint32_t magic;
        fread(&magic, sizeof(uint32_t), 1, f);
        
        switch(magic) {
            case FAT_MAGIC:
            case FAT_CIGAM: {
                print( "Fat binary." );
                fseeko(f, 0, SEEK_SET);
                struct fat_header fh;
                fread(&fh, sizeof(fh), 1, f);
                uint32_t num_arch = SwapIfNeed(fh.nfat_arch, magic);
                
                struct fat_arch archs[num_arch];
                fread(archs, sizeof(archs), 1, f);
                
                for (int i = 0; i < num_arch; i++) {
                    uint32_t offset = SwapIfNeed(archs[i].offset, magic);
                    
                    if (replace_restrict) {
                        overwriteRestrict(f, offset, magic);
                    }
                    
                    // inject dylib
                    if (dylib_path != NULL && stat(dylib_path, &s) == 0) {
                        fseeko(f, 0, SEEK_SET);
                        
                        if ( !inject_dylib(f, offset, magic, dylib_path) )
                        {
                            print("    ... Inject  failure!");
                        }
                        
                    }
                    else {
                        print("dylib file is bad!");
                        perror(binary_file);
                    }
                }
                
                
            }
                break;
            case MH_MAGIC_64:
            case MH_CIGAM_64:
            case MH_MAGIC:
            case MH_CIGAM:
                print("Thin binary.");
                if (replace_restrict) { overwriteRestrict(f, 0, magic); }
                // inject dylib
                if (dylib_path != NULL && stat(dylib_path, &s) == 0) {
                    print("Inject dylib %s", dylib_path);
                    fseeko(f, 0, SEEK_SET);
                    inject_dylib(f, 0, magic, dylib_path);
                }
                else {
                    print("dylib file is bad!");
                    perror(binary_file);
                }
                break;
                
            default:
                fclose(f);
                printf("Unknown magic: 0x%x\n ** please contact author **\n", magic);
                exit(1);
        }
        
        fclose(f);
        
    }
    return 0;
}

void print_usage(void)
{
    fprintf(stderr,
            "AAntiCrack \n"
            "Usage: AAntiCrack [options] <mach-o-file>\n"
            "\n"
            "  where options are:\n"
            "        -i <dylib-file>    specify the dylib file who would be injected to mach-o file\n"
            "        --replace-restrict replace the LC_SEGMENT(__RESTRICT,__restrict) command if exist\n"
            "\n\n"
            );
}

__attribute__((format(printf, 1, 2))) bool ask(const char *format, ...) {
    char *question;
    asprintf(&question, "%s [y/n] ", format);
    
    va_list args;
    va_start(args, format);
    vprintf(question, args);
    va_end(args);
    
    free(question);
    
    while(true) {
        char *line = NULL;
        size_t size;
        
        getline(&line, &size, stdin);
        
        switch(line[0]) {
            case 'y':
            case 'Y':
                return true;
                break;
            case 'n':
            case 'N':
                return false;
                break;
            default:
                printf("Please enter y or n: ");
        }
    }
}

int inject_dylib(FILE *pf, uint32_t offset, uint32_t magic, const char *dylib_path) {
    fseeko(pf, offset, SEEK_SET);
    struct mach_header header = {0};
    fread(&header, sizeof(header), 1, pf);
    
    
    uint32_t arch_magic = SwapIfNeed(header.magic, header.magic);
    
    int is_64bit = (arch_magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
    print("Inject dylib %s to %s arch", dylib_path, is_64bit?"64 Bit":"32 Bit");
    
    uint32_t last_cmd_offset = offset;
    if (arch_magic == MH_CIGAM_64 || arch_magic == MH_MAGIC_64) {
        last_cmd_offset += sizeof(struct mach_header_64);
    }
    else {
        last_cmd_offset += sizeof(struct mach_header);
    }
    last_cmd_offset += SwapIfNeed(header.sizeofcmds, arch_magic);
    
    char dylib_load_path[256] = {0};
    sprintf(dylib_load_path, "@executable_path/%s", dylib_path);
    size_t dylib_path_len = strlen(dylib_load_path);
    int padding = 8;
    uint32_t dylib_path_len_padding = (dylib_path_len + padding - 1) & ~(padding-1);
    uint32_t dylib_cmd_size = (uint32_t)(sizeof(struct dylib_command) + dylib_path_len_padding);
    
    struct dylib_command dc = {
        .cmd = SwapIfNeed(LC_LOAD_DYLIB, arch_magic),
        .cmdsize = dylib_cmd_size,
        .dylib = {
            .name.offset = SwapIfNeed(sizeof(struct dylib_command), arch_magic),
            .timestamp = 0,
            .current_version = 1,
            .compatibility_version = 1
        }
    };
    
    // check if space is enough
    char empty_space[dylib_cmd_size];
    fseeko(pf, last_cmd_offset, SEEK_SET);
    fread(empty_space, dylib_cmd_size, 1, pf);
    
    int is_enough = 1;
    for (int i = 0; i < dylib_cmd_size; i++) {
        if (empty_space[i] != 0) {
            is_enough = 0;
            break;
        }
    }
    
    if (!is_enough) {
        if(!ask("It seem like that there is not enough empty space. Continue anyway?")) {
            return 0;
        }
    }
    
    fseeko(pf, -((off_t)dylib_cmd_size), SEEK_CUR);
    fwrite(&dc, sizeof(struct dylib_command), 1, pf);
    
    char *dylib_path_with_padding = (char *)malloc(dylib_path_len_padding);
    strcpy(dylib_path_with_padding, dylib_load_path);
    fwrite(dylib_path_with_padding, dylib_path_len_padding, 1, pf);
    free(dylib_path_with_padding);
    
    // command count + 1
    header.ncmds = SwapIfNeed(header.ncmds + 1, arch_magic);
    header.sizeofcmds = SwapIfNeed(header.sizeofcmds + dylib_cmd_size, arch_magic);
    
    fseeko(pf, offset, SEEK_SET);
    fwrite(&header, sizeof(header), 1, pf);
    fflush(pf);
    print("Inject finish.");
    return 1;
}


void overwriteRestrict(FILE *pf, uint32_t offset, uint32_t magic) {
    fseeko(pf, offset, SEEK_SET);
    
    struct mach_header header = {0};
    fread(&header, sizeof(header), 1, pf);
    
    uint32_t arch_magic = SwapIfNeed(header.magic, header.magic);
    uint32_t cmd_count = SwapIfNeed(header.ncmds, header.magic);
    
    off_t cmd_offset = sizeof(struct mach_header);
    
    if (arch_magic == MH_CIGAM_64 || arch_magic == MH_MAGIC_64) {
        cmd_offset = sizeof(struct mach_header_64);
    }
    
    print("load command count %u", cmd_count);
    
    // seek to Load Commands position
    fseeko(pf, offset + cmd_offset, SEEK_SET);
    
    for (int i = 0; i < cmd_count; i++) {
        struct load_command lc;
        off_t lc_offset = ftello(pf);
        fread(&lc, sizeof(lc), 1, pf);
        fseeko(pf, -sizeof(lc), SEEK_CUR);
        
        if (lc.cmd == LC_SEGMENT) {
            struct segment_command sc = {0};
            fread(&sc, sizeof(sc), 1, pf);
            if (strcmp(sc.segname, "__RESTRICT") == 0) {
                uint32_t sect_count = SwapIfNeed(sc.nsects, arch_magic);
                
                print("Rewrite %s with %u sections", sc.segname, sect_count );
                
                strcpy(sc.segname, "__SESTRICT");
                
                fseeko(pf, -sizeof(sc), SEEK_CUR);
                fwrite(&sc, sizeof(sc), 1, pf);
                
                for (int j = 0; j < sect_count; j++ ) {
                    struct section sect = {0};
                    fread(&sect, sizeof(sect), 1, pf);
                    if (strcmp(sect.sectname, "__restrict") == 0) { // strcmp(sect.sectname, "__RESTRICT") == 0 ||
                        // memset(sect.sectname, 0, sizeof(sect.sectname));
                        strcpy(sect.sectname, "__sestrict");
                    }
                    if (strcmp(sect.segname, "__RESTRICT") == 0 ) {
                        strcpy(sect.segname, "__SESTRICT");
                    }
                    
                    // write back
                    fseeko(pf, -sizeof(sect), SEEK_CUR);
                    fwrite(&sect, sizeof(sect), 1, pf);
                }
                
            }
            
        }
        else if (lc.cmd == LC_SEGMENT_64) {
            struct segment_command_64 sc = {0};
            fread(&sc, sizeof(sc), 1, pf);
            if (strcmp(sc.segname, "__RESTRICT") == 0) {
                uint32_t sect_count = SwapIfNeed(sc.nsects, arch_magic);
                
                print("Rewrite %s with %u sections", sc.segname, sect_count );
                
                strcpy(sc.segname, "__SESTRICT");
                
                fseeko(pf, -sizeof(sc), SEEK_CUR);
                fwrite(&sc, sizeof(sc), 1, pf);
                
                for (int j = 0; j < sect_count; j++ ) {
                    struct section_64 sect = {0};
                    fread(&sect, sizeof(sect), 1, pf);
                    if (strcmp(sect.sectname, "__restrict") == 0) {
                        strcpy(sect.sectname, "__sestrict");
                    }
                    if (strcmp(sect.segname, "__RESTRICT") == 0 ) {
                        strcpy(sect.segname, "__SESTRICT");
                    }
                    
                    // write back
                    fseeko(pf, -sizeof(sect), SEEK_CUR);
                    fwrite(&sect, sizeof(sect), 1, pf);
                }
                
            }
            fseeko(pf, sc.cmdsize, SEEK_CUR);
        }
        
        fseeko(pf, lc_offset + lc.cmdsize, SEEK_SET);
    }
    
    fflush(pf);
    
}
