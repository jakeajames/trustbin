#import <Foundation/Foundation.h>
#include <err.h>
#include <sys/mman.h>

#include "kern_utils.h"
#include "patchfinder64.h"
#include "amfi_utils.h"

mach_port_t tfp0;
uint64_t kernel_base;
uint64_t kernel_slide;

//Jonathan Seals: https://github.com/JonathanSeals/kernelversionhacker
uint64_t find_kernel_base() {
#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS_IOS10 0xfffffff007004000
#define KERNEL_SEARCH_ADDRESS_IOS9 0xffffff8004004000
#define KERNEL_SEARCH_ADDRESS_IOS 0xffffff8000000000
    
#define ptrSize sizeof(uintptr_t)
    
    uint64_t addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;
    
    
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(tfp0, addr, 0x200, (vm_offset_t*)&buf, &sz);
        
        if (ret) {
            goto next;
        }
        
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(tfp0, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(tfp0, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    
                    printf("[*] kernel base: 0x%llx\n", addr);
                    
                    return addr;
                }
            }
        }
        
    next:
        addr -= 0x200000;
    }
}

//from xerub
static int strtail(const char *str, const char *tail)
{
    size_t lstr = strlen(str);
    size_t ltail = strlen(tail);
    if (ltail > lstr) {
        return -1;
    }
    str += lstr - ltail;
    return memcmp(str, tail, ltail);
}

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

kern_return_t trustbin(NSMutableArray *paths) {
    uint64_t trust_chain = find_trustcache();
    
    printf("[*] trust_chain at 0x%llx\n", trust_chain);
     
    struct trust_chain fake_chain;
    fake_chain.next = kread64(trust_chain);
    *(uint64_t *)&fake_chain.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&fake_chain.uuid[8] = 0xabadbabeabadbabe;
    
    int cnt = 0;
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    hash_t *allhash = malloc(sizeof(hash_t) * [paths count]);
    for (int i = 0; i != [paths count]; ++i) {
        uint8_t *cd = getCodeDirectory((char*)[[paths objectAtIndex:i] UTF8String]);
        if (cd != NULL) {
            getSHA256inplace(cd, hash);
            memmove(allhash[cnt], hash, sizeof(hash_t));
            ++cnt;
        }
        else {
            printf("[-] CD NULL\n");
            continue;
        }
    }
    
    fake_chain.count = cnt;
    
    size_t length = (sizeof(fake_chain) + cnt * sizeof(hash_t) + 0xFFFF) & ~0xFFFF;
    uint64_t kernel_trust = kalloc(length);
    printf("[*] allocated: 0x%zx => 0x%llx\n", length, kernel_trust);
    
    kwrite(kernel_trust, &fake_chain, sizeof(fake_chain));
    kwrite(kernel_trust + sizeof(fake_chain), allhash, cnt * sizeof(hash_t));
    kwrite64(trust_chain, kernel_trust);
}

int main(int argc, char **argv, char **envp) {
    
    if (argc != 2) {
        printf("[-] Please pass a directory with binaries to trust\n");
        return 0;
    }
    printf("[*] Initializing\n");
        
    kern_return_t ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);
    
    if (ret != KERN_SUCCESS) {
        fprintf(stderr,"[-] Failed host_get_special_port 4 with error: %s\n", mach_error_string(err));
        return -1;
    }
    printf("[*] Got tfp0!\n");

    kernel_base = find_kernel_base();
    init_kernel_utils(tfp0);
    init_kernel(kernel_base, NULL);
    kernel_slide = kernel_base - 0xFFFFFFF007004000;
    fprintf(stderr,"[*] kaslr slide: 0x%016llx\n", kernel_slide);
    
    NSMutableArray *arr = [NSMutableArray array];
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    BOOL isDir = NO;
    if (![fileManager fileExistsAtPath:@(argv[1]) isDirectory:&isDir]) {
        printf("[-] Path does not exist!\n");
        return -1;
    }
    
    NSURL *directoryURL = [NSURL URLWithString:@(argv[1])];
    NSArray *keys = [NSArray arrayWithObject:NSURLIsDirectoryKey];
    
    if (isDir) {
        NSDirectoryEnumerator *enumerator = [fileManager
                                             enumeratorAtURL:directoryURL
                                             includingPropertiesForKeys:keys
                                             options:0
                                             errorHandler:^(NSURL *url, NSError *error) {
                                                 if (error) printf("[-] %s\n", [[error localizedDescription] UTF8String]);
                                                 return YES;
                                             }];
        
        for (NSURL *url in enumerator) {
            NSError *error;
            NSNumber *isDirectory = nil;
            if (![url getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:&error]) {
                if (error) continue;
            }
            else if (![isDirectory boolValue]) {
                
                int rv;
                int fd;
                uint8_t *p;
                off_t sz;
                struct stat st;
                uint8_t buf[16];
                
                char *fpath = strdup([[url path] UTF8String]);
                
                if (strtail(fpath, ".plist") == 0 || strtail(fpath, ".nib") == 0 || strtail(fpath, ".strings") == 0 || strtail(fpath, ".png") == 0) {
                    continue;
                }
                
                rv = lstat(fpath, &st);
                if (rv || !S_ISREG(st.st_mode) || st.st_size < 0x4000) {
                    continue;
                }
                
                fd = open(fpath, O_RDONLY);
                if (fd < 0) {
                    continue;
                }
                
                sz = read(fd, buf, sizeof(buf));
                if (sz != sizeof(buf)) {
                    close(fd);
                    continue;
                }
                if (*(uint32_t *)buf != 0xBEBAFECA && !MACHO(buf)) {
                    close(fd);
                    continue;
                }
                
                p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
                if (p == MAP_FAILED) {
                    close(fd);
                    continue;
                }
                
                [arr addObject:@(fpath)];
                printf("[*] Will trust %s\n", fpath);
            }
        }
        trustbin(arr);
    }
    else {
        printf("[*] Will trust %s\n", argv[1]);
        [arr addObject:@(argv[1])];
        trustbin(arr);
    }
	return 0;
}

// vim:ft=objc
