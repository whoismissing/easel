#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

// gcc chall.c -no-pie -O0 -o chall

void xor(char * src, int src_len, char key) {
    int ii = 0;
    for (ii = 0; ii < src_len; ii++) {
        src[ii] ^= key;    
    }
}

int main(int argc, char * argv[]) {

    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        puts("Process is being traced\n");
        exit(1);         
    }

    if (argc < 2) {
        puts("Not enough cmdline args\n");
        printf("Usage: %s [password]\n", argv[0]);
        exit(2);
    }

    char buf[21 + 1] = { '>', 0x01, 0x06, 'I', 0x00, 0x1a, 'I', 0x03, 0x06, 0x0c, 'V',
        'I', '#', 0x06, 0x0c, 'I', '$', '(', '$', '(', 'H', 0x00 };

    xor(argv[1], 21, 'i');

    if (memcmp(argv[1], buf, 21) == 0) {
        puts("You got the flag!\n");
    } else {
        puts("Wrong password\n");
    }

    return 0;
}
