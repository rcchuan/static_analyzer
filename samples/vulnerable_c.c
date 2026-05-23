/* Sample vulnerable C code for testing */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUF 64

// CWE-798: Hardcoded password
const char* ADMIN_PASSWORD = "password123";

void unsafe_input(char* dest) {
    // CWE-120: gets() - no bounds checking
    gets(dest);
    
    // CWE-120: strcpy without size check  
    char src[256];
    scanf("%s", src);
    strcpy(dest, src);
}

int authenticate(char* argv[]) {
    char buffer[MAX_BUF];
    
    // CWE-78: Command injection via argv
    system(argv[1]);
    
    // CWE-134: Format string vulnerability
    printf(buffer);
    
    // CWE-476: NULL pointer dereference risk
    int* ptr = (int*)malloc(sizeof(int) * 10);
    *ptr = 999;   // no NULL check after malloc
    
    // CWE-120: memcpy without bounds check
    char dst[16];
    memcpy(dst, buffer, 256);  // overflow!
    
    // CWE-415: Double free
    free(ptr);
    free(ptr);  // double free!
    
    return 0;
}

// CWE-190: Integer overflow
int add_values(int a, int b) {
    int result = a + b;  // no overflow check
    return result;
}
