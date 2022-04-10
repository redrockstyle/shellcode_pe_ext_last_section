#include <windows.h>
#include <stdio.h>


#define CODE_SIZE   (1024 * 1024)

int main(int argc, char* argv[]) {

    unsigned char* buf = VirtualAlloc(NULL, CODE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    DWORD tmp;
    void (*sc)(void);

    if (argc > 1) {
        HANDLE file = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        ReadFile(file, buf, CODE_SIZE, &tmp, NULL);
        CloseHandle(file);
    }
    else {
        printf("read %d bytes\n", (int)fread(buf, 1, CODE_SIZE, stdin));
    }

    sc = (void(*)(void)) buf;
    (*sc)();

    printf("execute shellcode\n");

    return 0;
}
