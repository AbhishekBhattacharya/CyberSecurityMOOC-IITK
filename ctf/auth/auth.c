//
// This file was generated by the Retargetable Decompiler
// Website: https://retdec.com
// Copyright (c) 2017 Retargetable Decompiler <info@retdec.com>
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ------------------------ Structures ------------------------

struct _IO_FILE {
    int32_t e0;
    char * e1;
    char * e2;
    char * e3;
    char * e4;
    char * e5;
    char * e6;
    char * e7;
    char * e8;
    char * e9;
    char * e10;
    char * e11;
    struct _IO_marker * e12;
    struct _IO_FILE * e13;
    int32_t e14;
    int32_t e15;
    int32_t e16;
    int16_t e17;
    char e18;
    char e19[1];
    char * e20;
    int64_t e21;
    char * e22;
    char * e23;
    char * e24;
    char * e25;
    int32_t e26;
    int32_t e27;
    char e28[40];
};

struct _IO_marker {
    struct _IO_marker * e0;
    struct _IO_FILE * e1;
    int32_t e2;
};

// --------------------- Global Variables ---------------------

struct _IO_FILE * g1 = NULL; // 0x804a040
struct _IO_FILE * g2 = NULL; // 0x804a044

// ------------------------ Functions -------------------------

// From module:   /home/saurabh/Desktop/CS628A-CTF-1-master/6/auth.c
// Address range: 0x804867b - 0x804887f
// Line range:    5 - 39
int main(int argc, char ** argv) {
    char str3[256];
    char str[256];
    char format[40];
    // 0x804867b
    int32_t v1;
    int32_t written2 = v1; // bp-368
    int32_t v2;
    int32_t written = v2; // bp-360
    struct _IO_FILE * v3;
    struct _IO_FILE * fp = v3; // bp-356
    written2 = 0;
    setbuf(g2, NULL);
    struct _IO_FILE * file = fopen("flag.txt", "r"); // 0x80486cf
    if (file == NULL) {
        // 0x80486e6
        fwrite("Failed to open flag file\n", 1, 25, g1);
        exit(1);
        // UNREACHABLE
    }
    // 0x8048707
    fscanf(file, "%39s", &fp);
    puts("Enter the flag\n");
    scanf("%39s", &format);
    written = (int32_t)&str3;
    str3[0] = 89;
    str3[4] = 115;
    str3[8] = 32;
    int32_t v4 = written2; // 0x8048770
    written2 = v4 + 9;
    int32_t chars_printed = snprintf(str, 247 - v4, format);
    int32_t v5 = written2; // 0x80487af
    int32_t v6 = chars_printed; // 0x80487ce
    if (256 - v5 < chars_printed) {
        // 0x80487bd
        v6 = 255 - v5;
        // branch -> 0x80487ce
    }
    // 0x80487ce
    written2 = v6 + v5;
    int32_t strcmp_rc = strcmp(format, (char *)&fp); // 0x80487eb
    int32_t size = 256 - written2; // 0x80487fc
    char * str2 = (char *)(written + written2);
    if (strcmp_rc == 0) {
        // 0x80487f7
        snprintf(str2, size, " which is correct!!\n");
        // branch -> 0x804884f
    } else {
        // 0x8048824
        snprintf(str2, size, " which is incorrect!!\n");
        // branch -> 0x804884f
    }
    // 0x804884f
    puts(str3);
    if (*(int32_t *)20 != *(int32_t *)20) {
        // 0x8048872
        __stack_chk_fail();
        // branch -> 0x8048877
    }
    // 0x8048877
    return 0;
}

// --------------- Dynamically Linked Functions ---------------

// void __stack_chk_fail(void);
// void exit(int status);
// FILE * fopen(const char * restrict filename, const char * restrict modes);
// int fscanf(FILE * restrict stream, const char * restrict format, ...);
// size_t fwrite(const void * restrict ptr, size_t size, size_t n, FILE * restrict s);
// int puts(const char * s);
// int scanf(const char * restrict format, ...);
// void setbuf(FILE * restrict stream, char * restrict buf);
// int snprintf(char * restrict s, size_t maxlen, const char * restrict format, ...);
// int strcmp(const char * s1, const char * s2);

// --------------------- Meta-Information ---------------------

// Detected compiler/packer: gcc (5.4.0)
// Detected language: C
// Detected functions: 1
// Decompiler release: v2.2.1 (2016-09-07)
// Decompilation date: 2017-07-02 14:47:51
