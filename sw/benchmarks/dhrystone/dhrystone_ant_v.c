/*
 * Dhrystone 2.2 Benchmark adapted for ANT-V (CVE2 + Vector) simulation
 */

#include <stdint.h>

#define NUMBER_OF_RUNS 500

#define TESTUTIL_HALT          (*(volatile uint32_t *)0x20000)
#define TESTUTIL_SIG_BEGIN     (*(volatile uint32_t *)0x20004)
#define TESTUTIL_SIG_END       (*(volatile uint32_t *)0x20008)

volatile uint32_t benchmark_signature[8] __attribute__((aligned(16)));

static inline uint32_t read_cycles(void) {
    uint32_t c;
    __asm__ volatile ("csrr %0, mcycle" : "=r"(c));
    return c;
}

static inline uint32_t read_instret(void) {
    uint32_t i;
    __asm__ volatile ("csrr %0, minstret" : "=r"(i));
    return i;
}

/* Standard Dhrystone defines and types */
typedef enum { Ident_1, Ident_2, Ident_3, Ident_4, Ident_5 } Enumeration;

typedef struct record {
    struct record *Ptr_Comp;
    Enumeration Discr;
    union {
        struct {
            Enumeration Enum_Comp;
            int Int_Comp;
            char Str_Comp[31];
        } var_1;
    } variant;
} Rec_Type, *Rec_Pointer;

Rec_Type Record_Glob1, Record_Glob2;
Rec_Pointer Ptr_Glob, Next_Ptr_Glob;
int Int_Glob;
int Bool_Glob;
char Ch_1_Glob, Ch_2_Glob;
int Arr_1_Glob[50];
int Arr_2_Glob[50][50];

void *memset(void *s, int c, unsigned int n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

void *memcpy(void *dest, const void *src, unsigned int n) {
    char *d = (char *)dest;
    const char *s = (const char *)src;
    while (n--) *d++ = *s++;
    return dest;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

void Proc_3(Rec_Pointer *Ptr_Ref_Par);
void Proc_6(Enumeration Enum_Val_Par, Enumeration *Enum_Ref_Par);
void Proc_7(int Int_1_Par_Val, int Int_2_Par_Val, int *Int_Par_Ref);
void Proc_8(int Arr_1_Par_Ref[], int Arr_2_Par_Ref[][50], int Int_1_Par_Val, int Int_2_Par_Val);
Enumeration Func_1(char Ch_1_Par_Val, char Ch_2_Par_Val);
int Func_2(char Str_1_Par_Ref[], char Str_2_Par_Ref[]);
int Func_3(Enumeration Enum_Par_Val);

void Proc_1(Rec_Pointer Ptr_Val_Par) {
    Rec_Pointer Next_Record = Ptr_Val_Par->Ptr_Comp;
    *Ptr_Val_Par->Ptr_Comp = *Ptr_Glob;
    Ptr_Val_Par->variant.var_1.Int_Comp = 5;
    Next_Record->variant.var_1.Int_Comp = Ptr_Val_Par->variant.var_1.Int_Comp;
    Next_Record->Ptr_Comp = Ptr_Val_Par->Ptr_Comp;
    Proc_3(&Next_Record->Ptr_Comp);
    if (Next_Record->Discr == Ident_1) {
        Next_Record->variant.var_1.Int_Comp = 6;
        Proc_6(Ptr_Val_Par->variant.var_1.Enum_Comp, &Next_Record->variant.var_1.Enum_Comp);
        Next_Record->Ptr_Comp = Ptr_Glob->Ptr_Comp;
        Proc_7(Next_Record->variant.var_1.Int_Comp, 10, &Next_Record->variant.var_1.Int_Comp);
    } else {
        *Ptr_Val_Par = *Ptr_Val_Par->Ptr_Comp;
    }
}

void Proc_2(int *Int_Par_Ref) {
    int Int_Loc = *Int_Par_Ref + 10;
    Enumeration Enum_Loc;
    do {
        if (Ch_1_Glob == 'A') {
            Int_Loc -= 1;
            *Int_Par_Ref = Int_Loc - Int_Glob;
            Enum_Loc = Ident_1;
        }
    } while (Enum_Loc != Ident_1);
}

void Proc_3(Rec_Pointer *Ptr_Ref_Par) {
    if (Ptr_Glob != 0) {
        *Ptr_Ref_Par = Ptr_Glob->Ptr_Comp;
    }
    Proc_7(10, Int_Glob, &Ptr_Glob->variant.var_1.Int_Comp);
}

void Proc_4(void) {
    int Bool_Loc = Ch_1_Glob == 'A';
    Bool_Glob = Bool_Loc | Bool_Glob;
    Ch_2_Glob = 'B';
}

void Proc_5(void) {
    Ch_1_Glob = 'A';
    Bool_Glob = 0;
}

void Proc_6(Enumeration Enum_Val_Par, Enumeration *Enum_Ref_Par) {
    *Enum_Ref_Par = Enum_Val_Par;
    if (!Func_3(Enum_Val_Par)) {
        *Enum_Ref_Par = Ident_4;
    }
    switch (Enum_Val_Par) {
        case Ident_1: *Enum_Ref_Par = Ident_1; break;
        case Ident_2: *Enum_Ref_Par = (Int_Glob > 100) ? Ident_1 : Ident_4; break;
        case Ident_3: *Enum_Ref_Par = Ident_2; break;
        case Ident_4: break;
        case Ident_5: *Enum_Ref_Par = Ident_3; break;
    }
}

void Proc_7(int Int_1_Par_Val, int Int_2_Par_Val, int *Int_Par_Ref) {
    int Int_Loc = Int_1_Par_Val + 2;
    *Int_Par_Ref = Int_2_Par_Val + Int_Loc;
}

void Proc_8(int Arr_1_Par_Ref[], int Arr_2_Par_Ref[][50], int Int_1_Par_Val, int Int_2_Par_Val) {
    int Int_Loc = Int_1_Par_Val + 5;
    Arr_1_Par_Ref[Int_Loc] = Int_2_Par_Val;
    Arr_1_Par_Ref[Int_Loc+1] = Arr_1_Par_Ref[Int_Loc];
    Arr_1_Par_Ref[Int_Loc+30] = Int_Loc;
    for (int Int_Index = Int_Loc; Int_Index <= Int_Loc+1; ++Int_Index) {
        Arr_2_Par_Ref[Int_Loc][Int_Index] = Int_Loc;
    }
    Arr_2_Par_Ref[Int_Loc][Int_Loc-1] += 1;
    Arr_2_Par_Ref[Int_Loc+20][Int_Loc] = Arr_1_Par_Ref[Int_Loc];
    Int_Glob = 5;
}

Enumeration Func_1(char Ch_1_Par_Val, char Ch_2_Par_Val) {
    char Ch_1_Loc = Ch_1_Par_Val;
    char Ch_2_Loc = Ch_1_Loc;
    return (Ch_2_Loc != Ch_2_Par_Val) ? Ident_1 : Ident_2;
}

int Func_2(char Str_1_Par_Ref[], char Str_2_Par_Ref[]) {
    int Int_Loc = 2;
    char Ch_Loc;
    while (Int_Loc <= 2) {
        if (Func_1(Str_1_Par_Ref[Int_Loc], Str_2_Par_Ref[Int_Loc+1]) == Ident_1) {
            Ch_Loc = 'A';
            Int_Loc += 1;
        }
    }
    if (Ch_Loc >= 'W' && Ch_Loc < 'Z') Int_Loc = 7;
    if (Ch_Loc == 'R') return 1;
    else {
        if (strcmp(Str_1_Par_Ref, Str_2_Par_Ref) > 0) {
            Int_Loc += 7;
            return 1;
        } else return 0;
    }
}

int Func_3(Enumeration Enum_Par_Val) {
    return (Enum_Par_Val == Ident_3) ? 1 : 0;
}

int main(void) {
    int Int_1_Loc, Int_2_Loc, Int_3_Loc;
    char Ch_Index;
    Enumeration Enum_Loc;
    char Str_1_Loc[31], Str_2_Loc[31];

    Next_Ptr_Glob = &Record_Glob1;
    Ptr_Glob = &Record_Glob2;

    Ptr_Glob->Ptr_Comp = Next_Ptr_Glob;
    Ptr_Glob->Discr = Ident_1;
    Ptr_Glob->variant.var_1.Enum_Comp = Ident_3;
    Ptr_Glob->variant.var_1.Int_Comp = 40;
    strcpy(Ptr_Glob->variant.var_1.Str_Comp, "DHRYSTONE PROGRAM, SOME STRING");
    strcpy(Str_1_Loc, "DHRYSTONE PROGRAM, 1'ST STRING");
    Arr_2_Glob[8][7] = 10;

    uint32_t start_cycles = read_cycles();
    uint32_t start_instr = read_instret();

    for (int Run_Index = 1; Run_Index <= NUMBER_OF_RUNS; ++Run_Index) {
        Proc_5();
        Proc_4();
        Int_1_Loc = 2;
        Int_2_Loc = 3;
        strcpy(Str_2_Loc, "DHRYSTONE PROGRAM, 2'ND STRING");
        Enum_Loc = Ident_2;
        Bool_Glob = !Func_2(Str_1_Loc, Str_2_Loc);
        while (Int_1_Loc < Int_2_Loc) {
            Int_3_Loc = 5 * Int_1_Loc - Int_2_Loc;
            Proc_7(Int_1_Loc, Int_2_Loc, &Int_3_Loc);
            Int_1_Loc += 1;
        }
        Proc_8(Arr_1_Glob, Arr_2_Glob, Int_1_Loc, Int_3_Loc);
        Proc_1(Ptr_Glob);
        for (Ch_Index = 'A'; Ch_Index <= Ch_2_Glob; ++Ch_Index) {
            if (Enum_Loc == Func_1(Ch_Index, 'C')) {
                Proc_6(Ident_1, &Enum_Loc);
                strcpy(Str_2_Loc, "DHRYSTONE PROGRAM, 3'RD STRING");
                Int_2_Loc = Run_Index;
                Int_Glob = Run_Index;
            }
        }
        Int_2_Loc = Int_2_Loc * Int_1_Loc;
        Int_1_Loc = Int_2_Loc / Int_3_Loc;
        Int_2_Loc = 7 * (Int_2_Loc - Int_3_Loc) - Int_1_Loc;
        Proc_2(&Int_1_Loc);
    }

    uint32_t end_cycles = read_cycles();
    uint32_t end_instr = read_instret();

    uint32_t total_cycles = end_cycles - start_cycles;
    uint32_t total_instr = end_instr - start_instr;

    /* Verify results */
    int pass = 1;
    if (Int_Glob != 5) pass = 0;
    if (Bool_Glob != 1) pass = 0;
    if (Ch_1_Glob != 'A') pass = 0;
    if (Ch_2_Glob != 'B') pass = 0;
    if (Arr_1_Glob[8] != 7) pass = 0;
    if (Arr_2_Glob[8][7] != NUMBER_OF_RUNS + 10) pass = 0;
    if (Int_1_Loc != 5) pass = 0;
    if (Int_2_Loc != 13) pass = 0;
    if (Int_3_Loc != 7) pass = 0;
    if (Enum_Loc != Ident_1) pass = 0;

    /* Record signature */
    benchmark_signature[0] = total_cycles;
    benchmark_signature[1] = total_instr;
    benchmark_signature[2] = NUMBER_OF_RUNS;
    benchmark_signature[3] = Int_Glob;
    benchmark_signature[4] = Bool_Glob;
    benchmark_signature[5] = (Ch_1_Glob << 8) | Ch_2_Glob;
    benchmark_signature[6] = Arr_1_Glob[8];
    benchmark_signature[7] = Arr_2_Glob[8][7];

    /* Set signature address range in test utility */
    TESTUTIL_SIG_BEGIN = (uint32_t)&benchmark_signature[0];
    TESTUTIL_SIG_END   = (uint32_t)&benchmark_signature[8];

    /* Terminate simulation */
    TESTUTIL_HALT = 1;

    return 0;
}
