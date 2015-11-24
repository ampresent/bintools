#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <errno.h>
#include <string.h>
#include <libdasm.h>

#define OFFSET_OEP 24

long Ptrace(enum __ptrace_request request, pid_t pid, void *addr,void *data){
    long result;
    result = ptrace(request, pid, addr, data);
    if (request != PTRACE_PEEKTEXT && request != PTRACE_PEEKDATA &&
            request != PTRACE_PEEKUSER && result < 0){
        perror("Ptrace failed: ");
        exit(-1);
    }
    return result;
}

int get_single_instruction(char* bytes, char* str, size_t bufsize){
    INSTRUCTION inst;
    int len = 0;
    len = get_instruction(&inst, bytes, MODE_32);
    get_instruction_string(&inst, FORMAT_ATT, 0, str, bufsize);
    return len;
}

int get_single_instruction_word(unsigned word, char* str, size_t bufsize){
    char bytes[4];
    sprintf(bytes, "%c%c%c%c", word&0xff, (word>>8)&0xff, (word>>16)&0xff, (word>>24)&0xff);
    return get_single_instruction(bytes, str, bufsize);
}

unsigned get_entry_point(const char * filename){
    FILE* file;
    unsigned oep = 0;
    file = fopen(filename, "r");
    fseek(file, OFFSET_OEP, SEEK_SET);
    fread(&oep, 4, 1, file);
    fclose(file);
    return oep;
}

int main(){
    int wait_status;
    int len;
    int offset;
    unsigned ban;
    unsigned bp;
    unsigned backup;
    unsigned addr;
    unsigned data;
    unsigned buff;
    unsigned oep;
    struct user_regs_struct regs;
    char inst_str[128];

    char indirect = 0;
    char manual = 0;
    char plt = 1;
    int pop = 0;
    ban = 0x0804841b;
    const char *prog = "./try";

    pid_t pid = fork();
    if (pid == 0){
        Ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(prog, prog, NULL);
    }else if (pid > 0){
        oep = get_entry_point(prog);
        wait(&wait_status);

        if (WIFSTOPPED(wait_status)){
            bp = oep;
            backup = Ptrace(PTRACE_PEEKTEXT, pid, (void*)bp, NULL);
            buff = (backup&0xffffff00u)|0xccu;
            Ptrace(PTRACE_POKETEXT, pid, (void*)bp, (void*)buff);
            Ptrace(PTRACE_CONT, pid, NULL, NULL);
            wait(&wait_status);
        }

        // Break at Entry Point, I'm not sure of the need to break at oep
        if (WIFSTOPPED(wait_status)){
            Ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            regs.eip -= 1;
            Ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            // Restore
            Ptrace(PTRACE_POKETEXT, pid, (void*)bp, (void*)backup);

            if (indirect){
                bp = Ptrace(PTRACE_PEEKTEXT, pid, (void*)ban, NULL);
            }else{
                bp = ban;
            }

            backup = Ptrace(PTRACE_PEEKTEXT, pid, (void*)bp, NULL);

            buff = (backup&0xffffff00)|0xCC;

            Ptrace(PTRACE_POKETEXT, pid, (void*)bp, (void*)buff);
            Ptrace(PTRACE_CONT, pid, NULL, NULL);
            wait(&wait_status);
        }

        while (!WIFEXITED(wait_status) && WIFSTOPPED(wait_status)){
            Ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (regs.eip == bp + 1){
                regs.eip -= 1;
                Ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                // BUT THIS MAKES THE BREAKPOINT INVALID, SO WHILE NO USE!!!
                // CORRECT THIS LATAR
                Ptrace(PTRACE_POKETEXT, pid, (void*)regs.eip, (void*)backup);

                if (mitm){
                    if (plt || manual){

                    }else{

                    }
                }
                else if (disable){
                    if (plt || manual){
                        backup = Ptrace(PTRACE_PEEKTEXT, pid, (void*)regs.eip, NULL);
                        if (plt || pop==0)
                            buff = (backup & 0xffffff00) | 0xc3;
                        else
                            buff = (backup & 0xff000000) | 0xc2 | ((pop<<8)&0xffff00);
                        // Seems don't need to restore
                        Ptrace(PTRACE_POKETEXT, pid, (void*)regs.eip, (void*)buff);
                        Ptrace(PTRACE_CONT, pid, NULL, NULL);
                    }else{
                        // An automatic approach
                        offset = 0;
                        data = Ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.eip+offset), NULL);
                        len = get_single_instruction_word(data, inst_str, 128);
                        while (strncmp(inst_str, "retn", 4) && strncmp(inst_str, "ret", 3)){
                            offset += len;
                            data = Ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.eip+offset), NULL);
                            len = get_single_instruction_word(data, inst_str, 128);
                        }
                        regs.eip += offset;
                        Ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                        Ptrace(PTRACE_CONT, pid, NULL, NULL);
                    }
                }
            }
            wait(&wait_status);
        }
    }else{
        perror("Folk failed: ");
        exit(-1);
    }
    return 0;
}
