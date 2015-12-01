#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <errno.h>
#include <string.h>
#include <libdasm.h>
#include <limits.h>

#define OFFSET_OEP        24
#define MAX_MODULES       128

#define UTILITY_TYPE      unsigned
#define HANDLER_ID        unsigned
#define BOOL              int

#define TRUE              1
#define FALSE             0

#define UTILITY_DISABLE   1
#define UTILITY_MITM      2
#define UTILITY_TRACE     3
#define GLOBAL_REPAIR     4

#define MAX_HASH          65536

// When we need to traverse though list as well as
// Remove some elements
/*
#define ITER_WITH_DEL(p, h, nf, delay) for((p)=&(h);*(p);((delay)&&((p)=&((*(p))->nf))), delay=FALSE)
#define ITER_WITH_ADD(p, h, nf, proceed) for((p)=&(h);*(p); ((proceed)&&((p)==&(h))&&((p)=&((*(p))->nf))), (p)=&((*(p))->nf), proceed=FALSE)
#define DELAY(delay) ((delay)=1)
#define UNLINK(p, nf) (*(p)=(*(p))->nf)
*/
#define GET(p, a) ((*(p))->a)

unsigned priorityarray[] = {
    UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX,
    5,//PTRACE_CONT 7
    0,//PTRACE_KILL 8
    4,//PTRACE_SINGLESTEP 9
    UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX,
    3,//PTRACE_ATTACH 16
    1,//PTRACE_DETACH 17
    UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX,
    2,//PTRACE_SYSCALL 24
};

#define PRIORITY(pr1,pr2) (priorityarray[(pr1)]<priorityarray[(pr2)]?(pr1):(pr2))
#define GETID(ip) ((ip)&((MAX_HASH)-1))

struct Module{
    char* module_name;
    unsigned base;
    unsigned length;
    struct Module* next_module;
};

struct Option{
    UTILITY_TYPE utility;
    unsigned ip;
    unsigned life;
    FILE* file;
    struct Module* whitelist;
};

struct Handler{
    UTILITY_TYPE utility;
    unsigned ip;
    BOOL global_flag;
    // The readonly part of Handler
    struct Option* option;           // Options
    // A duplicate of Option.life
    unsigned life;                   // The life of the handler
    unsigned backup;                 // Backup of the memory on the breakpoint
    struct Handler* next_handler;    // Pointer to next handler on the list
    struct Handler* prev_handler;    // Pointer to next handler on the list
};

// It's a stack. FILO
struct Handler *handlers[MAX_HASH];
struct Handler *global_handler;

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

int get_single_instruction(BYTE* bytes, char* str, size_t bufsize){
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

int visible(unsigned ip, struct Module* whitelist){
    struct Module* module_p;
    for (module_p=whitelist; module_p; module_p=module_p->next_module){
        if (module_p->base+module_p->length > ip && module_p->base <= ip)
            return 1;
    }

    // Test
    if (ip <= 0x80484e7 && ip >= 0x80482b4)
        return 1;

    return 0;
}

struct Handler* get_global_handler(pid_t pid, UTILITY_TYPE utility, unsigned life, struct Option* opt){
    struct Handler *handler_p;
    handler_p = (struct Handler*)malloc(sizeof(struct Handler));
    handler_p -> global_flag = TRUE;
    handler_p -> option = opt;
    if (global_handler){
        global_handler -> prev_handler = handler_p;
    }
    handler_p -> next_handler = global_handler;
    // Global handler has no ip
    handler_p -> ip = 0;
    handler_p -> utility = utility;
    handler_p -> life = life;
    global_handler = handler_p;
    // So global handler doesn't necessarily work with breakpoints
    // At least doesn't work with breakpoints positively
    return handler_p;
}
// Allocate a new handler
struct Handler* get_handler(pid_t pid, unsigned ip, UTILITY_TYPE utility, unsigned life, struct Option* opt){
    HANDLER_ID hid;
    unsigned backup, buff;
    hid = GETID(ip);
    struct Handler *handler_p;
    handler_p = (struct Handler*)malloc(sizeof(struct Handler));
    handler_p -> global_flag = FALSE;
    handler_p -> option = opt;
    if (handlers[hid]){
         handlers[hid]->prev_handler = handler_p;
    }
    handler_p -> next_handler = handlers[hid];
    handler_p -> ip = ip;
    handler_p -> utility = utility;
    handler_p -> life = life;
    handlers[hid] = handler_p;

    backup = Ptrace(PTRACE_PEEKDATA, pid, (void*)ip, NULL);
    handler_p -> backup = backup;
    buff = (backup&0xffffff00) | 0xcc;
    Ptrace(PTRACE_POKETEXT, pid, (void*)ip, (void*)buff);

    return handler_p;
}

enum __ptrace_request trace(pid_t pid, struct Handler* handler){
    //int wait_status;
    unsigned ip, esp, ret;
    struct user_regs_struct regs;
    Ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    ip = regs.eip;
    // if ip is within a visible module
    if (visible(ip, handler->option->whitelist)){
        fprintf(handler->option->file, "0x%x\n", ip);
        fflush(handler->option->file);
        get_global_handler(pid, handler->utility, 1, handler->option);
        return PTRACE_SINGLESTEP;
    }else{
        esp = regs.esp;
        ret = Ptrace(PTRACE_PEEKDATA, pid, (void*)esp, NULL);
        if (visible(ret, handler->option->whitelist)){
            //backup = Ptrace(PTRACE_PEEKDATA, pid, (void*)ret, NULL);
            //buff = (backup&0xffffff00) | 0xcc;
            get_handler(pid, ret, handler->utility, 1, handler->option);
        }
        return PTRACE_CONT;
    }
}

void bp_hide(pid_t pid, struct Handler* handler_p){
    unsigned backup, ip;
    backup = handler_p -> backup;
    ip = handler_p -> ip;
    Ptrace(PTRACE_POKETEXT, pid, (void*)ip, (void*)backup);

    char inst_str[128];
    unsigned data;
    data = Ptrace(PTRACE_PEEKTEXT, pid, (void*)ip, NULL);
    get_single_instruction_word(data, inst_str, 128);
    printf("%s\n", inst_str);
}

// ????????????????????STRANGE
void bp_show(pid_t pid, struct Handler* handler_p){
    unsigned backup, ip, buff;
    ip = handler_p -> option->ip;
    backup = Ptrace(PTRACE_PEEKDATA, pid, (void*)ip, NULL);
    buff = (backup&0xffffff00)|0xcc;
    Ptrace(PTRACE_POKETEXT, pid, (void*)ip, (void*)buff);
}

enum __ptrace_request dispatch(pid_t pid, struct Handler* handler_p){
    enum __ptrace_request pr;
    // Stuff the breakpoint temporirily
    if (!handler_p -> global_flag){
        bp_hide(pid, handler_p);
    }
    pr = PTRACE_CONT;
    switch (handler_p -> utility){
        case UTILITY_DISABLE:
            pr = PTRACE_CONT;
            break;
        case UTILITY_MITM:
            pr = PTRACE_CONT;
            break;
        case UTILITY_TRACE:
            pr = trace(pid, handler_p);
            break;
        case GLOBAL_REPAIR:
            bp_show(pid, handler_p);
            break;
    }
    return pr;
}

void remove_from_list(struct Handler* handler, unsigned hid){
    struct Handler* removed;
    if (handler->next_handler)
        handler->next_handler->prev_handler = handler->prev_handler;

    if (handler->prev_handler){
        handler->prev_handler->next_handler = handler->next_handler;
    }

    if (global_handler==handler){
        global_handler = handler->next_handler;
    }
    else if(handler==handlers[hid]){
        handlers[hid] = handler->next_handler;
    }
    free(handler);
}

enum __ptrace_request global_expire(pid_t pid, struct Handler* handler, struct Handler** next_handler){
    struct Handler* prev;
    if (handler->life > 0){
        handler->life --;
        if (handler->life == 0){
            *next_handler = handler->next_handler;
            remove_from_list(handler, 0);
        }
    }
    // The lowest priority
    return PTRACE_CONT;
}
enum __ptrace_request expire(pid_t pid, struct Handler* handler, unsigned hid, struct Handler** next_handler){
    struct Handler* prev;
    //unsigned backup, breakpoint;
    if (handler->life > 0){
        // Has been used once before call to expire
        // So decrease it by 1
        handler->life --;
        if (handler->life > 0){
            get_global_handler(pid, GLOBAL_REPAIR, 1, handler->option);
            return PTRACE_SINGLESTEP;
        }else{
            // Leave it stuffed!(By dispatch, so expire save the effort)
            // Ptrace(PTRACE_POKETEXT, pid, (void*)breakpoint, (void*)backup);
            // Remove the handler from the list
            *next_handler = handler->next_handler;
            remove_from_list(handler, hid);
            // The lowest priority
            return PTRACE_CONT;
        }
    }
    return PTRACE_CONT;
}
void new_option(){

}

void init(){
    memset(handlers, 0, sizeof handlers);
}

int main(){
    //unsigned i;
    int wait_status;
    //int len;
    //int offset;
    //unsigned ban;
    //unsigned bp;
    //unsigned backup;
    //unsigned addr;
    //unsigned data;
    unsigned hid;
    //unsigned buff;
    unsigned oep;
    unsigned siginfo[512];
    enum __ptrace_request pr, pr2;
    //struct user_regs_struct regs;
    struct Handler* handler_p, *next_handler;
    //char inst_str[128];
    // Test
    struct Option opt;

    //char indirect = 0;
    //char manual = 0;
    //char plt = 1;
    //int pop = 0;
    //ban = 0x0804841b;
    const char *prog = "./try";
    struct user_regs_struct regs;
    BOOL delay = FALSE;
    BOOL proceed = FALSE;

    init();

    pid_t pid = fork();
    if (pid == 0){
        Ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(prog, prog, NULL);
    }else if (pid > 0){
        oep = get_entry_point(prog);

        // On loaded
        wait(&wait_status);
        if (WIFSTOPPED(wait_status)){
            // Test
            opt.utility = UTILITY_TRACE;
            opt.life = 1;
            opt.ip = oep;
            opt.file = fopen("/tmp/trace", "w");
            get_handler(pid, oep, UTILITY_TRACE, 1, &opt);
            Ptrace(PTRACE_CONT, pid, NULL, NULL);
        }

        wait(&wait_status);
        // Withdraw control from plugins
        while (WIFSTOPPED(wait_status)){
            Ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);
            // Caused by breakpoint
            if (siginfo[2] == 0x80){
                // Discard the 0xcc int 3 instruction
                // So move the eip upper by 1
                Ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                regs.eip --;
                Ptrace(PTRACE_SETREGS, pid ,NULL, &regs);
            }

            // PTRACE_CONT by default because it has the lowest priority
            pr = PTRACE_CONT;
            hid = GETID(regs.eip);

            for (handler_p=global_handler;handler_p;handler_p=next_handler){
                next_handler = handler_p->next_handler;
                pr2 = dispatch(pid, handler_p);
                pr = PRIORITY(pr, pr2);
                pr2 = global_expire(pid, handler_p, &next_handler);
                pr = PRIORITY(pr, pr2);
            }
            for (handler_p=handlers[hid];handler_p;handler_p=next_handler){
                next_handler = handler_p->next_handler;
                pr2 = dispatch(pid, handler_p);
                pr = PRIORITY(pr, pr2);
                pr2 = expire(pid, handler_p, hid, &next_handler);
                pr = PRIORITY(pr, pr2);
            }
            /*
            // A global handler deals with more general problem
            // Like breakpoint restoring
            ITER_WITH_ADD(handler_pp, global_handler, next_handler, delay){
                pr2 = dispatch(pid, *handler_pp);
                pr = PRIORITY(pr, pr2);
            }
            ITER_WITH_DEL(handler_pp, global_handler, next_handler, proceed){
                pr2 = global_expire(pid, handler_pp, &delay);
                pr = PRIORITY(pr, pr2);
            }

            ITER_WITH_ADD(handler_pp, handlers[hid], next_handler, proceed){
                pr2 = dispatch(pid, *handler_pp);
                pr = PRIORITY(pr, pr2);
            }
            ITER_WITH_DEL(handler_pp, handlers[hid], next_handler, proceed){
                pr2 = expire(pid, handler_pp, &delay);
                pr = PRIORITY(pr, pr2);
            }
            */
            Ptrace(pr, pid, NULL, NULL);
            wait(&wait_status);
        }

        /*
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
        */
    }else{
        perror("Folk failed: ");
        exit(-1);
    }

    for (hid=0;hid<=MAX_HASH;hid++){
        while (handlers[hid]){
            remove_from_list(handlers[hid], hid);
        }
    }
    return 0;
}
