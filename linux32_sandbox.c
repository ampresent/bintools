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
#define OFFSET_BASEADDR   0x7c
#define OFFSET_MEMSIZE    0x88
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
    unsigned base;
    unsigned length;
    struct Module* next_module;
};

struct TraceOption{
    FILE* file;
    struct Module* whitelist;
};

struct DisableOption{

};

struct MITMOption{

};

struct Option{
    UTILITY_TYPE utility;
    unsigned life;
    struct Option* next_option;
    union{
        struct TraceOption trace_option;
        struct DisableOption disable_option;
        struct MITMOption mitm_option;
    };
};

struct Handler{
    unsigned ip;                     // Address asscociated with the Handler. If global_flag specified, ip = 0
    unsigned backup;                 // Backup of the memory on the breakpoint
    unsigned life;                   // The life of the handler, duplication of option.life. But writable
    BOOL global_flag;                // Which queue it should be append to. Whether should clean breakpoint
    struct Option* option;           // Options, readonly, and consistent
    struct Handler* next_handler;    // Pointer to next handler on the list
    struct Handler* prev_handler;    // Pointer to next handler on the list
};

// It's a stack. FILO
struct Handler *handlers[MAX_HASH], *global_handler;
struct Handler* handler_p, *next_handler;
struct Module* whitelist, *module_h, *next_module;
struct Option* options, *option_h, *next_option;

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

int get_single_instruction_at(pid_t pid, unsigned ip, char* str, size_t bufsize){
    unsigned data;
    int len;
    data = Ptrace(PTRACE_PEEKTEXT, pid, (void*)ip, NULL);
    len = get_single_instruction_word(data, str, bufsize);
    return len;
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

unsigned get_baseaddr(const char * filename){
    FILE* file;
    unsigned res = 0;
    file = fopen(filename, "r");
    fseek(file, OFFSET_BASEADDR, SEEK_SET);
    fread(&res, 4, 1, file);
    fclose(file);
    return res;
}

unsigned get_memsize(const char * filename){
    FILE* file;
    unsigned res = 0;
    file = fopen(filename, "r");
    fseek(file, OFFSET_MEMSIZE, SEEK_SET);
    fread(&res, 4, 1, file);
    fclose(file);
    return res;
}

int visible(unsigned ip, struct Module* whitelist){
    struct Module* module_p;
    for (module_p=whitelist; module_p; module_p=module_p->next_module){
        if (module_p->base+module_p->length > ip && module_p->base <= ip)
            return 1;
    }
    return 0;
}

struct Option* get_option(UTILITY_TYPE utility, unsigned life){
    struct Option* no;
    no = (struct Option*)malloc(sizeof(struct Option));
    no -> utility = utility;
    no -> life = life;
    no -> next_option = options;
    options = no;
    return no;
}

struct Option* get_trace_option(FILE* file, struct Module* whitelist){
    struct Option* no;
    no = get_option(UTILITY_TRACE, 1);
    no -> trace_option.file = file;
    no -> trace_option.whitelist = whitelist;
    return no;
}

struct Handler* get_global_handler(pid_t pid, unsigned ip, struct Option* opt){
    struct Handler *handler_p;
    unsigned backup;
    unsigned hid;

    hid = GETID(ip);
    handler_p = (struct Handler*)malloc(sizeof(struct Handler));
    handler_p -> global_flag = TRUE;
    handler_p -> option = opt;

    // If already a breakpoint exists at this instruction
    // Then just copy the backup
    if (handlers[hid])
        backup = handlers[hid] -> backup;
    else
        backup = Ptrace(PTRACE_PEEKTEXT, pid, (void*)ip, NULL);

    // Not a breakpoint, just additional information
    handler_p -> ip = ip;
    handler_p -> backup = backup;
    handler_p -> life = opt -> life;

    if (global_handler) global_handler -> prev_handler = handler_p;
    handler_p -> next_handler = global_handler;
    handler_p -> prev_handler = NULL;
    global_handler = handler_p;
    return handler_p;
}
// Allocate a new handler
struct Handler* get_handler(pid_t pid, unsigned ip, struct Option* opt){
    HANDLER_ID hid;
    struct Handler *handler_p;
    unsigned buff, backup;

    hid = GETID(ip);
    handler_p = (struct Handler*)malloc(sizeof(struct Handler));
    handler_p -> global_flag = FALSE;
    handler_p -> option = opt;

    // If already exists a breakpoint at this instruction
    if (handlers[hid]){
        backup = handlers[hid] -> backup;
    }else{
    // Else, place a new breakpoint
        // Read the address of bp, making backup
        backup = Ptrace(PTRACE_PEEKTEXT, pid, (void*)ip, NULL);
        buff = (backup&0xffffff00) | 0xcc;
        Ptrace(PTRACE_POKETEXT, pid, (void*)ip, (void*)buff);
    }

    // IP is not breakpoint, just additional information
    handler_p -> ip = ip;
    handler_p -> backup = backup;
    handler_p -> life = opt->life;

    if (handlers[hid]) handlers[hid]->prev_handler = handler_p;
    handler_p -> next_handler = handlers[hid];
    handler_p -> prev_handler = NULL;
    handlers[hid] = handler_p;

    return handler_p;
}

enum __ptrace_request trace(pid_t pid, struct Handler* handler){
    unsigned ip, esp, ret;
    struct user_regs_struct regs;
    char inst_str[128];
    int len;
    Ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    ip = regs.eip;
    // if ip is within a visible module. Output and trace on
    if (visible(ip, handler->option->trace_option.whitelist)){
        fprintf(handler->option->trace_option.file, "0x%x\n", ip);
        fflush(handler->option->trace_option.file);

        len = get_single_instruction_at(pid, ip, inst_str, 128);
        if (!strncmp(inst_str, "call", 4)){
            // If 'call', record the latest 'ret' addr
            get_global_handler(pid, ip + len, handler->option);
        }else{
            // If not 'call', hand on the latest 'ret' addr
            get_global_handler(pid, handler->ip, handler->option);
        }
        return PTRACE_SINGLESTEP;
    }else{
    // If not, run until the latest 'ret' addr
        get_handler(pid, handler->ip, handler->option);
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
}

// ????????????????????STRANGE
void bp_show(pid_t pid, struct Handler* handler_p){
    unsigned backup, ip, buff;
    ip = handler_p -> ip;
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
    switch (handler_p -> option -> utility){
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

void remove_from_global_list(struct Handler* handler){
    struct Handler* removed;
    struct Module* mod, *next_module;
    if (handler->next_handler)
        handler->next_handler->prev_handler = handler->prev_handler;
    if (handler->prev_handler)
        handler->prev_handler->next_handler = handler->next_handler;
    // If we're removing head, then proceed the head
    if (global_handler==handler)
        global_handler = handler->next_handler;
    free(handler);
}

void remove_from_list(struct Handler* handler, unsigned hid){
    struct Handler* removed;
    struct Module* mod, *next_module;
    if (handler->next_handler)
        handler->next_handler->prev_handler = handler->prev_handler;
    if (handler->prev_handler)
        handler->prev_handler->next_handler = handler->next_handler;
    // If we're removing head, then proceed the head
    if(handler==handlers[hid])
        handlers[hid] = handler->next_handler;
    free(handler);
}

// Next_handler argument to keep track of the iteration
enum __ptrace_request global_expire(pid_t pid, struct Handler* handler, struct Handler** next_handler){
    struct Handler* prev;
    if (handler->life > 0){
        handler->life --;
    }
    if (handler->life <= 0){
        *next_handler = handler->next_handler;
        remove_from_global_list(handler);
    }
    // The lowest priority
    return PTRACE_CONT;
}

// Next_handler argument to keep track of the iteration
enum __ptrace_request expire(pid_t pid, struct Handler* handler, unsigned hid, struct Handler** next_handler){
    struct Handler* prev;
    //unsigned backup, breakpoint;
    if (handler->life > 0){
        // Has been used once before call to expire
        // So decrease it by 1
        handler->life --;
    }
    if (handler->life > 0){
        get_global_handler(pid, handler->ip, get_option(GLOBAL_REPAIR, 1));
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
    return PTRACE_CONT;
}

void add_module(struct Module** whitelist, unsigned base, unsigned length){
    struct Module* mod;
    mod = (struct Module*)malloc(sizeof(struct Module));
    mod -> base = base;
    mod -> length = length;
    mod -> next_module = *whitelist;
    *whitelist = mod;
}

void init(){
    memset(handlers, 0, sizeof handlers);
}

void finalize(){
    unsigned hid;
    for (hid=0;hid<=MAX_HASH;hid++)
        while (handlers[hid])
            remove_from_list(handlers[hid], hid);
    while (global_handler)
        remove_from_global_list(global_handler);
    for (module_h=whitelist;module_h;module_h=next_module){
        next_module = module_h->next_module;
        free(module_h);
    }
    for (option_h=options;option_h;option_h=next_option){
        next_option = option_h->next_option;
        free(option_h);
    }
}
int main(){
    //unsigned i;
    //int len;
    //int offset;
    //unsigned ban;
    //unsigned bp;
    //unsigned backup;
    //unsigned addr;
    //unsigned data;
    //unsigned buff;
    unsigned hid;
    unsigned oep;
    // This is NOT THE PROPER WAY!!!
    unsigned siginfo[512];
    unsigned baseaddr, memsize;
    enum __ptrace_request pr, pr2;
    //struct user_regs_struct regs;
    //char inst_str[128];
    // Test
    const char *prog = "./try";
    //char indirect = 0;
    //char manual = 0;
    //char plt = 1;
    //int pop = 0;
    //ban = 0x0804841b;
    int wait_status;
    struct user_regs_struct regs;

    init();

    pid_t pid = fork();
    if (pid == 0){
        Ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(prog, prog, NULL);
    }else if (pid > 0){
        oep = get_entry_point(prog);
        // Test
        oep = 0x080484a1;
        // On loaded
        wait(&wait_status);
        if (WIFSTOPPED(wait_status)){
            // Test, wrong
            memsize = get_memsize(prog);
            baseaddr = get_baseaddr(prog);
            add_module(&whitelist, baseaddr, memsize);
            get_handler(pid, oep, get_trace_option(fopen("/tmp/trace","w"), whitelist));
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
    finalize();
    return 0;
}
