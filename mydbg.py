from pydbg import *
from pydbg.defines import *
class mydbg(pydbg):
    def pydbg_log (self, a):
	pass
    def process_snapshot (self):
        '''
        Take memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self.pydbg_log("taking debuggee snapshot")

        do_not_snapshot = [PAGE_READONLY, PAGE_EXECUTE_READ,PAGE_GUARD, PAGE_NOACCESS]
        cursor          = 0

        # reset the internal snapshot data structure lists.
        self.memory_snapshot_blocks   = []
        self.memory_snapshot_contexts = []

        # enumerate the running threads and save a copy of their contexts.
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(None, thread_id)
	    print hex(context.Eip)

            self.memory_snapshot_contexts.append(memory_snapshot_context(thread_id, context))

            self.pydbg_log("saving thread context of thread id: %08x" % thread_id)

        # scan through the entire memory range and save a copy of suitable memory blocks.
        while cursor < 0xFFFFFFFF:
            save_block = True

            try:
                mbi = self.virtual_query(cursor)
            except:
                break

            # do not snapshot blocks of memory that match the following characteristics.
            # XXX - might want to drop the MEM_IMAGE check to accomodate for self modifying code.
            # or mbi.Type == MEM_IMAGE
            if mbi.State != MEM_COMMIT:
                save_block = False

            for has_protection in do_not_snapshot:
                if mbi.Protect & has_protection:
                    save_block = False
                    break

            if save_block:
                self.pydbg_log("Adding %08x +%d to memory snapsnot." % (mbi.BaseAddress, mbi.RegionSize))

                # read the raw bytes from the memory block.
                data = self.read_process_memory(mbi.BaseAddress, mbi.RegionSize)

                self.memory_snapshot_blocks.append(memory_snapshot_block(mbi, data))

            cursor += mbi.RegionSize

        return self.ret_self()
