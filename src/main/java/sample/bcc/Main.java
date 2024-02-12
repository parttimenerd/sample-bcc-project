package sample.bcc;

import me.bechberger.ebpf.bcc.BPF;
import me.bechberger.ebpf.bcc.BPFTable;
import me.bechberger.ebpf.bcc.Syscalls;

public class Main {

    record Arguments(boolean skipOthers) {
        static Arguments parseArgs(String[] args) {
            boolean skipOthers = false;
            if (args.length > 0) {
                if (args.length == 1 && args[0].equals("--skip-others")) {
                    skipOthers = true;
                } else {
                    System.err.println("""
                Usage: app [--skip-others]
                    
                   --skip-others: Only log execve and itimer system calls
                """);
                    System.exit(1);
                }
            }
            return new Arguments(skipOthers);
        }
    }

    static final String EBPF_PROGRAM = """
                BPF_PROG_ARRAY(syscall, 300);

                int hello(struct bpf_raw_tracepoint_args *ctx) {
                    int nr = ctx->args[1];
                    // syscall.call(ctx, nr) doesn't compile
                    // for whatever reason, so we use the raw helper
                    // function instead
                    bpf_tail_call_(bpf_pseudo_fd(1, -1), ctx, nr);
                    bpf_trace_printk("Another syscall: %d", nr);
                    return 0;
                }

                int hello_exec(void *ctx) {
                    bpf_trace_printk("Executing a program");
                    return 0;
                }

                int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
                    int nr = ctx->args[1];
                    switch (nr) {
                        case 222:
                            bpf_trace_printk("Creating a timer");
                            break;
                        case 226:
                            bpf_trace_printk("Deleting a timer");
                            break;
                        default:
                            bpf_trace_printk("Some other timer operation");
                            break;
                    }
                    return 0;
                }

                int ignore_nr(void *ctx) {
                    return 0;
                }
                """;

    public static void main(String[] args) {
        run(Arguments.parseArgs(args));
    }

    static void run(Arguments args) {
        try (var b = BPF.builder(EBPF_PROGRAM).build()) {
            b.attach_raw_tracepoint("sys_enter", "hello");

            var ignoreFn = b.load_raw_tracepoint_func("ignore_nr");
            var execFn = b.load_raw_tracepoint_func("hello_exec");
            var timerFn = b.load_raw_tracepoint_func("hello_timer");

            var progArray = b.get_table("syscall", BPFTable.ProgArray.createProvider());
            progArray.set(Syscalls.getSyscall("execve").number(), execFn);
            for (String syscall : new String[]{
                    "timer_create", 
                    "timer_gettime", 
                    "timer_getoverrun",
                    "timer_settime", 
                    "timer_delete"}) {
                progArray.set(Syscalls.getSyscall(syscall).number(), timerFn);
            }
            // ignore some system calls that come up a lot
            for (int i : new int[]{
                    21, 22, 25, 29, 56, 57, 63, 64, 66, 72,
                    73, 79, 98, 101, 115, 131,
                    134, 135, 139, 172, 233, 280, 291}) {
                progArray.set(i, ignoreFn);
            }
            b.trace_print(f -> {
                String another = "Another syscall: ";
                // replace other syscall with their names
                if (f.line().contains(another)) {
                    // skip these lines if --skip-others is passed
                    if (args.skipOthers) {
                        return null;
                    }
                    var syscall = Syscalls.getSyscall(
                            Integer.parseInt(f.line().substring(
                                    f.line().indexOf(another) + another.length())));
                    return f.line().replace(another + syscall.number(), another + syscall.name());
                }
                return f.line();
            });
        }
    }
}
