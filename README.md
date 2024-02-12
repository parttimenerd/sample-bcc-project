Sample BCC/Hello-ebpf project
=============================

Sample project using the bcc library of the 
[hello-ebpf](https://github.com/parttimenerd/hello-ebpf) project
to implement a trivial eBPF program in Java.

The [Main](src/main/java/sample/bcc/Main.java) class implements a simple eBPF program that counts
the number of `execve` system calls per user:

```java
public class Main {
    public static void main(String[] args) throws InterruptedException {
        try (var b = BPF.builder("""
                BPF_HASH(counter_table);
                
                int hello(void *ctx) {
                   u64 uid;
                   u64 counter = 0;
                   u64 *p;
                
                   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                   p = counter_table.lookup(&uid);
                   if (p != 0) {
                      counter = *p;
                   }
                   counter++;
                   counter_table.update(&uid, &counter);
                   return 0;
                }
                """).build()) {
            var syscall = b.get_syscall_fnname("execve");
            b.attach_kprobe(syscall, "hello");
            BPFTable.HashTable<Long, Long> counterTable = b.get_table("counter_table", UINT64T_MAP_PROVIDER);
            while (true) {
                Thread.sleep(2000);
                for (var entry : counterTable.entrySet()) {
                    System.out.printf("ID %d: %d\t", entry.getKey(), entry.getValue());
                }
                System.out.println();
            }
        }
    }
}
```

Read more on this specific example in my blog post 
[Hello eBPF: Recording data in basic eBPF maps (2)](https://mostlynerdless.de/blog/2024/01/12/hello-ebpf-recording-data-in-basic-ebpf-maps-2/).


Requirements
------------
- Linux 64-bit (or a VM)
- Java 21 (exactly this version, as we need [Project Panama](https://openjdk.org/projects/panama/) with is a preview
  feature), we'll switch to Java 22 as soon as it is released
- libbcc (see [bcc installation instructions](https://github.com/iovisor/bcc/blob/master/INSTALL.md), be sure to install the libbpfcc-dev package)
- root privileges (for running eBPF programs)

On Mac OS, you can use the [Lima VM](https://lima-vm.io/) (or use the `hello-ebpf.yaml` file as a guide to install the prerequisites):

```sh
limactl start hello-ebpf.yaml
limactl shell hello-ebpf
```

Vim and tmux are installed in the VM.

Build
-----
```shell
./mvnw package
```

Usage
-----
With root privileges (`sudo PATH=$PATH`):
```shell
java --enable-preview --enable-native-access=ALL-UNNAMED -jar target/sample-bcc-project.jar
# or
./run.sh
```

Other Examples
--------------
For a recent blog post, I implemented a version of the 
[HelloTail](https://github.com/parttimenerd/hello-ebpf/blob/main/bcc/src/main/java/me/bechberger/ebpf/samples/chapter2/HelloTail.java) 
example from the [hello-ebpf](https://github.com/parttimenerd/hello-ebpf) repository
as its own project. You can find it in the [tail-example](https://github.com/parttimenerd/sample-bcc-project/tree/tail-example) branch of this repository.

Contributing
------------
Please open an issue or a pull request if you have any problems.
Feel free to contribute to the main project [hello-ebpf](https://github.com/parttimenerd/hello-ebpf).

License
-------
MIT, Copyright 2023 SAP SE or an SAP affiliate company, Johannes Bechberger