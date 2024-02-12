System Call Logger
==================

Log system calls, focusing on `execve` and itimer calls, using Java and eBPF (via [hello-ebpf](https://github.com/parttimenerd/hello-ebpf/)).

This is based on the [HelloTail](https://github.com/parttimenerd/hello-ebpf/blob/main/bcc/src/main/java/me/bechberger/ebpf/samples/chapter2/HelloTail.java)
example from the [hello-ebpf](https://github.com/parttimenerd/hello-ebpf/) project.

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

Contributing
------------
Please open an issue or a pull request if you have any problems.
Feel free to contribute to the main project [hello-ebpf](https://github.com/parttimenerd/hello-ebpf).

License
-------
MIT, Copyright 2023 SAP SE or an SAP affiliate company, Johannes Bechberger