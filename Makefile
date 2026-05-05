APP = tcpcap
BPF_OBJ = src/tcpcap.bpf.o
SKEL = src/tcpcap.skel.h
VMLINUX = src/vmlinux.h

CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

LIBBPF_CFLAGS := $(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --libs libbpf)

all: $(APP)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(BPF_OBJ): src/tcpcap.bpf.c $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I./src $(LIBBPF_CFLAGS) \
		-c src/tcpcap.bpf.c -o $(BPF_OBJ)

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

$(APP): src/tcpcap.c $(SKEL)
	$(CC) -g -O2 -I./src $(LIBBPF_CFLAGS) src/tcpcap.c \
		-o $(APP) $(LIBBPF_LIBS) -lelf -lz -Wl,-rpath,/usr/local/lib

clean:
	rm -f $(APP) $(BPF_OBJ) $(SKEL) $(VMLINUX)
