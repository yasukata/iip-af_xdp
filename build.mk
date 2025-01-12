CFLAGS += -D_GNU_SOURCE
LDFLAGS += -lpthread -lnuma

ifeq ($(shell echo '#include <bpf/xsk.h>' | cpp -H -fsyntax-only 2>&1 | head -n 1 | grep 'No such file' | wc -l), 0)
CFLAGS += -DXSK_HEADER_LIBBPF
LDFLAGS += -lbpf
else ifeq ($(shell echo '#include <xdp/xsk.h>' | cpp -H -fsyntax-only 2>&1 | head -n 1 | grep 'No such file' | wc -l), 0)
CFLAGS += -DXSK_HEADER_LIBXDP
LDFLAGS += -lxdp
else
$(error xsk.h is not found, maybe libbpf or libxdp is not installed)
endif
