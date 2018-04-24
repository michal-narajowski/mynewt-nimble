TARGET_LIB := libnimble-hci-dummy.a
NIMBLE_ROOT := ../../nimble

CC ?= arm-none-eabi-gcc
CFLAGS ?= -m32

INCLUDE = \
	-I$(NIMBLE_ROOT)/include \
	-I$(NIMBLE_ROOT)/host/include \
	-I../libnimble/include \

OBJ = \
	src/hci_dummy.o \

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDE)

.PHONY: all clean

all: $(TARGET_LIB)

clean:
	rm $(OBJ) -f

$(TARGET_LIB): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)