# Set by elixir_make
# ERL_EI_LIBDIR=
# ERL_EI_INCLUDE_DIR=

TARGET=./src/crypto

all: $(TARGET).so

clean:
	rm -f $(TARGET).so

$(TARGET).so: $(TARGET).c
	$(CC) -I$(ERL_EI_INCLUDE_DIR) $(TARGET).c -o $(TARGET).so -L$(ERL_EI_LIBDIR) -fPIC -shared -lsodium
