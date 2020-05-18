# Set by elixir_make
# ERL_EI_LIBDIR=
# ERL_EI_INCLUDE_DIR=

SOURCE=./src/crypto.c
TARGET=./priv/crypto

all: $(TARGET).so

clean:
	rm -f $(TARGET).so

$(TARGET).so: $(SOURCE)
	$(CC) -I$(ERL_EI_INCLUDE_DIR) $(SOURCE) -o $(TARGET).so -L$(ERL_EI_LIBDIR) -fPIC -shared -lsodium
