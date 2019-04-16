# Makefile
#
# 5/3/2012 D. W. Hawkins (dwh@ovro.caltech.edu)
#
# Create the Linux pci_debug utility for accessing
# BAR regions.
#

# -----------------------------------------------------------------
# Cygwin check
# -----------------------------------------------------------------
#
ifeq ("$(shell uname -o)","Cygwin")
$(info Cygwin shell detected)
$(error Sorry, pci_debug can only be built under Linux)
endif

# -----------------------------------------------------------------
# pci_debug
# -----------------------------------------------------------------
#
default: pci_debug

CFLAGS += -Wall -std=gnu99
LDFLAGS += -lreadline -lncurses

pci_debug: pci_debug.c
	$(CC) $(CFLAGS) pci_debug.c $(LDFLAGS)  -o pci_debug
clean:
	rm -rf pci_debug *.o 
