CC = gcc

CFLAGS = -Wall -Wno-deprecated-declarations -O3
IFLAGS = -Iinclude
LFLAGS = -lm -lssl -lcrypto

SRCDIR = src
OBJDIR = obj
BINDIR = bin

SCB = $(OBJDIR)/hashmap.o $(OBJDIR)/scb.o
SCB_FILE = $(OBJDIR)/scb_file.o
SCB_IMAGE = $(OBJDIR)/scb_image.o

MKDIR = mkdir -p

all: dirs scb_file scb_image

scb_file: hashmap.o scb.o scb_file.o
	$(CC) $(CFLAGS) $(IFLAGS) $(LFLAGS) $(SCB) $(SCB_FILE) -o$(BINDIR)/scb_file

scb_image: hashmap.o scb.o scb_image.o
	$(CC) $(CFLAGS) $(IFLAGS) $(LFLAGS) $(SCB) $(SCB_IMAGE) -o$(BINDIR)/scb_image

%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(IFLAGS) $< -c -o$(OBJDIR)/$@

dirs: ${BINDIR} ${OBJDIR}

${BINDIR}:
	${MKDIR} ${BINDIR}

${OBJDIR}:
	${MKDIR} ${OBJDIR}

clean:
	rm -rf $(OBJDIR) $(BINDIR)

.PHONY: all dirs clean