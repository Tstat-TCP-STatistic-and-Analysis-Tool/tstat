#
# Tstat - TCP STatistic and Analysis Tool
#
# Build requirements (Ubuntu):
#   apt-get install build-essential libpcap-dev libldns-dev libssl-dev librrd-dev
#
# Targets:
#   make               build the tstat executable (tstat/tstat)
#   make libtstat      build the shared library (libtstat/libtstat.so)
#   make demo          build the libtstat demo (libtstat-demo/demo)
#   make install       install tstat (and libtstat, if built) under PREFIX
#   make clean
#
# Options (both enabled by default, set them to 0 to disable):
#   RRD_THREADED=0     write the RRD files from the main thread, instead of
#                      a separate thread (useful for libtstat and tstat-dpdk)
#   PACKET_STATS=0     do not log statistics on the first segments of each flow
#                      (extra columns in log_tcp_complete and log_udp_complete)
#
# Options are compiled in the objects: run "make clean" when changing them.
#

PREFIX     ?= /usr/local
CC         ?= gcc
CXX        ?= g++
CFLAGS     ?= -O2 -g
CXXFLAGS   ?= -O2 -g
RRD_THREADED ?= 1
PACKET_STATS ?= 1

DEFINES  = -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
DEFINES += -DBUILT_USER="\"$(shell whoami)\""
DEFINES += -DBUILT_HOST="\"$(shell hostname)\""
DEFINES += -DBUILT_DATE="\"$(shell date)\""
ifeq ($(RRD_THREADED),1)
DEFINES += -DRRD_THREADED
endif
ifeq ($(PACKET_STATS),1)
DEFINES += -DPACKET_STATS
endif

WARNINGS = -Wall -Werror=implicit-function-declaration
LIBS     = -lpcap -lldns -lcrypto -lrrd -lpthread -lm

SRCDIR   = tstat
C_SRCS   = $(wildcard $(SRCDIR)/*.c) $(wildcard $(SRCDIR)/rfc6234/*.c)
CXX_SRCS = $(wildcard $(SRCDIR)/dnscache/*.cpp)

# The executable and the shared library are built from the same sources,
# in different object directories
EXE_OBJDIR = build/tstat
LIB_OBJDIR = build/libtstat
EXE_OBJS   = $(C_SRCS:%.c=$(EXE_OBJDIR)/%.o) $(CXX_SRCS:%.cpp=$(EXE_OBJDIR)/%.o)
LIB_OBJS   = $(C_SRCS:%.c=$(LIB_OBJDIR)/%.o) $(CXX_SRCS:%.cpp=$(LIB_OBJDIR)/%.o)

LIBTSTAT_VERSION = 1.0.0

.PHONY: all libtstat demo install clean

all: tstat/tstat

tstat/tstat: $(EXE_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

libtstat: libtstat/libtstat.so libtstat/libtstat.pc

libtstat/libtstat.so: $(LIB_OBJS)
	$(CXX) -shared $(LDFLAGS) -Wl,-soname,libtstat.so.1 -o libtstat/libtstat.so.$(LIBTSTAT_VERSION) $^ $(LIBS)
	ln -sf libtstat.so.$(LIBTSTAT_VERSION) libtstat/libtstat.so.1
	ln -sf libtstat.so.1 $@

libtstat/libtstat.pc: libtstat/libtstat.pc.in
	sed -e 's|@prefix@|$(PREFIX)|' -e 's|@LIBTSTAT_VERSION@|$(LIBTSTAT_VERSION)|' $< > $@

demo: libtstat-demo/demo

libtstat-demo/demo: libtstat-demo/demo.c libtstat-demo/pcapwrapper.c libtstat/libtstat.so
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -Iinclude $(LDFLAGS) -o $@ \
	    libtstat-demo/demo.c libtstat-demo/pcapwrapper.c \
	    -Llibtstat -Wl,-rpath,'$$ORIGIN/../libtstat' -ltstat -lpcap

$(EXE_OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(DEFINES) $(CFLAGS) $(WARNINGS) -MMD -MP -c -o $@ $<

$(EXE_OBJDIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(DEFINES) $(CXXFLAGS) $(WARNINGS) -MMD -MP -c -o $@ $<

$(LIB_OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(DEFINES) -DTSTAT_RUNASLIB -fPIC $(CFLAGS) $(WARNINGS) -MMD -MP -c -o $@ $<

$(LIB_OBJDIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(DEFINES) -DTSTAT_RUNASLIB -fPIC $(CXXFLAGS) $(WARNINGS) -MMD -MP -c -o $@ $<

install: tstat/tstat
	install -D -m 755 tstat/tstat $(DESTDIR)$(PREFIX)/bin/tstat
	if [ -f libtstat/libtstat.so ]; then \
	    install -D -m 755 libtstat/libtstat.so.$(LIBTSTAT_VERSION) $(DESTDIR)$(PREFIX)/lib/libtstat.so.$(LIBTSTAT_VERSION); \
	    ln -sf libtstat.so.$(LIBTSTAT_VERSION) $(DESTDIR)$(PREFIX)/lib/libtstat.so.1; \
	    ln -sf libtstat.so.1 $(DESTDIR)$(PREFIX)/lib/libtstat.so; \
	    install -D -m 644 include/libtstat.h $(DESTDIR)$(PREFIX)/include/libtstat.h; \
	    install -D -m 644 libtstat/libtstat.pc $(DESTDIR)$(PREFIX)/lib/pkgconfig/libtstat.pc; \
	fi

clean:
	rm -rf build tstat/tstat libtstat/libtstat.so* libtstat/libtstat.pc libtstat-demo/demo

-include $(EXE_OBJS:.o=.d) $(LIB_OBJS:.o=.d)
