CFLAGS = -Wall -O2 -I../../libimmds
CXXFLAGS = -Wall -O2 -I../../libimmds
LDFLAGS = -L../../libimmds -limmds -lprotobuf

all: cc_immds c_immds
.PHONY: all

cc_immds: cc_immds.cc
	g++ $(CXXFLAGS) -o $@ $< $(LDFLAGS)

c_immds: c_immds.c
	gcc $(CFLAGS) -o $@ $< $(LDFLAGS)

install: cc_immds c_immds
	install -d $(DESTDIR)/bin
	install -m 755 cc_immds c_immds $(DESTDIR)/bin

.PHONY: clean
clean:
	rm -f cc_immds c_immds
