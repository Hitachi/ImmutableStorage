libimmds.so: libimmds.go libimmds.h
	go build -buildmode c-shared

install: libimmds.so
	install -d $(DESTDIR)/lib
	install -m 755 libimmds.so $(DESTDIR)/lib

.PHONY: clean
clean:
	rm -f libimmds.so
