include config.info
INSTALL_DIR:=$(PREFIX)

all: tracegrind stp driver samples

inst_check: 
	mkdir -p $(INSTALL_DIR)

install: inst_check tracegrind-inst stp-inst driver-inst

tracegrind:
	cd valgrind; if (test -r Makefile); then make; else ./autogen.sh; ./configure --prefix=$(INSTALL_DIR) && make; fi

tracegrind-inst:
	cd valgrind; make install

stp:
	cd stp-ver-0.1-11-18-2008; if (test -r Makefile); then make; else ./configure --with-prefix=$(INSTALL_DIR) && make; ulimit -s unlimited; fi

stp-inst:
	cd stp-ver-0.1-11-18-2008; make install

driver:
	cd driver; make

driver-inst:
	cd driver; make install

samples:
	cd samples; make

clean:
	cd valgrind; make clean
	cd stp-ver-0.1-11-18-2008; make clean
	cd driver; make clean

.PHONY : inst_check tracegrind stp driver samples
