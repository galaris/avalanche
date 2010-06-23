all: inst_check tracegrind stp driver samples

INSTALL_DIR:=inst

inst_check:
	mkdir -p $(INSTALL_DIR)

tracegrind:
	cd valgrind; if (test -r Makefile); then make && make install; else ./autogen.sh; ./configure --prefix=$(PWD)/$(INSTALL_DIR); make && make install; fi

stp:
	cd stp-ver-0.1-11-18-2008; if (test -r Makefile); then make && make install; else ./configure --with-prefix=$(PWD)/$(INSTALL_DIR); make && make install; ulimit -s unlimited; fi

driver:
	cd driver; make && make install

samples:
	cd samples; make

clean:
	rm avalanche
	cd valgrind; make clean
	cd stp-ver-0.1-11-18-2008; make clean
	cd driver; make clean

.PHONY : inst_check tracegrind stp driver samples
