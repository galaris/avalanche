### From source archive ###

  1. Download and unpack the source tarball from http://code.google.com/p/avalanche/downloads/list
```
$ tar xf avalanche-VERSION.tar.gz
$ cd avalanche-VERSION
```
  1. Configure and make:
```
$ ./configure --prefix=<path to avalanche install directory>
$ make
$ make install
```

### From subversion repository ###

  1. Checkout the sources:
```
$ svn checkout http://avalanche.googlecode.com/svn/trunk avalanche
```
  1. Configure and make:
```
$ ./autogen.sh
$ ./configure --prefix=<path to avalanche install directory>
$ make
$ make install
```