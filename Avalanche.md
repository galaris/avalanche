### Documentation ###

  * [Installation](Installation.md)
  * [Using\_Avalanche](Using_Avalanche.md)
  * [Samples](Samples.md)
  * [Papers](Papers.md)

### Detected errors ###

Avalanche was tested on a number of open-source tools and has found the following bugs:

  * [llvm](http://llvm.org/) ([segmentation fault](http://llvm.org/bugs/show_bug.cgi?id=8494))
  * [mono](http://www.mono-project.com/Main_Page) ([segmentation fault](https://bugzilla.novell.com/show_bug.cgi?id=636794))
  * [parrot vm](http://www.parrot.org/) ([a bunch of segmentation faults](http://trac.parrot.org/parrot/ticket/1740))
  * [mencoder](http://www.mplayerhq.hu/design7/news.html) (segmentation fault)
  * [wget](http://www.gnu.org/software/wget/) (segmentation fault)
  * [libquicktime](http://libquicktime.sourceforge.net/) (3 segmentation faults, infinite loop)
  * [swftools](http://www.swftools.org/) (2 segmentation faults)
  * [avifile](http://avifile.sourceforge.net/) (segmentation fault)
  * [libmpeg2](http://libmpeg2.sourceforge.net/) (division by zero)
  * [gnash](http://www.gnu.org/software/gnash/) (uncaught exception)
  * [audiofile](http://www.68k.org/~michael/audiofile/) (infinite loop)
  * [libsndfile](http://www.mega-nerd.com/libsndfile/) (division by zero)
  * [vorbis-tools](http://xiph.org/downloads/) (infinite loop)
  * [libjpeg](http://www.ijg.org/) (division by zero)
  * [libmpeg3](http://freshmeat.net/projects/libmpeg3/) (2 segmentation faults)
  * [libwmf](http://wvware.sourceforge.net/libwmf.html) (segmentation fault)

etc...

### License ###

The two valgrind plugins, which are part of Avalanche (_tracegrind_ and _covgrind_) are licensed under [GPLv2](http://www.gnu.org/licenses/gpl-2.0.html). The driver module, that coordinates iterative testing is using [Apache](http://www.apache.org/licenses/LICENSE-2.0.html) license.

Third party open-source components use their own licenses: Valgrind is GPL licensed, STP uses MIT license.

### Mailing list ###

[The place to ask any question related to Avalanche](http://groups.google.com/group/avalanche-users)