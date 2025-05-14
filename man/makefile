all: klutshnik.1 klutshnikd.1 klutshnik.cfg.5 klutshnikd.cfg.5

install: $(PREFIX)/share/man/man1/klutshnik.1 $(PREFIX)/share/man/man1/klutshnikd.1 \
	      $(PREFIX)/share/man/man5/klutshnik.cfg.5 $(PREFIX)/share/man/man5/klutshnikd.cfg.5 \

clean:
	rm -f *.1 *.5

%.1: %.md
	cp $(@:.1=.head) $@
	cmark -t man $< >>$@

%.5: %.md
	cp $(@:.5=.head) $@
	cmark -t man $< >>$@
