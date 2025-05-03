all: klutshnik.1 klutshnikd.1 klutshnik.cfg.1 klutshnikd.cfg.1

install: $(PREFIX)/share/man/man1/klutshnik.1 $(PREFIX)/share/man/man1/klutshnikd.1 \
	      $(PREFIX)/share/man/man5/klutshnik.cfg.1 $(PREFIX)/share/man/man5/klutshnikd.cfg.1 \

clean:
	rm -f *.1

%.1: %.md
	cp $(@:.1=.head) $@
	cmark -t man $< >>$@
