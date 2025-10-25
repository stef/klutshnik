HTMLS=index.html code.html docs.html servers.html client_install.html server_install.html device_install.html faq.html

all: $(HTMLS) manpages

man:
	make -C ../man/ html
	cp ../man/*.html manpages

upload: $(HTMLS) 
	rsync -WPvr $(HTMLS) manpages ltximg keeper7keys.jpg klutshnik.info:/var/www/klutshnik.info

clean:
	rm $(HTMLS) manpages/*.html

%.html: %.org
	emacs -l ~/.emacs -Q --visit $< --batch --eval "(org-html-export-to-html)"
