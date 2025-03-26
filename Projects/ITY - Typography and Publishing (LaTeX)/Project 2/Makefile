FILENAME = proj2
ZIPNAME = xbobol00-fit.zip

all:
	latex $(FILENAME).tex
	latex $(FILENAME).tex
	dvips -t a4 $(FILENAME).dvi
	ps2pdf $(FILENAME).ps

makezip:
	zip $(ZIPNAME) $(FILENAME).tex Makefile
