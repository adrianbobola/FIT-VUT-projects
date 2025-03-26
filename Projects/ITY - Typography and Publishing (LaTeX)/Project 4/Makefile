FILENAME = proj4
ZIPNAME = xbobol00-fit.zip

all:
	latex $(FILENAME).tex
	bibtex $(FILENAME).aux
	latex $(FILENAME).tex
	latex $(FILENAME).tex
	dvips $(FILENAME).dvi
	ps2pdf $(FILENAME).ps

makezip:
	zip $(ZIPNAME) $(FILENAME).tex $(FILENAME).bib czechiso.bst Makefile 