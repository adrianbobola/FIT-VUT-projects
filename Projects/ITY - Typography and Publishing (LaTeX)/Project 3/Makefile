FILENAME = proj3
ZIPNAME = xbobol00-fit.zip

all:
	latex $(FILENAME).tex
	latex $(FILENAME).tex
	dvips -sPAPERSIZE=a4 $(FILENAME).dvi
	ps2pdf -sPAPERSIZE=a4 $(FILENAME).ps

makezip:
	zip $(ZIPNAME) $(FILENAME).tex Makefile etiopan.eps oniisan2.eps oniisan.eps algorithm2e.sty
