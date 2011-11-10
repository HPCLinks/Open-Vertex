all: xcpu2.ps xcpu2.pdf


xcpu2.ps: xcpu2.dvi
	dvips -o xcpu2.ps xcpu2.dvi

xcpu2.pdf: xcpu2.ps 
	ps2pdf xcpu2.ps xcpu2.pdf

xcpu2.dvi: xcpu2.tex xcpu2.bib xcpu-tspawn.eps
	latex xcpu2.tex
	bibtex xcpu2
	latex xcpu2.tex
	bibtex xcpu2
	latex xcpu2.tex


clean:
	rm -f *~ *.dvi *.log *.aux

distclean:
	rm -f *~ *.dvi *.log *.aux xcpu2.ps xcpu2.pdf
