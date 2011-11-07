all: xcpu.ps xcpu.pdf xcpu-madrid.ps xcpu-madrid.pdf

xcpu.ps: xcpu.dvi
	dvips -o xcpu.ps xcpu.dvi

xcpu.pdf: xcpu.ps
	ps2pdf xcpu.ps xcpu.pdf

xcpu.dvi: xcpu.tex
	latex xcpu.tex

xcpu-madrid.ps: xcpu-madrid.dvi
	dvips -o xcpu-madrid.ps xcpu-madrid.dvi

xcpu-madrid.pdf: xcpu-madrid.ps
	ps2pdf xcpu-madrid.ps xcpu-madrid.pdf

xcpu-madrid.dvi: xcpu-madrid.tex xcpu-madrid.bib
	latex xcpu-madrid.tex
	bibtex xcpu-madrid
	latex xcpu-madrid.tex
	bibtex xcpu-madrid
	latex xcpu-madrid.tex


clean:
	rm -f *~ *.dvi *.log *.aux *.bbl *.blg

