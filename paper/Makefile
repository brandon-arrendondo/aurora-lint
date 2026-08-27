MAIN := sqc
SECTIONS := $(wildcard sections/*.tex)

.PHONY: all pdf watch clean cleanall

all: pdf

pdf: $(MAIN).pdf

$(MAIN).pdf: $(MAIN).tex $(SECTIONS) fig_timing.tex
	latexmk -pdf -interaction=nonstopmode -halt-on-error $(MAIN).tex

# Rebuild on save (requires a PDF viewer that reloads on file change).
watch:
	latexmk -pdf -pvc -interaction=nonstopmode $(MAIN).tex

# Remove intermediate build artifacts, keep the PDF.
clean:
	latexmk -c $(MAIN).tex

# Remove all build artifacts including the PDF.
cleanall:
	latexmk -C $(MAIN).tex
