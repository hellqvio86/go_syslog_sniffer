.PHONY: build clean lint renovate renovate-summary
lint:
	golint .
clean:
	rm -f sniffer
build:
	go build sniffer.go
sniffer: build

renovate:
	@./bin/renovate/run.sh

renovate-summary:
	@./bin/renovate/run.sh --summary