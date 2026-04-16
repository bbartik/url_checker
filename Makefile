.PHONY: build win64 win32 clean vet

# Linux/WSL binary — for local testing
build:
	go build -o url_checker .

# Windows 7+ 64-bit — use this for the lab box
win64:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o url_checker.exe .

# Windows 7 32-bit fallback
win32:
	GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o url_checker_32.exe .

vet:
	go vet ./...

clean:
	rm -f url_checker url_checker.exe url_checker_32.exe results_*.csv
