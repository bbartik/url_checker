.PHONY: build win64 win32 clean vet

# Go 1.20 is required for Windows 7 — bcryptprimitives.dll (Win8+) is linked by Go 1.21+
# Install: curl -LO https://go.dev/dl/go1.20.14.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.20.14.linux-amd64.tar.gz
GO120 := /usr/local/go/bin/go

# Linux/WSL binary — for local testing (system Go is fine here)
build:
	go build -o url_checker .

# Windows 7+ 64-bit — MUST use Go 1.20
win64:
	GOROOT=/usr/local/go GOOS=windows GOARCH=amd64 $(GO120) build -ldflags="-s -w" -o url_checker.exe .

# Windows 7 32-bit fallback — MUST use Go 1.20
win32:
	GOROOT=/usr/local/go GOOS=windows GOARCH=386 $(GO120) build -ldflags="-s -w" -o url_checker_32.exe .

vet:
	go vet ./...

clean:
	rm -f url_checker url_checker.exe url_checker_32.exe results_*.csv
