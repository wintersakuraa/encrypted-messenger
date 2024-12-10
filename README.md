# Double Ratchet protocol implementation

## Local setup

1. Clone the repository:

```bash
git clone https://github.com/wintersakuraa/encrypted-messenger.git
```

2. `cd` into the working directory:

```bash
cd encrypted-messenger
```

3. Install dependencies:

```bash
go mod tidy
```

4. Run `bob.go` file first:

```bash
go run cmd/bob/bob.go
```

5. In the separate terminal window run `alice.go`:

```bash
go run cmd/alice/alice.go
```

## Check out-of-order messages

```bash
go run cmd/tests/skipped.go
```
