@ECHO OFF
ECHO Doing PQC tests...
go run mlkem-keygen\mlkem-keygen.go
go run mlkem-encap-decap\mlkem-encap-decap.go
go run mldsa-keygen\mldsa-keygen.go
go run slhdsa-keygen\slhdsa-keygen.go
go run mldsa-siggen\mldsa-siggen.go
go run mldsa-sigver\mldsa-sigver.go
go run slhdsa-sigver\slhdsa-sigver.go
IF "%1"=="-doshlsig" (
    go run slhdsa-siggen\slhdsa-siggen.go
) ELSE (
    ECHO slhdsa-siggen.go OMITTED FOR TIME CONSTRAINTS
    ECHO To run type ``do-acvp-tests -doshlsig``
)

