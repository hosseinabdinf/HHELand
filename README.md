# HHESoK

Implementation for [The HHE Land: Exploring the Landscape of Hybrid Homomorphic Encryption](https://eprint.iacr.org/2025/071)



# Testing Instruction

## HE-friendly ciphers

To test each symmetric cipher, navigate to its respective directory:

    $ cd ./symcips/CNAME/

Then execute the following commands:

    $  go test -run TestCNAME

To obtain comprehensive benchmarking results, execute the following commands:

    $  go test -bench=^BenchmarkCNAME$ -benchmem

Replace "CNAME" with the name of the desired cipher, for which a benchmark is
available, from the following list:

    Available CNAMES for Benchmarking:
    - Pasta3:   PASTA cipher with 3 rounds
    - Pasta4:   PASTA cipher with 4 rounds
    - Hera:     HERA cipher
    - Rubato:   Rubato cipher

## HHE scheme

To test each HHE scheme, navigate to its respective directory:

    $ cd ./hhe/CNAME/

Then execute the following commands:

    $ go test -run TestCNAME -timeout=120m

To obtain comprehensive benchmarking results, execute the following commands:

    $ go test -bench=BenchmarkCNAME -benchtime=1x -timeout=120m -benchmem -run=^$

Replace "CNAME" with the name of the desired cipher, for which a benchmark is
available, from the following list:

    Available CNAMES for Benchmarking:
    - Pasta3:       PASTA cipher with 3 rounds    (single ciphertext)
    - Pasta4:       PASTA cipher with 4 rounds    (single ciphertext)
    - Pasta3Pack:   PASTA cipher with 3 rounds    (full coefficient)
    - Pasta4Pack:   PASTA cipher with 4 rounds    (full coefficient)
    - Hera:         HERA cipher                   (full coefficient)
    - Rubato:       Rubato cipher                 (full coefficient)

## How to cite

    @misc{cryptoeprint:2025/071,
      author = {Hossein Abdinasibfar and Camille Nuoskala and Antonis Michalas},
      title = {The {HHE} Land: Exploring the Landscape of Hybrid Homomorphic Encryption},
      howpublished = {Cryptology {ePrint} Archive, Paper 2025/071},
      year = {2025},
      url = {https://eprint.iacr.org/2025/071}
    }