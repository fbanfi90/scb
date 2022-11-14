# SCB Mode: _Semantically Secure Length-Preserving Encryption_

Conventional symmetric-key *length-preserving* encryption schemes do not achieve semantic security.
This means that repeated plaintexts, or even just repeating blocks within plaintexts, are mapped to the same ciphertext bitstrings.
**Secure Codebook (SCB) mode of operation** is the first length-preserving encryption scheme that *does achieve semantic security*.
This is possible because SCB allows decryption _not_ to be perfect.
More precisely, encrypting a message $m$ into a ciphertext $c$ and later decrypting $c$ might result in message $m'$ different from $m$.
But crucially, this only happens with *negligible probability*, if the parameters $\sigma$ and $\tau$ defined by SCB are appropriately chosen.
This choice strongly depends on the setting in which an instance of SCB is meant to be used.
For more details, see the paper appearing in [IACR Transactions on Symmetric Cryptology, Volume 2022, Issue 4](https://crypto.ethz.ch/publications/files/Banfi22.pdf).
SCB can be instantiated with any block cipher and compression function, and this code specifically implements SCB with $n=128$ as $\textsf{SCB}[\texttt{AES-128},\texttt{SHA-256}]$, where the output of SHA is truncated to $\tau$ bits.

## SCB Parameters

SCB Mode defines two parameters, $\sigma$ and $\tau$, and it requires $\sigma+\tau\leq n$.
The first affects *security*, while the second affects *correctness*.
More concretely, SCB guarantees semantic security, provided **the total number $\beta$ of blocks of $n$ bits of the encrypted plaintexts does not exceed $2^\sigma$**.
This is because SCB uses $\sigma$ bits for counters that keep track of repeated blocks of plaintext.
Reasonable values for $\sigma$ are dictated by the following equation:
$$\log\beta\leq\sigma\leq n-2\log\beta.$$
On the other hand, SCB internally compresses each block of plaintext into a hash value of $\tau$ bits, and therefore reasonable values for $\tau$ are dictated by the following equation:
$$2\log\beta\leq\tau\leq n-\sigma.$$
Together, these two equations govern the trade-off between security and correctness.
For example, for this implementation with $n=128$, if it can be estimated that $\beta\leq2^{10}$, then a reasonable choice of parameters would be $\sigma=10$ and $\tau=108$.
If instead it can be estimated that $\beta\leq2^{20}$, then a reasonable choice of parameters would be $\sigma=20$ and $\tau=108$.
See the paper for a more in-depth explanation.

> **Note:** since currently the code only allows to instantiate $\sigma$ and $\tau$ as **multiples of 8**, the above parameters choice for the case of $\beta\leq2^{20}$ should be either $\sigma=24$ and $\tau=104$ (``max_count = 3`` and ``max_hash = 13``, see below) or $\sigma=16$ and $\tau=116$ (``max_count = 2`` and ``max_hash = 14``).

## Code

### Compiling and Running

Running `make` in Linux or `compile.bat` in Windows (in a [developer command prompt](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line)) will generate **two** executables: `bin/scb_file[.exe]` and `bin/scb_image[.exe]`.
The program `scb_file` allows to encrypt any file, while `scb_image` allows to *visually* encrypt PNG images (only the color stream is encrypted), and is only meant for demonstration purposes.

The syntax for `scb_file` is as follows:

```sh
./scb_file enc[+]|dec max_count max_hash key_file input_file [verbose]
```

The options and inputs are explained in detail in the table below.

| Option / Input | Details |
| ------ | ------ |
| `enc` | Encrypt the file `input_file` using the key stored in `key_file`. |
| `enc+` | Like `enc`, but additionally report the number of errors that would result upon successive decryption (activates the option `verbose`). |
| `dec` | Decrypt the file `input_file` using the key stored in `key_file`. |
| `max_count` | The parameter $\sigma$ of SCB _divided by 8_ (affects security). Must be an integer between 0 and 16. |
| `max_hash` | The parameter $\tau$ of SCB _divided by 8_ (affects correctness). Must be an integer between 0 and 16. |
| `key_file` | The file to be used as key. Must be at least 16 bytes in size. |
| `input_file` | The file to be encrypted or decrypted. |
| `verbose` | Optional, output information about encryption and decryption. |

> **Note:** it is required that `max_count + max_hash <= 16`

The syntax for `scb_image` is as follows:

```sh
./scb_image enc[+]|dec|ecb max_count max_hash key_file input_file.png [verbose]
```

The options and inputs follow the specification of `scb_file`, with the exceptions explained in the table below.

| Option / Input | Details |
| ------ | ------ |
| `ecb` | Visually encrypt the image file `input_file.png` using the key stored in `key_file` in ECB mode (for reference only). |
| `input_file.png` | The image file to be visually encrypted or decrypted. It must be a valid PNG file. |

### Dependencies

The code only requires the [OpenSSL] library to be installed on the system (in addition to the standard C library).
For windows, the script `compile.bat` assumes OpenSSL to be installed in `C:\openssl-3`.

The other two libraries used in this project are [hashmap.c] and [stb] (both also released under the MIT license), and the relevant files are included in the project.

## Test

The folder `test/` contains Linux (`test.sh`) and Windows (`test.bat`) script files that test the reproducibility of the figures from the paper.
When run, the test will print `OK` for each generated file `{cor,sec}/file.png` if it equals the reference file `ref/{cor,sec}/file.png`, and `FAIL` otherwise.

## Notice

The code is provided without any warranty and has *not* been written with efficiency in mind.

[OpenSSL]: <https://www.openssl.org/>
[hashmap.c]: <https://github.com/tidwall/hashmap.c>
[stb]: <https://github.com/nothings/stb>