# Crypto-DSA

DSA implementation with OpenSSL library in C++.

## Install OpenSSL Library

Debian / Ubuntu:

```bash
$ sudo apt install libssl-dev
```

Fedora / CentOS / RHEL:

```bash
$ sudo yum install openssl-devel
```

## Build

```bash
$ git clone https://github.com/Triple-Z/Crypto-DSA.git
$ cd Crypto-DSA/
$ cd src/
$ make
$ make run
```

> `OpenSSL`, `GNU Make` & `G++` required.

## Clean

```bash
$ make clean
```

## Debug

```bash
$ make debug
```

> `GDB` required.

