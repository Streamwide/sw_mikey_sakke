# sw_mikey_sakke
An implementation of a subset of 3GPP TS33.180

## Original libs
[minisip-mikey-sakke](https://bitbucket.org/secollab/minisip-mikey-sakke/wiki/Home)

[libmikey-sakke](https://bitbucket.org/secollab/libmikey-sakke/wiki/Home)

## Pre-requisite
### Tools
The following tools/libs are needed in order to build this project:
- cmake
- g++ or clang++

### Dependencies

- openssl 1.1.1 or newer (compiled from source. You can use installed version by providing `-DOPENSSL_ROOT_DIR=<path_to_openssl_dir>` at config time)
- libxml2 (needs to be installed on host system)
- libcurl (compiled from source)
- libgmp (compiled from source, only if you build with `-DOPENSSL_ONLY=ON`)
- spdlog (compiled from source, only if you build with `-DUSE_SPDLOG=ON`)

## Lib build
### Dependencies
Some libraries are supplied under ./third_party/.

The following libraries' paths need to be passed to cmake or it will try to look for them on the system:
* openssl (1.1.1 or 3.0)
* libxml2

### Standalone build

For ease of use, a few presets are provided. You are invited to check the content of `CMakePresets.json`

```
cmake . --preset dev
cmake --build --preset dev
```

## Tests
WARNING: Asan have an incompatibility with ubuntu-22.04, fix it with the following command (see https://github.com/actions/runner/issues/3481):
```
$ sudo sysctl vm.mmap_rnd_bits=28
```
```
ctest --preset dev
```

## Docs

* TS 33.180
* RFC 6507
* RFC 6508
* RFC 6509
