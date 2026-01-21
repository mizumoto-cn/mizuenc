# Mizu-encrypt

![Go Version](https://img.shields.io/badge/Go-1.24.4-yellow.svg)
[![License](https://img.shields.io/badge/License-MGPL%20v1.5-green.svg)](/Licensing/Mizumoto.General.Public.License.v1.5.md)

A Go template repository with MGPL License and workflow.

After creating a new repository from this template, you should update the following:

- [ ] `go.mod` file with the correct module name
- [ ] You must keep the `LICENSE` file and the `Licensing` folder as the license requires it
  - And all the files from this template repository are governed by the Mizumoto General Public License
- [ ] Setup a `codecov` token in the repository secrets from <https://app.codecov.io/>.
- [ ] Update `.golangci.yml` with the correct go version
- [ ] Update the `.lincenserc.json` file with the correct license information

## Table of Contents

- [Mizu-encrypt](#mizu-encrypt)
  - [Table of Contents](#table-of-contents)
  - [Documentation](#documentation)
  - [Usage](#usage)
    - [Install](#install)
    - [Encrypt](#encrypt)
    - [Decrypt](#decrypt)
  - [Milestones](#milestones)
  - [Roadmap](#roadmap)
  - [Contributing](#contributing)
  - [Licensing](#licensing)

## Documentation

All documentation is available in the [Wiki](./Wiki/) folder.

## Usage

### Install

Requires Go 1.24+.

Install the CLI to your machine:

```bash
go install github.com/mizumoto-cn/mizuenc@latest
```

Make sure `$(go env GOPATH)/bin` is in your `PATH`, then run:

```bash
mizuenc --help
```

### Encrypt

```bash
mizuenc encrypt "hello world"
```

### Decrypt

```bash
mizuenc decrypt "<token>"
```

## Milestones

## Roadmap

## Contributing

Please refer to the [CONTRIBUTING](./CONTRIBUTING.md) file for more information.

## Licensing

This project is licensed under the Mizumoto.General.Public.License - see the [LICENSE](./LICENSE) file.
As for the full context of this license, please refer to the markdown version: [Mizumoto General Public License v1.5](./licensing/Mizumoto.General.Public.License.v1.5.md).

---

copyRight @ 2026 Ruiyuan "mizumoto-cn" Xu <mizumoto@mizumoto.tech>