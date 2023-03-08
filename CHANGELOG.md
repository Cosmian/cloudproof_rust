# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] - 2023-03-08

### Features

- Add the meta crate `cloudproof` in order to build 1 shared library containing both cover_crypt and findex

## [1.0.0] - 2023-03-07

### Documentation

- Create README.md

### Features

- Add existing findex and cover_crypt source code
- Get callback errors from Findex
- Add RusqliteFindex implementation
- Define workspace dependencies and mutualize findex and cover_crypt to 7.0.0
- Wrap FindexCloud in Pyo3

### Refactor

- Rebase on cover_crypt 11
