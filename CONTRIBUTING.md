# Contributing

Use the Linux prerequisites and source install steps in [the README](README.md).
Run the tests from the source directory before opening a pull request.

```sh
python3 -m unittest discover -s tests -v
```

Include the behavior you changed, how you verified it, and any coverage gaps.
Use synthetic fixtures or an isolated lab for network tests. Keep real network
addresses, hostnames, logs, and credentials out of issues, patches, and test
fixtures. Report vulnerabilities privately. [Security policy](SECURITY.md)
