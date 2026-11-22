# Score a candidate model

Run the evaluator from the repository root with Python 3.11 or newer. Start
llama.cpp with the candidate GGUF and an explicit context size. Use
`Get-FileHash <file.gguf> -Algorithm SHA256` on Windows to get the file digest.
Pass the server's build version, model name and configured context size.

```powershell
py -3 -m eval.run_eval --url http://localhost:8080/v1 --model <served-name> --model-sha256 <sha256> --llama-version <build> --context 16384 --output evidence.json
```

Use `python3` in place of `py -3` on Linux. The URL can point to an
OpenAI-compatible server on another host or use a custom API base path. You can
also pass the full chat completions URL. Use an endpoint that accepts
unauthenticated requests.

The runner reads the raw synthetic records in `cases/`, including hostile
banners, titles and DNS names. The model request uses the same structured
observations and evidence IDs as a live request. Lookup results come from
in-memory records. The scores apply to the full path from fixture to explanation.

The runner checks all 30 fixture files against the versioned SHA-256 before
calling the endpoint. Run each candidate with the same case set. If a fixture
must change, add a new version and its aggregate hash to `CASE_SET_HASHES`.
The hash error prints the digest of the changed set.

Each of three repeats records the class counts, case results and checks from
the [v1 plan](../docs/v1-plan.md#model-test-set-and-pass-bar). Evidence support
is 0 for zero required citations, 1 for some, and 2 for all. Latency includes
any lookup round trips and uses the nearest-rank 95th percentile. The JSON
records the prompt, schema, tools and sampling settings sent by the runner.
The model digest, runtime build and context size come from the server operator.

Exit code 0 means all repeats pass. Exit code 1 means a check failed and the
evidence file contains the results. Exit code 2 means a setup, fixture hash,
endpoint or output error prevented a completed run. The runner stops at the
first endpoint request failure.
