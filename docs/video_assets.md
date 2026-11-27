# Video assets: toolarg-guard

Three concrete commands for a short demo video; every quoted output below was captured from the real CLI.

## Beat sheet (outputs are captured from real runs)

| time | beat | command | captured output (first line) |
| --- | --- | --- | --- |
| 0:00-0:25 | Hook: the model asks the shell tool to run a chained command | `python -m toolarg_guard scan examples/dangerous_call.json` | toolarg-guard 0.1.0  scan  examples/dangerous_call.json  (4 call(s)) |
| 0:25-1:00 | The CI gate refuses to execute it | `python -m toolarg_guard scan examples/dangerous_call.json --fail-on high` | toolarg-guard 0.1.0  scan  examples/dangerous_call.json  (4 call(s)) |
| 1:00-1:35 | JSON-Schema validation catches a malformed call | `python -m toolarg_guard scan examples/bad_schema_call.json --tools examples/tools.json` | toolarg-guard 0.1.0  scan  examples/bad_schema_call.json  (3 call(s)) |
| 1:35-2:05 | Legitimate calls stay clean | `python -m toolarg_guard scan examples/clean_call.json --fail-on low` | toolarg-guard 0.1.0  scan  examples/clean_call.json  (4 call(s)) |
| 2:05-2:25 | Tests and honest limits | python -m unittest discover -s tests -t . | Ran 42 tests in ... OK |

## Real command transcripts for the recording

### 0:00-0:25 -- Hook: the model asks the shell tool to run a chained command

The command contains `; rm -rf ... && curl http://169.254.169.254/...`; expose the high findings.

```console
$ python -m toolarg_guard scan examples/dangerous_call.json
toolarg-guard 0.1.0  scan  examples/dangerous_call.json  (4 call(s))
call 1/4  tool=shell.run  findings=3  max_severity=high
  HIGH   ARG-SSRF-METADATA        arguments.command            URL targets a cloud metadata endpoint (169.254.169.254)
  HIGH   ARG-COMMAND-CHAIN        arguments.command            unquoted command chaining (; && ||) in a shell argument
  HIGH   ARG-PATH-TRAVERSAL       arguments.cwd                path traversal sequence escapes the working directory
call 2/4  tool=file.read  findings=1  max_severity=high
  HIGH   ARG-ABS-SENSITIVE-PATH   arguments.path               sensitive absolute path (credentials, system or autostart location)
call 3/4  tool=http.fetch  findings=1  max_severity=high
  HIGH   ARG-SSRF-LOOPBACK        arguments.url                URL targets loopback/unspecified host '127.0.0.1'
call 4/4  tool=shell.run  findings=1  max_severity=high
  HIGH   ARG-ABS-SENSITIVE-PATH   arguments.command            sensitive absolute path (credentials, system or autostart location)
summary: 6 finding(s): 6 high, 0 medium, 0 low
[exit code: 0]
```

### 0:25-1:00 -- The CI gate refuses to execute it

`--fail-on high` exits 1 before any tool runs.

```console
$ python -m toolarg_guard scan examples/dangerous_call.json --fail-on high
toolarg-guard 0.1.0  scan  examples/dangerous_call.json  (4 call(s))
call 1/4  tool=shell.run  findings=3  max_severity=high
  HIGH   ARG-SSRF-METADATA        arguments.command            URL targets a cloud metadata endpoint (169.254.169.254)
  HIGH   ARG-COMMAND-CHAIN        arguments.command            unquoted command chaining (; && ||) in a shell argument
  HIGH   ARG-PATH-TRAVERSAL       arguments.cwd                path traversal sequence escapes the working directory
call 2/4  tool=file.read  findings=1  max_severity=high
  HIGH   ARG-ABS-SENSITIVE-PATH   arguments.path               sensitive absolute path (credentials, system or autostart location)
call 3/4  tool=http.fetch  findings=1  max_severity=high
  HIGH   ARG-SSRF-LOOPBACK        arguments.url                URL targets loopback/unspecified host '127.0.0.1'
call 4/4  tool=shell.run  findings=1  max_severity=high
  HIGH   ARG-ABS-SENSITIVE-PATH   arguments.command            sensitive absolute path (credentials, system or autostart location)
summary: 6 finding(s): 6 high, 0 medium, 0 low
FAIL: 6 finding(s) at or above severity 'high'
[exit code: 1]
```

### 1:00-1:35 -- JSON-Schema validation catches a malformed call

Wrong type + bad enum + missing required property, independent of the security rules.

```console
$ python -m toolarg_guard scan examples/bad_schema_call.json --tools examples/tools.json
toolarg-guard 0.1.0  scan  examples/bad_schema_call.json  (3 call(s))
call 1/3  tool=weather.get  findings=2  max_severity=medium
  MEDIUM TOOL-SCHEMA-TYPE         arguments.city               expected type string, got integer
  MEDIUM TOOL-SCHEMA-ENUM         arguments.units              value 'kelvin' is not one of ['metric', 'imperial']
call 2/3  tool=weather.get  findings=2  max_severity=medium
  MEDIUM TOOL-SCHEMA-REQUIRED     arguments.city               required property is missing
  MEDIUM TOOL-SCHEMA-RANGE        arguments.days               value above maximum 14
call 3/3  tool=weather.get  findings=1  max_severity=medium
  MEDIUM TOOL-SCHEMA-PROPERTY     arguments.debug              property is not allowed by additionalProperties: false
summary: 5 finding(s): 0 high, 5 medium, 0 low
[exit code: 0]
```

### 1:35-2:05 -- Legitimate calls stay clean

No findings at the strictest gate; the semicolon inside a benign text argument is not flagged.

```console
$ python -m toolarg_guard scan examples/clean_call.json --fail-on low
toolarg-guard 0.1.0  scan  examples/clean_call.json  (4 call(s))
call 1/4  tool=weather.get  findings=0  max_severity=none
call 2/4  tool=file.read  findings=0  max_severity=none
call 3/4  tool=http.fetch  findings=0  max_severity=none
call 4/4  tool=translate.text  findings=0  max_severity=none
summary: 0 finding(s): 0 high, 0 medium, 0 low
PASS: no finding at or above severity 'low'
[exit code: 0]
```

### 2:05-2:25 -- Tests and honest limits

```console
$ python -m unittest discover -s tests -t .
Ran 42 tests
OK
```

## Ready files for the edit

- `docs/screenshots/terminal_clean.txt`
- `docs/screenshots/terminal_gate.txt`
- `docs/screenshots/terminal_scan.txt`
- `docs/screenshots/terminal_schema.txt`
- `docs/screenshots/terminal_tests.txt`
- `docs/EVIDENCE.md`
- `examples/dangerous_call.json`
- `examples/tools.json`

## OBS/screen-recording notes

- Record a 1920x1080 terminal at 120x32 characters; the commands above fit without wrapping.
- Run every command from the repository root so the relative paths match.
- The JSON runs are for the evidence log only and are not needed on camera.

## Caveats to state on camera

The JSON-Schema support is a deliberate subset, not full Draft 2020-12. Shell rules apply to command-like arguments, while path and URL rules apply to every string; document the residual risk and keep tool implementations parameterised and least-privileged.
