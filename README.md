# Blackbird incident PoC

This snapshot contains five synthetic incident houses, a generic HTTP JSON chat-model adapter, and offline tests. The houses are controlled feasibility demonstrations for Blackbird's design and functionality.

## Requirements and setup

Use Python 3.10 or newer. Only the Python standard library is required; there is no dependency installation step. Extract the ZIP and run commands from the extracted `blackbird-incident-poc` directory.

The complete offline suite uses synthetic in-memory targets and loopback mock services. It does not need a model service, credential, or non-loopback network access.

```sh
python -B -m unittest discover -v
```

The snapshot contains 133 tests. To run only the two-configuration, five-house guided/blind mock matrix:

```sh
python -B -m unittest -v cci_prototype.shoot_house.tests.test_http_guided_blind
```

## Generic model configuration

The runtime supports an HTTP JSON protocol with a catalog lookup and non-streaming, JSON-schema chat responses. A compatible service must return exactly one catalog entry matching the requested model, one textual JSON-object choice with a stop finish, matching model identity, and consistent token usage. Redirects are rejected.

Set configuration for the service being used; no service-specific endpoint, model, credential, or request default is supplied here:

```sh
export BLACKBIRD_MODEL_ENDPOINT='https://model-service.example.invalid/chat'
export BLACKBIRD_MODEL_CATALOG_ENDPOINT='https://model-service.example.invalid/catalog'
export BLACKBIRD_MODEL='your-model-identifier'
export BLACKBIRD_MODEL_CREDENTIAL_FILE='/absolute/path/outside/package/model-credential'
export BLACKBIRD_MODEL_OUTPUT_TOKENS_FIELD='output_cap'
export BLACKBIRD_MODEL_REQUEST_OPTIONS='{}'
export BLACKBIRD_MODEL_ALLOW_REMOTE='true'
```

Replace the placeholders and set the output-cap field and request options to values accepted by the configured service. `BLACKBIRD_MODEL_REASONING_FIELD` is optional and should be set only when the service supports a separate reasoning field. Loopback HTTP is intended for local mocks. Non-loopback endpoints require HTTPS and explicit remote authorization; URL userinfo, queries, and fragments are rejected.

For your privacy and security, please do not place credential files in the source tree or command history. `BLACKBIRD_MODEL_CREDENTIAL` is available as an alternative, but the file form avoids putting the value directly in an environment variable. The client redacts configured credentials from its traces, but model responses can still contain sensitive material.

## Guided and blind commands

Each command runs the synthetic `vulnerable` condition and writes a new record. Choose an output directory outside the extracted package. The CLI refuses to overwrite an existing record.

```sh
umask 077
mkdir -p ../incident-poc-runs

python -B -m cci_prototype.shoot_house.cli --house cline --condition vulnerable --out ../incident-poc-runs/cline-guided.json
python -B -m cci_prototype.shoot_house.cli --house cline --condition vulnerable --blind --out ../incident-poc-runs/cline-blind.json

python -B -m cci_prototype.shoot_house.cli --house sandbox-escape --condition vulnerable --out ../incident-poc-runs/sandbox-escape-guided.json
python -B -m cci_prototype.shoot_house.cli --house sandbox-escape --condition vulnerable --blind --out ../incident-poc-runs/sandbox-escape-blind.json

python -B -m cci_prototype.shoot_house.cli --house midnight-blizzard --condition vulnerable --out ../incident-poc-runs/midnight-blizzard-guided.json
python -B -m cci_prototype.shoot_house.cli --house midnight-blizzard --condition vulnerable --blind --out ../incident-poc-runs/midnight-blizzard-blind.json

python -B -m cci_prototype.shoot_house.cli --house hackerbot-claw --condition vulnerable --out ../incident-poc-runs/hackerbot-claw-guided.json
python -B -m cci_prototype.shoot_house.cli --house hackerbot-claw --condition vulnerable --blind --out ../incident-poc-runs/hackerbot-claw-blind.json

python -B -m cci_prototype.shoot_house.cli --house trivy-litellm --condition vulnerable --out ../incident-poc-runs/trivy-litellm-guided.json
python -B -m cci_prototype.shoot_house.cli --house trivy-litellm --condition vulnerable --blind --out ../incident-poc-runs/trivy-litellm-blind.json
```

Run records will contain model requests, responses, model identifiers, endpoint identities, and synthetic incident events.
# blackbird
