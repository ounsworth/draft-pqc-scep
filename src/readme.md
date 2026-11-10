# Generated draft content

The scripts in this directory generate content that the draft includes with `{::include ./src/<file>.md}`.

| Script | Output | Draft location |
|---|---|---|
| `generate_response_kek_example.py` | `responseKekExample.md` | Appendix "Worked Example: Response Key Derivation" |

## Setup

Requires python3, pip and venv.

```shell
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Regenerating

```shell
python3 generate_response_kek_example.py
```

The inputs are fixed, so the output only changes when the derivation changes. Commit the generated `.md` files so the draft builds without running Python.
