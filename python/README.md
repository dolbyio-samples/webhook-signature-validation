# Python Webhook Signature Validation

The purpose of this project is to showcase the python implementation for validating the Dolby-Signature webhook Ed25519 signature header.

## Prerequisites

#### Versions

* Python version: `Python 3.9.0`
* Pip version: `pip 20.2.3`

#### Environment

If you wish to use a virtual environment be sure to run these first, if not simply ignore the 2 commands below.
```shell
python3 -m venv venv
source venv/bin/activate
```

#### Dependencies

Install dependencies:
```shell
pip install -r requirements.txt
```

## Content

* `validation.py`: contains the sample validation code with comments explaining every step to validate a signature.
