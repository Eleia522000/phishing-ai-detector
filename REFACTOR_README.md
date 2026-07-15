# MsgGuard Backend Refactor

This folder contains a modular replacement for the original long `Backend/msgguard.py`.
The API endpoints and JSON response structure were preserved.

## Copying the files

1. Create a backup branch or commit before replacing anything.
2. Copy the new folders and files into the existing `Backend` directory.
3. Keep the existing `Backend/requirements.txt` file.
4. Keep the existing root-level `models/bert_model_v4` directory.
5. Rename the original file before replacement, for example:

```text
Backend/msgguard_old.py
```

6. Copy the modular `Backend/msgguard.py` into its place.

## New structure

```text
Backend/
├── __init__.py
├── config.py
├── database.py
├── msgguard.py
├── requirements.txt
├── analyzers/
│   ├── __init__.py
│   ├── message_analyzer.py
│   ├── url_analyzer.py
│   ├── brand_analyzer.py
│   └── domain_analyzer.py
├── services/
│   ├── __init__.py
│   └── bert_service.py
├── decision/
│   ├── __init__.py
│   └── decision_engine.py
└── utils/
    ├── __init__.py
    └── helpers.py
```

## Running the backend

From the repository root:

```powershell
python Backend/msgguard.py
```

The old command also works:

```powershell
cd Backend
python msgguard.py
```

## Verification

Test the health endpoint:

```text
http://127.0.0.1:5000/health
```

Then test the analyze endpoint with the same frontend or test scripts used before.
The frontend does not need changes because `/health`, `/analyze`, and the response fields remain unchanged.
