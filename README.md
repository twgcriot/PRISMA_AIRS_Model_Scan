# Prisma AIRS Model Scan

Terminal helper for **Palo Alto Prisma AIRS AI Model Security**. It wraps the vendor `model-security` CLI so you can scan models from a **local directory** or a **public Hugging Face** repo, with optional loading of credentials from a dotenv file.

Official product documentation: [AI Model Security](https://docs.paloaltonetworks.com/ai-runtime-security/ai-model-security/model-security-to-secure-your-ai-models/get-started-with-ai-model-security/scanning-models) (scanning models, install, security groups).

## Requirements

- **Python 3.11+** (matches AI Model Security CLI/SDK expectations)
- Prisma AIRS **AI Model Security** entitlement, **SCM** service account, and a **security group** whose source type matches how you scan (e.g. `HUGGING_FACE` vs `LOCAL`)

The `model-security-client` package is installed from your **tenant PyPI URL**, not the unrelated placeholder on public PyPI.

## Quick start

### 1. Clone and create a virtual environment

```bash
git clone https://github.com/twgcriot/PRISMA_AIRS_Model_Scan.git
cd PRISMA_AIRS_Model_Scan
python3.11 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -U pip
pip install -e .
```

### 2. Configure credentials (do not commit secrets)

```bash
cp config/model-security.env.example config/model-security.env
```

Edit `config/model-security.env` with your **client ID**, **client secret**, **TSG ID**, and **API endpoint** from Palo Alto’s install/onboarding docs.

`config/model-security.env` is listed in `.gitignore` and must stay local.

### 3. Install the vendor CLI and SDK

Either set `MODEL_SECURITY_PYPI_URL` in that file (from SCM `mgmt/v1/pypi/authenticate`) and run:

```bash
./scripts/install-pan-model-security.sh
```

Or fetch the URL and install in one line:

```bash
pip install "model-security-client[all]" --extra-index-url "$(python scripts/fetch-pan-pypi-url.py)"
```

(`fetch-pan-pypi-url.py` reads the same dotenv files as `airs-modelscan`.)

### 4. Verify the environment

```bash
airs-modelscan doctor
```

### PDF report of scan history (Data Plane API)

The [Prisma AIRS AI Model Security API](https://pan.dev/prisma-airs-model-security/api/aisecuritymodel/aisecuritymodel/) documents the management and data planes. The `report-pdf` subcommand calls **`GET /data/v1/scans`** (paginated), builds a **landscape PDF table** of recent scans, then appends **per-scan detail pages** (file inventory from `/files` and violations from `/rule-violations`) plus a **full UUID reference**. Add **`--include-evaluations`** to also fetch and print the **per-rule evaluation** table on each detail page.

```bash
airs-modelscan report-pdf -o scans-report.pdf
airs-modelscan report-pdf -o report.pdf --max-scans 500 --include-evaluations
airs-modelscan report-pdf --security-group-uuid "<uuid>" -o hf-only.pdf
```

Requires the Python SDK (`model-security-client`) and the same OAuth env vars as scans; it does **not** require the `model-security` binary on `PATH`.

Each scan gets a **detail section** with a tight header, **files in scan** (path, type, result, formats, and counts), and **violations grouped by file**. With **`--include-evaluations`**, a **rule evaluations** table (short rule summary per row) is added above the file table. Row counts are capped so sections usually fit comfortably; long scans may spill across pages.

## Usage

`airs-modelscan` loads the first dotenv file it finds among:

- `MODEL_SECURITY_ENV_FILE` (path), or
- `.env`, `model-security.env`, `config/model-security.env`

Override with `--env-file /path/to/file`.

### Hugging Face (public repos only)

You need a security group with source type **HUGGING_FACE**. Discover UUIDs in Strata Cloud Manager or via the Model Security API.

```bash
airs-modelscan hf \
  --security-group-uuid "<uuid>" \
  org/model-name \
  -l env=dev
```

Optional: pin revision, restrict files with globs (repeat `--allow-patterns` or pass multiple globs per flag):

```bash
airs-modelscan hf \
  --security-group-uuid "<uuid>" \
  Qwen/Qwen3-Reranker-4B \
  --revision "<git-sha>" \
  --allow-patterns "*.json" "*.safetensors"
```

Forward extra flags to `model-security scan` after a bare `--`:

```bash
airs-modelscan hf --security-group-uuid "<uuid>" org/model -- --poll-timeout-secs 3600
```

### Local directory

Use a security group with source type **LOCAL**.

```bash
airs-modelscan local --security-group-uuid "<uuid>" /path/to/model/dir -l env=dev
```

### Dry run

Print the `model-security` command without executing:

```bash
airs-modelscan hf --security-group-uuid "<uuid>" org/model --dry-run
```

## Exit codes

The underlying `model-security` CLI exits **non-zero** when the model **fails** your security group (e.g. `BLOCKED`). That is expected policy behavior, not a crash.

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/fetch-pan-pypi-url.py` | OAuth + `pypi/authenticate`; prints tenant PyPI URL to stdout |
| `scripts/install-pan-model-security.sh` | `pip install "model-security-client[all]"` using `MODEL_SECURITY_PYPI_URL` or dotenv |

## Development

```bash
source .venv/bin/activate
pip install -e .
PYTHONPATH=src python -m prisma_airs_modelscan.cli --help
```

## License

This repository is a thin wrapper around Palo Alto **model-security-client**; use of scanning features requires a valid Palo Alto Networks agreement and credentials. Refer to Palo Alto documentation for product terms.
