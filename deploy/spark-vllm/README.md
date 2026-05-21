# vLLM on NVIDIA Spark (Docker) for THNewsCaster

Serves `Qwen/Qwen3-Next-80B-A3B-Instruct-FP8` via vLLM's OpenAI-compatible
API on **port 8001**, ready for THNewsCaster to consume.

The DGX Spark is **GB10 Grace-Blackwell, ARM64 (aarch64)** with unified
CPU/GPU memory — keep that in mind for image selection and memory tuning.

## Prerequisites

- Docker + the **NVIDIA Container Toolkit** installed and working:
  ```bash
  docker run --rm --gpus all ubuntu nvidia-smi   # should list the GB10 GPU
  ```
- A Hugging Face account/token with access to the model.
- ~80–100 GB free disk for the FP8 weights.

## Quick start

```bash
cd deploy/spark-vllm
cp .env.example .env
# edit .env: set HUGGING_FACE_HUB_TOKEN, confirm MODEL/VLLM_PORT
docker compose up -d
docker compose logs -f          # watch the first-run download + load
```

First boot downloads the model (slow, one-time) — `docker compose ps` will
show the service as `healthy` once it's serving. Then verify:

```bash
curl -s http://localhost:8001/v1/models | python3 -m json.tool
```

You should see the model id listed.

## Point THNewsCaster at it

In `/etc/thnewscaster/thnewscaster.env`:

```bash
THNC_OPENAI_BASE_URL=http://<spark-ip>:8001/v1
THNC_OPENAI_API_KEY=not-needed          # vLLM is open by default; any string
THNC_OPENAI_MODEL=Qwen/Qwen3-Next-80B-A3B-Instruct-FP8
THNC_OPENAI_TIMEOUT=300
THNC_MAX_BRIEFINGS=10
```

(If THNewsCaster runs on the Spark itself, use `http://127.0.0.1:8001/v1`.)
Then: `sudo systemctl start thnewscaster.service`.

## ARM64 image note

`vllm/vllm-openai:latest` publishes a multi-arch manifest, but if
`docker compose up` fails with **"no matching manifest for linux/arm64"**,
use NVIDIA's vLLM container built for the Spark instead. Find the current
tag in NGC (`nvcr.io/nvidia/vllm`) or the Spark "playbooks", then set it in
`.env`:

```bash
VLLM_IMAGE=nvcr.io/nvidia/vllm:<spark-tag>
```

You may need `docker login nvcr.io` first.

> **Qwen3-Next needs a recent vLLM.** Its hybrid (Gated DeltaNet + MoE)
> architecture was added in a recent release — if you see an
> "unknown architecture / model not supported" error, pull a newer image
> tag.

## Tuning on the Spark

- **`GPU_MEM_UTIL`** — unified memory is shared with the OS; start at `0.85`
  and lower it if you hit OOM, raise it if you have headroom.
- **`MAX_MODEL_LEN`** — 32k is ample here; lowering it frees KV-cache memory.
- Single GPU, so **no tensor-parallelism** flags are needed.

## Operations

```bash
docker compose ps              # health/status
docker compose logs -f vllm    # live logs (throughput, requests)
docker compose restart vllm    # restart
docker compose down            # stop (weights stay cached in HF_CACHE)
```

To run vLLM as a boot service, this compose file already has
`restart: unless-stopped`; just ensure Docker starts on boot
(`sudo systemctl enable docker`).

## Alternative: keep the Thinking model

If you'd rather not pull the Instruct weights, serve your existing
`...-Thinking-FP8` and set `THNC_OPENAI_DISABLE_THINKING=true` in
THNewsCaster's env — it tells vLLM to skip the reasoning pass for fast,
JSON-clean output.
