import json
import os
import subprocess
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title="DPI Engine API",
    version="0.1.0",
    description="Backend API for the DPI Engine full-stack application",
)

# Resolve paths relative to this file
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
DPI_ENGINE_PATH = PROJECT_ROOT / "build" / "dpi_engine.exe"

# MSYS2 UCRT64 runtime DLLs are required by the compiled binary
UCRT64_BIN = Path(r"C:\msys64\ucrt64\bin")


@app.get("/api/health")
async def health_check():
    """Health-check endpoint to verify the server is running."""
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    """
    Accepts a PCAP file upload, runs the real dpi_engine.exe binary,
    and returns the structured JSON analysis results.
    """
    # --- 1. Validate the engine binary exists ---
    if not DPI_ENGINE_PATH.exists():
        raise HTTPException(
            status_code=400,
            detail=(
                f"dpi_engine.exe not found at {DPI_ENGINE_PATH}. "
                "Please build the project first (cmake --build build)."
            ),
        )

    # --- 2. Save uploaded file to a temp .pcap ---
    tmp_dir = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="dpi_")
        input_path = os.path.join(tmp_dir, "input.pcap")
        output_pcap_path = os.path.join(tmp_dir, "output.pcap")
        json_output_path = os.path.join(tmp_dir, "report.json")

        contents = await file.read()
        if len(contents) < 24:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is too small to be a valid PCAP (minimum 24 bytes for global header).",
            )

        with open(input_path, "wb") as f:
            f.write(contents)

        # --- 3. Run dpi_engine.exe ---
        # Prepend UCRT64 bin to PATH so the binary can find its runtime DLLs
        env = os.environ.copy()
        if UCRT64_BIN.exists():
            env["PATH"] = str(UCRT64_BIN) + os.pathsep + env.get("PATH", "")

        try:
            result = subprocess.run(
                [
                    str(DPI_ENGINE_PATH),
                    input_path,
                    output_pcap_path,
                    "--json-output",
                    json_output_path,
                ],
                capture_output=True,
                timeout=30,
                env=env,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(
                status_code=400,
                detail="dpi_engine.exe timed out after 30 seconds. The PCAP file may be too large.",
            )
        except FileNotFoundError:
            raise HTTPException(
                status_code=400,
                detail=f"Could not execute dpi_engine.exe at {DPI_ENGINE_PATH}.",
            )

        if result.returncode != 0:
            stderr_raw = result.stderr or result.stdout or b"No output"
            stderr_snippet = stderr_raw.decode("utf-8", errors="replace")[:500]
            raise HTTPException(
                status_code=400,
                detail=f"dpi_engine.exe failed (exit code {result.returncode}): {stderr_snippet}",
            )

        # --- 4. Read and return the JSON report ---
        if not os.path.exists(json_output_path):
            raise HTTPException(
                status_code=400,
                detail=(
                    "dpi_engine.exe completed but did not produce a JSON report. "
                    "The uploaded file may not be a valid PCAP."
                ),
            )

        with open(json_output_path, "r", encoding="utf-8") as jf:
            report = json.load(jf)

        # The C++ engine's JSON output already matches the frontend's
        # expected shape exactly (total_packets, forwarded, dropped,
        # active_flows, app_breakdown[].{app,count,percentage},
        # detected_domains[].{domain,app}), so no field remapping is needed.
        return report

    except HTTPException:
        # Re-raise FastAPI exceptions as-is
        raise
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=400,
            detail=f"dpi_engine.exe produced invalid JSON: {e}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Unexpected error during analysis: {e}",
        )
    finally:
        # --- 5. Clean up temp files ---
        if tmp_dir and os.path.exists(tmp_dir):
            for fname in os.listdir(tmp_dir):
                try:
                    os.remove(os.path.join(tmp_dir, fname))
                except OSError:
                    pass
            try:
                os.rmdir(tmp_dir)
            except OSError:
                pass


@app.get("/")
async def serve_frontend():
    """Serve the main frontend HTML file."""
    return FileResponse(FRONTEND_DIR / "code.html")


# Mount the frontend directory for any other static assets
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
