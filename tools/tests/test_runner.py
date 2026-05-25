import runner.main as runner
import pytest
from httpx import ASGITransport, AsyncClient


SAMPLE_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"


def test_run_command_records_timeout(monkeypatch):
    monkeypatch.setattr(runner, "COMMAND_TIMEOUT_SECONDS", 0.01)

    result = runner.run_command(["python3", "-c", "import time; time.sleep(1)"])

    assert result["timed_out"] is True
    assert result["exit_code"] is None
    assert result["timeout_seconds"] == 0.01


@pytest.mark.anyio
async def test_analyze_image_returns_passive_metadata(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir()
    image_path = uploads_dir / "pixel.png"
    image_path.write_bytes(SAMPLE_PNG)
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    monkeypatch.setattr(runner, "run_command", fake_image_command)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/image",
            json={"file_id": "f" * 32, "relative_path": "uploads/pixel.png"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["analyzer"] == "inspectra-image-basic"
    assert payload["identification"]["detected_format"] == "png"
    assert payload["identification"]["mime_type"] == "image/png"
    assert payload["metadata"]["exiftool"]["ImageWidth"] == 1
    assert payload["privacy_indicators"]["gps_present"] is True
    assert payload["hashes"]["sha256"]


@pytest.mark.anyio
async def test_analyze_image_rejects_path_traversal(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/image",
            json={"file_id": "f" * 32, "relative_path": "../outside.png"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Path escapes data directory."


def fake_image_command(args: list[str]) -> dict:
    stdout = ""
    if args[0] == "file" and "--mime-type" in args:
        stdout = "image/png\n"
    elif args[0] == "file":
        stdout = "PNG image data, 1 x 1, 8-bit/color RGB\n"
    elif args[0] == "exiftool":
        stdout = '[{"ImageWidth":1,"ImageHeight":1,"MIMEType":"image/png","GPSLatitude":40.0,"Software":"unit-test"}]'

    return {
        "command": args[0],
        "args": args[1:-1],
        "exit_code": 0,
        "duration_ms": 1.0,
        "stdout": stdout,
        "stderr": "",
        "timed_out": False,
        "timeout_seconds": runner.COMMAND_TIMEOUT_SECONDS,
    }
