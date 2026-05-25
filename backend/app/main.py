from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, File, Request, UploadFile, status

from app.config import load_settings
from app.models import DeletedFileResponse, JobListItem, JobRecord, StoredFile
from app.services import PdfAuditService
from app.storage import FileStore, JobStore


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    settings.ensure_directories()
    file_store = FileStore(settings)
    job_store = JobStore(settings)

    app.state.settings = settings
    app.state.files = file_store
    app.state.jobs = job_store
    app.state.pdf_audits = PdfAuditService(settings, file_store, job_store)
    yield


app = FastAPI(
    title="Inspectra",
    summary="Lightweight defensive security audit API.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "inspectra-backend"}


@app.post("/files/pdf", response_model=StoredFile, status_code=status.HTTP_201_CREATED)
async def upload_pdf(request: Request, file: UploadFile = File(...)) -> StoredFile:
    return await request.app.state.files.save_pdf(file)


@app.get("/files", response_model=list[StoredFile])
async def list_files(request: Request) -> list[StoredFile]:
    return request.app.state.files.list()


@app.get("/files/{file_id}", response_model=StoredFile)
async def get_file(request: Request, file_id: str) -> StoredFile:
    return request.app.state.files.get(file_id)


@app.delete("/files/{file_id}", response_model=DeletedFileResponse)
async def delete_file(request: Request, file_id: str) -> DeletedFileResponse:
    deleted_file = request.app.state.files.delete(file_id)
    associated_jobs_marked = request.app.state.jobs.mark_file_deleted(file_id)
    return DeletedFileResponse(deleted_file=deleted_file, associated_jobs_marked=associated_jobs_marked)


@app.post("/audits/pdf/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_pdf_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    request.app.state.files.get(file_id)
    job = request.app.state.jobs.create_pdf_job(file_id)
    background_tasks.add_task(request.app.state.pdf_audits.run_pdf_analysis, job.id)
    return job


@app.get("/jobs", response_model=list[JobListItem])
async def list_jobs(request: Request) -> list[JobListItem]:
    return request.app.state.jobs.list()


@app.get("/jobs/{job_id}", response_model=JobRecord)
async def get_job(request: Request, job_id: str) -> JobRecord:
    return request.app.state.jobs.get(job_id)
