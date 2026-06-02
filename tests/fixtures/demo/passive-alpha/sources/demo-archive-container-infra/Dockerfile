FROM python:3.12-slim

ENV APP_TOKEN=token_should_never_render
WORKDIR /app
COPY . /app
RUN echo "passive demo only"
CMD ["python", "-m", "http.server", "8000"]
