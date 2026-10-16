FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY target ./target
COPY scanner ./scanner
RUN pip install --no-cache-dir .

RUN useradd --create-home lab
USER lab

# The target binds 0.0.0.0 only inside the container; compose publishes it on 127.0.0.1.
EXPOSE 8000
CMD ["uvicorn", "target.main:app", "--host", "0.0.0.0", "--port", "8000"]
