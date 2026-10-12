FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY profiles ./profiles
COPY examples ./examples
RUN pip install --no-cache-dir .
RUN useradd --create-home --shell /usr/sbin/nologin netscan
USER netscan
ENTRYPOINT ["netscan"]
CMD ["--help"]
