FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    cmake \
    ninja-build \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY tests ./tests
COPY configs ./configs

RUN python -m pip install --upgrade pip setuptools wheel

RUN pip install -e ".[dev,pqc]"

# Force liboqs-python to build/install liboqs during image creation
RUN python -c "import oqs; print('liboqs-python import successful')"

CMD ["python", "-m", "qkd_hake.cli", "demo"]