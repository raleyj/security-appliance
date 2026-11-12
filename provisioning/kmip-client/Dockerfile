FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535
COPY requirements.txt .
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m pip uninstall -y setuptools wheel \
    && rm -rf /usr/local/lib/python3.11/ensurepip
COPY check.py /check.py
CMD ["python", "/check.py"]
