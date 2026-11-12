FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY requirements.txt .
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appliance
COPY . .
USER 10001:10001
EXPOSE 8080
CMD ["gunicorn","--bind","0.0.0.0:8080","--workers","2","--timeout","120","server:app"]
