# syntax=docker/dockerfile:1

# Comments are provided throughout this file to help you get started.
# If you need more help, visit the Dockerfile reference guide at
# https://docs.docker.com/go/dockerfile-reference/

# Want to help us make this template better? Share your feedback here: https://forms.gle/ybq9Krt8jtBL3iCk7

ARG PYTHON_VERSION=3.9.13
FROM python:${PYTHON_VERSION}-slim as base

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the plication crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1


RUN apt-get update && \
    apt-get install -y tshark && \
    apt-get install -y iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create a non-privileged user that the p will run under.
# See https://docs.docker.com/go/dockerfile-user-best-practices/
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    puser

# Download dependencies as a separate step to take advantage of Docker's caching.
# Leverage a cache mount to /root/.cache/pip to speed up subsequent builds.
# Leverage a bind mount to requirements.txt to avoid having to copy them into
# into this layer.
RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=./detector/requirements.txt,target=./detector/requirements.txt \
    python -m pip install -r ./detector/requirements.txt

# Switch to the non-privileged user to run the plication.
USER puser

COPY ["output", "/app/output"]

# Copy the source code into the container.
COPY . . 
# Expose the port that the plication listens on.
EXPOSE 5000
# Run the plication.
CMD ["python", "detector/src/main.py"]
