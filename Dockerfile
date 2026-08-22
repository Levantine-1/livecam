# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory to /app
WORKDIR /app

# Copy the requirements file to the working directory
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Expose port 5000
EXPOSE 5000

# Run the command to start the app.
#
# The defaults are wrong for this app in two ways that both break live
# video, and both were found the hard way:
#
#   --workers/--threads: gunicorn defaults to a single *synchronous*
#     worker, which serves exactly one request at a time. A live stream
#     holds its request open indefinitely, so the first camera consumed
#     the only worker and every other camera just hung -- the dashboard
#     showed one working tile and the rest blank.
#
#   --timeout 0: the default 30s worker timeout treats a long-lived
#     streaming response as a hung worker and kills it, so streams died
#     after a few seconds and gunicorn logged handle_abort/"Booting
#     worker". 0 disables that; the tradeoff is that a genuinely wedged
#     worker won't be recycled, which is the right trade for an app whose
#     normal case is holding connections open for minutes.
#
# ONE worker, many threads -- not a bigger process count. Live-stream
# tokens, heartbeat timestamps and the full-quality stream count are all
# module-level dicts, which are per-process: with 2 workers a token minted
# by one was unknown to the other, so requests 403d depending on which
# worker answered. Threads share memory, and these streams are I/O-bound
# (blocked on the upstream socket, not the GIL), so concurrency is
# unaffected. 96 threads covers 6 cameras against ~10 viewers with room,
# since each viewer holds one stream per camera they can see.
CMD ["gunicorn", "livecam:app", \
     "-b", "0.0.0.0:5000", \
     "--worker-class", "gthread", \
     "--workers", "1", \
     "--threads", "96", \
     "--timeout", "0", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
