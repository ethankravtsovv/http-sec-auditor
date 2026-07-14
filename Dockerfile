FROM python:3.14-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py app_claude.py ./
COPY static/ static/

# Claude version by default; set APP_MODULE=app:app for the Gemini version.
# gthread workers: a scan can block ~90s worst case (slow target + redirects
# + AI call), so sync workers would let one slow site stall everyone.
ENV APP_MODULE=app_claude:app WEB_CONCURRENCY=2
EXPOSE 8000
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:8000 --workers ${WEB_CONCURRENCY} --worker-class gthread --threads 8 --timeout 90 ${APP_MODULE}"]
