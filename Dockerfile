FROM python:3.14-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py app_claude.py ./
COPY static/ static/

# Claude version by default; set APP_MODULE=app:app for the Gemini version.
ENV APP_MODULE=app_claude:app
EXPOSE 8000
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:8000 --workers 2 --timeout 60 ${APP_MODULE}"]
