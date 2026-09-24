# SecureBank API: imagen de la aplicación
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
ENV PYTHONPATH=/app/src

# El contenedor NO corre como root (deficiencia 05 de la Sesión 1)
RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000
# SECUREBANK_JWT_SECRET se inyecta en tiempo de ejecución, nunca se escribe en la imagen
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "securebank:create_app()"]
