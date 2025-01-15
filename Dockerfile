FROM python:3.12-slim

WORKDIR /app

# Instalar dependencias del sistema necesarias
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    pkg-config \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements.txt
COPY requirements.txt .

# Crear y activar entorno virtual
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Crear directorios necesarios
RUN mkdir -p exerciseImg && \
    chmod 777 exerciseImg

# Copiar el código de la aplicación
COPY . .

# Crear script de inicio
RUN echo '#!/bin/bash\nuvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}' > start.sh && \
    chmod +x start.sh

# Comando para ejecutar la aplicación
CMD ["./start.sh"]