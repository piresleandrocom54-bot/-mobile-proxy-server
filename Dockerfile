FROM python:3.12-slim
WORKDIR /app
COPY proxy.py .
ENV PORT=3030
EXPOSE 3030
CMD ["python3", "proxy.py"]
