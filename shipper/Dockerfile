FROM python:3.9-slim
RUN pip install requests
WORKDIR /app
COPY shipper.py .
CMD ["python", "-u", "shipper.py"]