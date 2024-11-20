### 2.167.2 (build 3669dce) ###

FROM public.ecr.aws/docker/library/python:latest

WORKDIR /app

COPY expansion.py requirements.txt .

RUN pip install -r requirements.txt --no-cache-dir --upgrade

ENTRYPOINT [ "python", "/app/expansion.py" ]
