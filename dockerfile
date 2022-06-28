FROM python:3.9

RUN mkdir /app
RUN mkdir /app/rules
RUN mkdir /app/result
RUN mkdir /app/file

WORKDIR /app

COPY /src .
COPY requirements.txt .
COPY entrypoint.sh .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8877
EXPOSE 19951
EXPOSE 8080

ENTRYPOINT [ "python3", "-u", "./main.py" ]