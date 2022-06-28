FROM python:3.9

LABEL name="yaraservice"
LABEL version="1.0"

RUN git clone https://github.com/D-XIII/yara-api && cd yara-api

EXPOSE 8877/tcp

RUN pip install redis dotenv-python flask yara-python mongo 

CMD [ "python", "main.py" ] 
