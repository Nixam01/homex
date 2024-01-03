FROM python:3.10.0-alpine
COPY . /code
WORKDIR /code
RUN pip3 install -r libraries.txt
RUN apk add tshark
RUN chgrp root /usr/bin/dumpcap
EXPOSE 8003
CMD python3 /code/agent.py
