FROM python:3.10.11-alpine3.17

# Adding Labels to identify repository for github
LABEL org.opencontainers.image.source=https://github.com/moyito2604/IOTScan
LABEL org.opencontainers.image.description="IOT Scanner"

# copy requirements, upgrade pip and install requirements.
COPY /requirements.txt /requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r /requirements.txt
RUN apk update
RUN apk upgrade --available && sync
RUN apk add --no-cache tshark

# Set work directory, copy source code to there
WORKDIR /app
COPY IOTScan.py .

ENV INTERFACE="wlan0"
ENV SOURCEIP="192.168.0"
ENV PACKETCNT=1000

CMD [ "python3", "-u", "IOTScan.py" ]