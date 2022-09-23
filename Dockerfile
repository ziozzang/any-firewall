FROM python:3

WORKDIR /opt
COPY * /opt/
EXPOSE 8080
RUN apt update && apt install -fy clamav clamav-daemon && \
    pip install -r requirements.txt && \
    rm -rf /var/lib/apt/lists/*

#RUN freshclam

CMD ["bash", "/opt/startup.sh"]
