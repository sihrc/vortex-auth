FROM python:3.8

LABEL author="Chris Lee"
LABEL email="sihrc.c.lee@gmail.com"

COPY . /vortex
WORKDIR vortex

RUN pip3 install -e .[testing]

CMD ["bash"]