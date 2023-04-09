# syntax=docker/dockerfile:1
   
FROM node:18-alpine
WORKDIR /kms
RUN apk add build-base libsodium-dev git 
#RUN git clone https://github.com/stef/klutshnik
RUN git clone https://github.com/v-p-b/klutshnik
RUN git clone https://github.com/project-everest/hacl-star
RUN git clone https://github.com/stef/liboprf/
WORKDIR /kms/liboprf
RUN make install
RUN cp liboprf.so /usr/lib
WORKDIR /kms/klutshnik/XK_25519_ChaChaPoly_BLAKE2b 
ENV HACL_HOME /kms/hacl-star
RUN make
WORKDIR /kms/klutshnik
RUN git checkout docker
RUN make
WORKDIR /kms/klutshnik/python
RUN apk add python3 py3-pip python3-dev # TODO merge
RUN pip install -r requirements.txt

