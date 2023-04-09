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
RUN apk add openssl-dev python3 py3-pip python3-dev # TODO merge
RUN pip install -r requirements.txt
COPY template.cfg /kms/klutshnik/klutshnik.cfg
COPY startup.sh /kms/klutshnik/python/startup.sh
ENV LD_LIBRARY_PATH /kms/klutshnik
EXPOSE 10000
CMD ["/bin/sh","./startup.sh"]
