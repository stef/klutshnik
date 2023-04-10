# syntax=docker/dockerfile:1
   
FROM python:3.11.1-alpine
WORKDIR /client
RUN apk add build-base libsodium-dev git openssl-dev python3 py3-pip python3-dev  
# RUN git clone https://github.com/stef/klutshnik
RUN git clone https://github.com/v-p-b/klutshnik
RUN git clone https://github.com/project-everest/hacl-star
RUN git clone https://github.com/stef/liboprf/
WORKDIR /client/liboprf
RUN make install
RUN cp liboprf.so /usr/lib
WORKDIR /client/klutshnik/XK_25519_ChaChaPoly_BLAKE2b 
ENV HACL_HOME /client/hacl-star
RUN make
WORKDIR /client/klutshnik
RUN git checkout docker
RUN make
WORKDIR /client/klutshnik/python
RUN pip install -r requirements.txt
ENV LD_LIBRARY_PATH /client/klutshnik
WORKDIR /client
RUN git clone https://github.com/stef/libopaque
WORKDIR /client/libopaque/src
ENV OPRFHOME /client/liboprf
RUN make install
WORKDIR /client/klutshnik/python
RUN touch klutshnik/__init__.py
RUN cp klutshnik/client.py .
RUN cp klutshnik/genkey.py .
WORKDIR /client/klutshnik
COPY startup.sh /client/klutshnik/startup.sh
COPY gen_config.py /client/klutshnik/gen_config.py
RUN mkdir python/keys
CMD ["/bin/sh","./startup.sh"]
