ARG BASEIMG
FROM $BASEIMG

COPY ./st2-auth-backend-immst /opt/stackstorm/st2-auth-backend-immst

USER root
WORKDIR /opt/stackstorm/st2/lib/python3.8/site-packages
RUN (cd /opt/stackstorm/st2-auth-backend-immst; . /opt/stackstorm/st2/bin/activate; /opt/stackstorm/st2/bin/python3 setup.py bdist_wheel;/opt/stackstorm/st2/bin/pip3 install dist/st2_auth_backend_immst-0.0.1-py3-none-any.whl)

WORKDIR /opt/stackstorm

USER st2
