FROM python:3.10
ADD requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt
ADD operator.py /app/operator.py
WORKDIR /app
ENV API_GROUP "k8s.chximn.pro"
ENV API_GROUP_VERSION "v1"
ENV JWT_CRD "jwts"
ENV JWT_SIGNER_CRD "jwt-signers"
ENTRYPOINT [ "kopf", "run", "--all-namespaces", "operator.py"]