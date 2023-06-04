# JWT Manager Helm Chart
The JWT Manager Helm Chart is a Kubernetes chart that provides a custom resource definition (CRD) for managing JSON Web Tokens (JWTs) and their signers in your Kubernetes cluster. It allows you to create and manage JWTs, and handles the signing process using various encryption algorithms.

## Installing the Chart

To install the JWT Manager chart, follow these steps:

1. Add the Helm repository:

```shell
helm repo add jwt-manager https://chximn.github.io/jwt-manager
```

2. Update the Helm repositories:
```shell
helm repo update
```

3. Install the chart with a release name of your choice:
```shell
helm install my-jwt-manager jwt-manager/jwt-manager
```


## Usage
Once the JWT Manager chart is installed, you can start using JWTs and JWT signers in your Kubernetes cluster. The chart provides two custom resource definitions (CRD): JWT and JWTSigner.

### JWT
The JWT CRD allows you to create, update, and delete JWTs. It has the following specification:

* `signer`: The name of the JWT signer to use for signing the token.
* `data`: The data to include in the JWT payload.
* `secretName`: The name of the Kubernetes Secret to store the generated JWT.
* `expiryTime`: The expiration time for the JWT. It can be specified in terms of days, hours, or minutes.
* `resignBefore`: The automation resign time for the JWT. It can be specified in terms of days, hours, or minutes.

Example JWT resource:

```yaml
apiVersion: k8s.chximn.pro/v1
kind: JWT
metadata:
  name: my-jwt
spec:
  signer: my-jwt-signer
  data:
    username: john.doe
    role: admin
  secretName: my-jwt-secret
  expiryTime:
    days: 1
  resignBefore:
    hours: 1
```

### JWTSigner
The JWTSigner CRD allows you to define the signers for JWTs. It has the following specification:

* `algorithm`: The encryption algorithm to use for signing the JWT.
* `key`: The key used for encryption. It can be provided as a secret, a config map, or a direct value.

Example JWTSigner resource with a secret key:

```yaml
apiVersion: k8s.chximn.pro/v1
kind: JWTSigner
metadata:
  name: my-jwt-signer
spec:
  algorithm: HS256
  key:
    secret:
      namespace: my-namespace
      name: my-secret
      key: secret-key
```

Example JWTSigner resource with a direct value:

```yaml
apiVersion: k8s.chximn.pro/v1
kind: JWTSigner
metadata:
  name: my-jwt-signer
spec:
  algorithm: RS256
  key:
    value: |
      -----BEGIN RSA PRIVATE KEY-----
      ...
      -----END RSA PRIVATE KEY-----
```

## Note
* Please ensure that you have the necessary permissions to create and manage custom resources (CRDs) in your Kubernetes cluster.