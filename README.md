# Server-side Encryption HTTP API

This is a Server-side Encryption HTTP API that saves and retrieves encrypted data. The API uses Flask for HTTP operations, SQLAlchemy for database interactions, and the cryptography library for cryptographic operations.

## Implementation

The implementation includes:

- **Flask**: A lightweight and easy-to-use web framework for Python.
- **SQLAlchemy**: A SQL toolkit and Object-Relational Mapping (ORM) library for Python.
- **cryptography**: A library for various cryptographic recipes.

Additionally, the code incorporates the following cryptographic techniques:

- **Elliptic Curve Cryptography (ECC)**: Used for generating key pairs and implementing the Schnorr protocol.
- **Symmetric Encryption (AES)**: Used for encrypting data symmetrically.
- **Cryptographic Hash Functions (SHA-256)**: Used for generating hashes in the Schnorr protocol.
- **Cryptographic Accumulators**: Used for efficient addition and removal of elements.
- **Asymmetric Encryption (ECIES)**: Used for encrypting the symmetric key.

## How to Run the Code

1. Clone the repository:

```bash
git clone https://github.com/Ahsan-Abba5i/http-api-python.git
cd your-repo
```
2. Build the Docker image:
```bash
sudo docker build -t server-side-encryption-api .
```
3. Run the Docker container:
```bash
sudo docker run -p 4000:80 server-side-encryption-api
```
 Open your web browser and navigate to [http://127.0.0.1:4000](http://127.0.0.1:4000) to access the API.
   (Note: Ensure that the Flask app is running and check the terminal for any additional instructions or messages.)
