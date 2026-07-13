# Tests - Web Demonstration

[Versão em Português](READMEPT.md)

This directory contains a complete simulation application (Frontend and Backend Node.js), developed specifically for academic purposes, in order to validate the **Database Security Middleware** operating in real-time.

By using the orchestration configured in this environment, the infrastructure automatically spins up and configures isolated PostgreSQL databases, HashiCorp Vault, two Middleware instances (Per-Row and Shared), and the Client application.

> [!NOTE]
> All databases created here are inside containers. The website will perform automatic table injection as soon as it is accessed.

## Requirements
To run the virtualized infrastructure:
- Docker Engine v24.0+
- Docker Compose v2.20+

## Running the Test

If you want to evaluate the Middleware functioning already coupled to the website:

> [!WARNING]
> **Beware of the Execution Folder!**
> Make sure you are inside this directory (`demo/`) to spin up the tests. If you run `docker-compose` in the root of the repository, it will spin up the Production version.

1. Enter the test directory:
   ```bash
   cd demo/
   ```
2. Start the cluster orchestration:
   ```bash
   docker-compose up -d --build
   ```
3. Wait about 15 to 20 seconds. A script will run internally in the Docker network to initialize HashiCorp Vault, provision the master keys, and inject the variables.

> [!TIP]
> If the web interface returns an `ECONNREFUSED` error, Vault is still generating the keys. Wait an additional 10 seconds.

4. Access the application interface in your local browser:
   `http://localhost:3000`

## Test Environment

The demonstration environment was built to prove the effectiveness of the middleware. Below is the operational flow:

### 1. Access Portal
The entry point of the lab simulates a corporate intranet connecting the application to two distinct databases.

![Access Portal](../docs/assets/1.png)

### 2. Clinic

![Clinic Registration](../docs/assets/2.png) 

### 3. Search
When searching for a patient, the interface displays real proof of the Middleware's operation: the SSN (CPF) saved in the database is an illegible Ciphertext. However, thanks to the Blind Index mechanism, the partial search by name works perfectly, filtering the data directly in the proxy's memory.

![Search Result](../docs/assets/3.png) 

### 4. E-commerce Mode
The application also demonstrates the use of the Middleware's "Shared Mode" aimed at E-commerces, protecting credit cards with high-performance symmetric keys and lower storage overhead.

![E-commerce](../docs/assets/4.png)
