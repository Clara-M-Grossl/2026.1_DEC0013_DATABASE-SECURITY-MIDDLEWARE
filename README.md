# Database Security Middleware

> Sistema de Interceptação TCP e Criptografia em Rede para Bancos de Dados

O Database Security Middleware é um proxy TCP e gateway de criptografia em nível de rede para bancos de dados PostgreSQL. O sistema implementa um modelo de segurança Zero-Trust, realizando criptografia e descriptografia durante a transmissão de dados em tempo real, no protocolo do banco de dados, mantendo-se totalmente transparente para a aplicação cliente.

**Índice**

- [Arquitetura](#arquitetura)
- [Funcionalidades Principais](#funcionalidades-principais)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Modelo de Segurança](#modelo-de-segurança)
- [Estrutura de Diretórios
  ](#estrutura-de-diretórios)

---



## Arquitetura

O sistema opera como uma camada de rede intermediária entre o back-end da aplicação e o banco de dados PostgreSQL. Ele interceota o protocolo ce conexão do PostgreSQL, realiza a análise sintática de comandos SQL para uma AST e reescreve as queries em tempo real antes de repassá-las ao banco de dados.


## Funcionalidades Principais

**Envelope Encryption:** Implementa criptografia de envelope híbrida. Cada dado é cifrado com uma Data Encryption Key, DEK, única. As DEK's são encapsuladas por uma Key Encryption Key, KEK, gerenciada através do HashiCorp Vault

**Suporte de Buscas:** Suporte de buscas sobre dados criptografados, via Blind Indexing, e correspondência parcial de strings.

**Transparência para a Aplicação:** Não requer modificações na logica da aplicação


## Pré-requisitos

* Go 1.21 ou superior;
* Node.js 20 ou superior - testes;
* Docker e Docker Compose.

## Instalação



1. Clone o repositório:

   ```bash
   git clone <url_do_repositorio>
   cd databaseSecurityMiddleware
   ```
2. Inicialize a infraestrutura de suporte (Banco de Dados e Vault):

   ```bash
   docker-compose up -d database vault
   ```
3. Compile o middleware:

   ```bash
   cd middleware
   make
   ```



## Como usar

```Shell
./main.exe
```

O middleware iniciará a escuta de conexões PostgreSQL no endereço. Configure o back-end da sua aplicação para se conectar a porta do middleware em vez da porta padão do banco de dados.

## Estrutura de Diretórios

```
```text
.
├── middleware/           # Proxy Go, parser SQL e motor criptográfico
├── testes/               # Ambiente de integração
│   ├── backend/          # Aplicação Node.js de referência (API)
│   ├── frontend/         # Frontend de referência para testes end-to-end
│   └── database/         # Scripts DDL e provisionamento de dados
├── docs/                 # Especificações arquiteturais
└── docker-compose.yml    # Orquestração do ambiente de desenvolvimento
```
