# TSN Node RPC API
## Table of Contents
1. [Introduction](#introduction)
2. [Endpoints](#endpoints)
    * [1. `get_blockk`](#1-get_blockk)
    * [2. `get_transaction`](#2-get_transaction)
    * [3. `send_transaction`](#3-send_transaction)
    * [4. `get_account`](#4-get_account)
    * [5. `get_network_info`](#5-get_network_info)
3. [Usage examples](#examples-dusage)
4. [References](#references)

## Introduction
The TSN node RPC API allows users to interact with the TSN network programmatically. This documentation presents the various JSON-RPC methods exposed by the TSN node, along with their parameters, return values, and usage examples.

## Endpoints
### 1. `get_blockk`
* **Description** : Retrieves a specific blockk from the TSN network.
* **Parameters** :
    + `blockk_hash` (string) : The hash of the blockk to retrieve.
    + `blockk_number` (integer) : Le number of the blockk to recover.
* **Return** :
    + `blockk` (object) : The retrieved blockk.
* **Example** :
```bash
curl -X POST \
  http://localhost:8080/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_blockk","params":["0x1234567890abcdef"],"id":1}'

### 2. `get_transaction`
* **Description** : Retrieves a specific transaction from the TSN network.
* **Parameters** :
    + `transaction_hash` (string) : The hash of the transaction to retrieve.
* **Return** :
    + `transaction` (object) : The retrieved transaction.
* **Example** :
curl -X POST \
  http://localhost:8080/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_transaction","params":["0x1234567890abcdef"],"id":1}'

### 3. `send_transaction`
* **Description** : Sends a transaction on the TSN network.
* **Parameters** :
    + `transaction` (object) : The transaction to send.
* **Return** :
    + `transaction_hash` (string) : The hash of the sent transaction.
* **Example** :
curl -X POST \
  http://localhost:8080/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"send_transaction","params":[{"from":"0x1234567890abcdef","to":"0x1234567890abcdef","value":10}],"id":1}'

### 4. `get_account`
* **Description** : Retrieves information about a specific account on the TSN network.
* **Parameters** :
    + `account_address` (string) : The address of the account to retrieve.
* **Return** :
    + `account` (object) : The retrieved account.
* **Example** :
curl -X POST \
  http://localhost:8080/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_account","params":["0x1234567890abcdef"],"id":1}'

### 5. `get_network_info`
* **Description** : Retrieves TSN network information.
* **Parameters** : None
* **Return** :
    + `network_info` (object) : TSN network information.
* **Example** :
curl -X POST \
  http://localhost:8080/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"get_network_info","id":1}'

## Usage examples
The examples above show how to use JSON-RPC methods to interact with the TSN network. They can be used to create custom applications that interact with the TSN network.

## References
* [TSN-001: Communication protocol specification](specs/TSN-001.md)
* [TSN-002: Data format specification](specs/TSN-002.md)