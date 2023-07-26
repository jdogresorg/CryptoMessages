        Title: Crypto Address Messaging System (CryptoMessages)
        Author: Jeremy Johnson (J-Dog) & Javier Varona
        Created: 2023-07-26

# Abstract
Establish an address messaging system via Broadcasts

# Motivation
Allow users to pass messages between addresses

# Rationale
While Bitcoin provides some level of anonymity in financial transactions, there are times when communication between addresses could improve the overall experience of using Bitcoin.

This proposal establishes a new crypto address messaging system which allow will passing of plaintext and secure messages between addresses on Bitcoin via the Counterparty `broadcast` system.

This spec can be extended in the future to allow for additional options and formats.

# Definitions

- `broadcast` - A general purpose transaction type which allows broadcasting of a message to the Counterparty platform
- `INIT` - A specially formatted `broadcast` which establishes a shared key to use for decrypting messages
- `MESSAGE` - A specially formatted `broadcast` which passes a message to a `DESTINATION` address 

# Specification
This spec defines 2 formats `INIT` and `MESSAGE` which allows for both plaintext and encrypted messaging.

## Project Prefix
The default `broadcast` project prefix which should be used for CryptoMessage transactions is `CM`. All CryptoMessages actions will begin with `cm:` (case insensitive)

## `ACTION` commands
Below is a list of the defined `ACTION` commands and the function of each:

| ACTION                   | Description                                                                | 
| -------------------------| -------------------------------------------------------------------------- |
| [`INIT`](./INIT.md)      | Establishes a shared key to be used to exchange messages between addresses |
| [`MESSAGE`](./MESSAGE.md)| Sends a message to the `DESTINATION` address.                              |

# Copyright
This document is placed in the public domain.