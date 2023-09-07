# INIT command
This command establishes a shared key to be used to exchange messages between addresses

## PARAMS
| Name          | Type   | Description                               |
| --------- | ------ | ----------------------------------------- |
| `VERSION` | String | Broadcast Format Version                  |
| `TYPE`    | String | Encryption Type (0=AES, 1=B64)            |
| `ADDRESS` | String | Address of the message recipient          |
| `KEY`     | String | Shared key to be used to exchange messages|

## Formats

### Version `0`
- `VERSION|TYPE|ADDRESS|KEY`

### Version `1`
- `VERSION|TYPE|ADDRESS`

## Examples
```
cm:INIT|0|0|1JDogZS6tQcSxwfxhv6XKKjcyicYA4Feev|SHARED_KEY_GOES_HERE
This example establishes a shared key to securely exchange messages with address 1JDogZS6tQcSxwfxhv6XKKjcyicYA4Feev
```

```
cm:INIT|1|0|1Donatet2LrNpuWByAnH8gc9Wh9zSzZuLC
This example responds to the above request to securely exchange messages with address 1JDogZS6tQcSxwfxhv6XKKjcyicYA4Feev
```

## Rules

## Notes
- `INIT` command may only be used if `ADDRESS` public key is known
- `KEY` is a shared key which should only be decrypted/known by sender and receiver
- Format `0` is to be used when first initializing a request
- Format `1` is to be used when responding to an INIT request 