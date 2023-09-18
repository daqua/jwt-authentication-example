# Example 1: JWT

* Customer creates EC Key Pair and shares Public Key with ecolytiq.
* Customer defines value for issuer attribute
* Customer is sender and issues a token
* ecolytiq is receiver and validates the token
* token is not encrypted. content of token is readable.

## Code Example
src/test/kotlin/JWTExampleTest.kt

## Create Key EC Pairs with openssl
### Create EC Private Key
```
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
```

### Create EC Public Key from EC Private Key
```
openssl ec -in private-key.pem -pubout -out public-key.pem
```


# Example 2: JWE

* Customer creates RSA Key Pair and shares Public Key with ecolytiq.
* ecolytiq creates RSA Key Pair and shares Public Key with customer.
* Customer defines value for issuer attribute
* Customer is sender and issues a token
* ecolytiq is receiver and validates the token
* token is encrypted. content of token is only readable by ecolytiq after decryption

## Code Example
src/test/kotlin/JWEExampleTest.kt

## Create Key RSA Pairs with openssl

### Create RSA Private Key (key length = 2048)
```
openssl genrsa -out private-key.pem 2048
```

# Create RSA Public Key from RSA private Key
```
openssl rsa -in private-key.pem -outform PEM -pubout -out public-key.pem
```