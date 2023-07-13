
[](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf)
During a pair-wise key-agreement scheme, the secret keying material to be established is not sent
directly from one entity to another. Instead, the two parties exchange information from which
they each compute a shared secret that is used (along with other exchanged/known data) to
derive the secret keying material. The method used to combine the information made available to
both parties provides assurance that neither party can control the output of the key-agreement
process.

ISO:
encryption key is derived from the verification application key provided by the jwks
or jwks_uri and the mdoc App ephemeral private key.

ISO B.3.2.2:
In the JWE header, the epk shall contain the nonce from mdoc App which shall be concatenated to
client_id to compute the schemehandoverbytes

The owner of a private/public key pair is the entity that is authorized to use the private key of
that key pair. The precise steps required may depend upon the key establishment scheme and the
type of key pair (static or ephemeral).



[](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk/examples/oauth/jarm)

