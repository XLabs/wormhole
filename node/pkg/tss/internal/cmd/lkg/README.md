Please read the entire document before running the protocol.


# Running 'local' DKG

The following binary runs the DKG protocol to
generate secrets for guardians to use by the threshold signing scheme (TSS).

The script expects a config file (similar to the cnfg.json) provided
in this package.
The config file contains a few key fields: 
```
"NumParticipants": int,
"WantedThreshold": int,
"GuardianSpecifics" : array
```




Where `NumParticipants` is the number of guardians in the system,
`WantedThreshold` is the wanted threshold (For instance, `NumParticipants=19` and `WantedThreshold=13`).

The following is an example of the `GuardianSpecifics` array (for a working example, please see `cnfg.json`):


```
   "GuardianSpecifics": [
        {
            "Identifier": {
                "TlsX509":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JS
                UgvVENDQmVXZ0F3SUJBZ0lRYUJZRTMvTTA4WEhZQ25OVm1jRkJja
                kFOQmdrcWhraUc5dzBCQVFzRkFEQnkKTVFzd0NRWURWUVFHRXdKV
                .
                .
                .
                FlscWNPbWVYMXVGbUtiZGkvWG9yR2xrQ29NRjNURHg4cm1wOURCa
                UIvCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
                
            },
            "WhereToSaveSecrets": "/Path/To/File/NameWithoutPrefix"
        },
        {
            "Identifier": {...},
            "WhereToSaveSecrets": "..."
        },
        {...},
        .
        .
        .
   ]
```

The DKG protocol is used to generate secrets to TSS, 
and it assumes a public key infrastructure. 
These public keys are x509 certificates (and stored inside `GuardianSpecifics[i].Identifier.TlsX509`), 
and are used later by the TSS to establish TLS channels between the participants.
As a result, the x509 certificate provided by you should be self-signed root-level certificates. 
In addition, you should safely store the signing key you've used to sign your certificate in a known location ([see after running the protocol](#after-running-the-local-dkg-protocol))


When creating the X509 certificates, be aware that the DNS name you set 
in the certificate will be used as the hostname of
servers participating in the TSS protocol.
As a result, please refrain from using hostnames that are
unreachable.


# After running the local DKG protocol.

Once you run the protocol, expect numerous files containing secret keys and 
additional configurations. 
Each guardian operator should take the file saved by the given name they 
provided in the config.

The file each operator holds should be kept like other files containing secret keys. 
This file contains the result og the DKG, before this file is usable, one should provide the signing key used to sign the x509 certificate used by the DKG protocol.






