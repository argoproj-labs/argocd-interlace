## Provenance data for ArgoCD sync

ArgoCD Interlace generates provenance data for each Application sync by ArgoCD.

The provenance data here means build process information of the YAML manifest, such as what was the source materials for producing the synced resources, how those materials were converted into the YAML manifest, what was the actual YAML manifest and so on.

The actual provenance data is something like the below.


`materials` is the list of source material repositories with commit ID.

`invocation` is the build command and its parameters when the YAML manifest was generated.

`subject` field in the provenance contains the digest value of the generated manifest.


```
{
    "_type": "https://in-toto.io/Statement/v0.1",
    "predicateType": "https://slsa.dev/provenance/v0.1",
    "subject": [
        {
            "name": "/tmp/workspace2689764547/sample-app/manifest.yaml",
            "digest": {
                "sha256": "72d33174b97b178a035a16f04518ff971b1edb3d1b603c858f11e0f12befb8ca"
            }
        }
    ],
...
    "predicate": {
        "invocation": {
            "configSource": {
                "entryPoint": "kustomize"
            },
            "parameters": [
                "build",
                "/tmp/kustomize-505837180"
            ]
        },
        ...
        "materials": [
            {
                "uri": "https://github.com/hirokuni-kitahara/sample-kustomize-app.git",
                "digest": {
                "commit": "0ff5408670b90b4a7ca69ca3829aa37e1acb39db",
                "path": "./",
                "revision": "master"
                }
            }
        ]
    }
}
```