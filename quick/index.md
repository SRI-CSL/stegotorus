---
layout: archive
title: "Quick Start to using StegoTorus"
image:
  feature: home-feature.png
---



Assuming that you are in the top-level source directory.  Then, open two command line windows.

In the first one, start StegoTorus client:

```
$> ./stegotorus --config-file=modus_operandi/client-vm06-config.conf
```

In the second one, bootstrap Tor:

```
$> tor -f data/stegotorrc
```

