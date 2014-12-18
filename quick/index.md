---
layout: archive
title: "Quick Start to using StegoTorus"
image:
  feature: home-feature.png
---



Assuming that you are in the top-level source directory.

Then, open two command line windows.

In the first one, start StegoTorus client:

```
$> ./stegotorus --config-file=modus_operandi/client-vm06-config.conf
```

In the second one, bootstrap Tor:

```
$> tor -f data/stegotorrc
```

Once the bootstrapping has reached 100% (this may take a moment), you can test the connection using a third command line window:

```
$> curl --socks4a 127.0.0.1:9060 https://check.torproject.org | grep Congrat
```

