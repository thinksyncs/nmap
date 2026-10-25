# NetBuster multiversion review materials

This proposal adds explicit NetBuster 1.30 identification and the default Info
fingerprint observed in 1.12, without assigning a version to that Info reply.
It preserves the 1.31 version rule from [#3570](https://github.com/nmap/nmap/pull/3570).
The [incremental patch](after-pr3570.patch) shows the additions to that PR.

Download [the reproduction archive](netbus-multiversion-review.tar.gz) and verify
its checksum in [SHA256SUMS](SHA256SUMS). With Python 3.9+, Git and Lua 5.3+:

```sh
tar -xzf netbus-multiversion-review.tar.gz
cd netbus-multiversion-review
python3 run_review.py --output ../review-offline
```

This opens no sockets. It runs 169 contracts, checks both patches and rechecks
the retained raw data from 136 synthetic scans and 168 application scans.
With Nmap and its standard data installed, add fresh localhost reproduction:

```sh
python3 run_review.py --output ../review-network --replay --compare
```

The added 20 replay cases and 28 comparison scans passed from the extracted
archive with access to the original workspace denied. See the
[reproduction result](fresh-reproduction.json) and [validation record](VALIDATION.json).
No application executables or VM disks are included.

The [application measurements](formal-summary.json) compare the previous local
multiversion candidate `72aee081` with `1dab4ae5`, not #3570. Under Wine/QEMU,
later GetInfo/GetApps coalescing changed from misses at 5.17 seconds to detection
at 1.53/1.55 seconds for 1.30/1.31. Other medians increased by up to 0.03 seconds.
The candidate retained 78 positive identifications and six negative controls,
including 18 versionless 1.12 results; these counts include warmups. Five
measured runs per variant and condition exclude one warmup.

[Sample provenance](sample-provenance.json), settings, captures and raw logs are
included. The archive contains the fixed pre-submission snapshot, so its README,
draft and validation metadata describe it as unsubmitted at that time. Recorded
paths remain as provenance; verification resolves them inside the attachment.
Native Windows and real-world detection rates have not been evaluated.
