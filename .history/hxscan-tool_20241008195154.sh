#!/bin/bash
docker pull sakura501/hxscan-tool:beta
docker run -it -d -p 3443:3443 --name awvs --cap-add LINUX_IMMUTABLE sakura501/hxscan-tool:beta