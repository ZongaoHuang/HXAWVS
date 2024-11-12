#!/bin/bash
docker pull secfa/docker-awvs:240111130
docker run -it -d -p 3443:3443 --name awvs2024 --cap-add LINUX_IMMUTABLE  sakura501/hxscan-tool:beta