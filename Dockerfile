docker-version	0.6.1
FROM	debian
MAINTAINER	Christine Spang <christine@spang.cc> (@spang)

# Packaged dependencies
RUN	apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq \
	python \
	p7zip \
	tmux \
	--no-install-recommends

ENTRYPOINT	['/bin/bash']
