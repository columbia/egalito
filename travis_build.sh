#!/bin/bash
set -e

DOCKER_DIR=./test/docker

if [ "$ARCH" != "x86_64" ]; then

		echo "Building for $ARCH in docker using qemu"
		docker run --rm --privileged multiarch/qemu-user-static:register --reset
		docker create --name register hypriot/qemu-register
		docker cp register:qemu-$ARCH $DOCKER_DIR/qemu-$ARCH-static
		docker build -t egalito/$ARCH -f $DOCKER_DIR/Dockerfile_$ARCH $DOCKER_DIR
		docker run -it --rm -e LOCAL_USER_ID=$(id -u $(whoami)) -v $(readlink -f ./):/egalito -v $(readlink -f $DOCKER_DIR/qemu-$ARCH-static):/usr/bin/qemu-$ARCH-static egalito/$ARCH /bin/bash -c "cd /egalito && make && cd test && ./runner"

else
		if [ ! -z "$CROSS" ]; then
				echo "Cross Compiling for $CROSS on $ARCH inside docker"
				CROSS_COMMAND="cd /egalito && USE_CONFIG=travis_${CROSS}_config.mk make src"
				echo $CROSS_COMMAND
				docker build -t egalito/$ARCH-$CROSS -f $DOCKER_DIR/Dockerfile_${ARCH}-${CROSS} $DOCKER_DIR
				docker run -it --rm -e LOCAL_USER_ID=$(id -u $(whoami)) -v $(readlink -f ./):/egalito egalito/$ARCH-$CROSS /bin/bash -c "$CROSS_COMMAND"
				echo "Running Tests in $CROSS docker using qemu"
				docker run --rm --privileged multiarch/qemu-user-static:register --reset
				docker create --name register hypriot/qemu-register
				docker cp register:qemu-$CROSS $DOCKER_DIR/qemu-$CROSS-static
				docker build -t egalito/$CROSS -f $DOCKER_DIR/Dockerfile_$CROSS $DOCKER_DIR
				docker run -it --rm -e LOCAL_USER_ID=$(id -u $(whoami)) -v $(readlink -f ./):/egalito egalito/$CROSS /bin/bash -c "cd /egalito && make test && cd test && ./runner"
		else
				echo "Building & Testing for $ARCH on $ARCH"
				docker build -t egalito/$ARCH -f $DOCKER_DIR/Dockerfile_$ARCH $DOCKER_DIR
				docker run -it --rm -e LOCAL_USER_ID=$(id -u $(whoami)) -v $(readlink -f ./):/egalito egalito/$ARCH /bin/bash -c "cd /egalito && make && cd test && ./runner"
		fi
fi
