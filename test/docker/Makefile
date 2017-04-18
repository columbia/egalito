include ../../env.mk

docker_build:
	docker run --rm --privileged multiarch/qemu-user-static:register --reset
	docker create --name register hypriot/qemu-register
	docker cp register:qemu-$ARCH $DOCKER_DIR/qemu-$ARCH-static
	docker build -t egalito/$(P_ARCH) -f Dockerfile_$(P_ARCH) .

docker_check:
	docker images | grep egalito/$(P_ARCH) | awk '{print $1}' > $@

ifneq ($(CROSS),)
	QEMU_STATIC = qemu-$(P_ARCH)-static
	QEMU_STATIC_PATH = $(shell which $(QEMU_STATIC))
	DOCKER_QEMU = -v $(shell which $(QEMU_STATIC)):/usr/bin/$(QEMU_STATIC)
endif

run: docker_check
	@if grep -q "egalito/$(P_ARCH)" $<; then \
		docker run -it -e LOCAL_USER_ID=$(id -u $(whoami)) -v $(shell readlink -f ../../):/egalito egalito/$(P_ARCH) $(DOCKER_QEMU); \
	else \
		echo "Error egalito/$(P_ARCH) docker image not built!"; \
	fi;

.PHONY: clean
clean:
	rm -f docker_check
