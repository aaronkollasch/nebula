

build-docker-static tag:
	# tag example: docker-repo/nebula:1.6
	sudo DOCKER_BUILDKIT=1 docker build -t {{tag}} --target nebula-static .	

build-docker-alpine tag:
	# tag example: docker-repo/nebula:1.6-alpine
	sudo DOCKER_BUILDKIT=1 docker build -t {{tag}} --target nebula-alpine .

run-docker tag:
	# tag example: docker-repo/nebula:1.6
	sudo docker run -it --rm --cap-add net_admin --volume /etc/nebula:/etc/nebula:ro --device /dev/net/tun:/dev/net/tun --net host {{tag}} -config /etc/nebula/config.yaml

