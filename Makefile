DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=prometheus-exporter

IMAGE?=harbor.509.digital/security/$(BINARY_NAME)
TAG?=latest


build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .
docker-push:
	docker push $(IMAGE):$(TAG)
