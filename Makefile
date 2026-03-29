ci-base-all:
	@docker buildx build --platform linux/arm64 -t ghcr.io/udzura/rbbcc-ci-images:libbcc-0.29.0-ruby-4.0.2 --file Dockerfile.ci --load .
	@docker buildx build --platform linux/amd64 --build-arg RUBY_VERSION=3.4.9 -t ghcr.io/udzura/rbbcc-ci-images:libbcc-0.29.0-ruby-3.4.9 --file Dockerfile.ci --load .
	@docker buildx build --platform linux/arm64 --build-arg BCC_VERSION=0.31.0 -t ghcr.io/udzura/rbbcc-ci-images:libbcc-0.31.0-ruby-4.0.2 --file Dockerfile.ci --load .
	@docker buildx build --platform linux/arm64 --build-arg BCC_VERSION=0.31.0 --build-arg RUBY_VERSION=3.4.9 -t ghcr.io/udzura/rbbcc-ci-images:libbcc-0.31.0-ruby-3.4.9 --file Dockerfile.ci --load .
	@docker buildx build --platform linux/arm64 --build-arg BCC_VERSION=0.35.0 -t ghcr.io/udzura/rbbcc-ci-images:libbcc-0.35.0-ruby-4.0.2 --file Dockerfile.ci --load .
	@docker buildx build --platform linux/arm64 --build-arg BCC_VERSION=0.35.0 --build-arg RUBY_VERSION=3.4.9 -t ghcr.io/udzura/rbbcc-ci-images:libbcc-0.35.0-ruby-3.4.9 --file Dockerfile.ci --load .
