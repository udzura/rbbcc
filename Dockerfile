FROM rubylang/ruby:2.6.3-bionic

RUN set -ex; \
    echo "deb [trusted=yes] http://repo.iovisor.org/apt/bionic bionic-nightly main" > /etc/apt/sources.list.d/iovisor.list; \
    apt-get update -y; \
    deps="auditd bcc-tools curl gcc git libelf1 libbcc-examples"; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y $deps; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*;

RUN gem install rbbcc
COPY ./misc/rbbcc-dfm-ruby /usr/bin/rbbcc-dfm-ruby
RUN chmod a+x /usr/bin/rbbcc-dfm-ruby

ENTRYPOINT ["ruby"]
