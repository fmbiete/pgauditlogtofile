FROM almalinux:9

# podman run -ti --name pgauditlogtofile17 -v `pwd`:/usr/local/src/pgauditlogtofile:Z docker.io/library/almalinux:9 bash

ENV PG_VERSION 17
ENV PATH $PATH:/usr/pgsql-${PG_VERSION}/bin

RUN dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm \
  && dnf install -y --enablerepo=crb --enablerepo=pgdg${PG_VERSION} \
    postgresql${PG_VERSION}-server postgresql${PG_VERSION}-devel make openssl-devel llvm-toolset redhat-rpm-config krb5-devel \
  && dnf clean all -y

  # Compile & install pgaudit
RUN dnf install -y --enablerepo=crb --enablerepo=pgdg${PG_VERSION} pgaudit_${PG_VERSION}

# Compile & install pgauditlogtofile
RUN make -C /pgauditlogtofile install USE_PGXS=1

USER postgres

# Create PostgreSQL cluster
RUN /usr/pgsql-${PG_VERSION}/bin/initdb -A trust -k /var/lib/pgsql/${PG_VERSION}/data \
  && echo "shared_preload_libraries = 'pgaudit,pgauditlogtofile'" >> /var/lib/pgsql/${PG_VERSION}/data/postgresql.conf \
  && /usr/pgsql-${PG_VERSION}/bin/pg_ctl start -D /var/lib/pgsql/${PG_VERSION}/data \
  
# Enable pgaudit
RUN psql -Xc 'create extension pgaudit' \
  && psql -Xc 'alter system set pgaudit.log = "all"' \
  && psql -Xc 'alter system set pgaudit.log_parameter = on' \
  && psql -Xc 'select pg_reload_conf()'

# Enable pgauditlogtofile
RUN psql -Xc 'create extension pgauditlogtofile' \
  && psql -Xc 'alter system set log_connections = on' \
  && psql -Xc 'alter system set log_disconnections = on' \
  && psql -Xc 'alter system set pgaudit.log_connections = on' \
  && psql -Xc 'alter system set pgaudit.log_disconnections = on' \
  && psql -Xc 'select pg_reload_conf()'

RUN psql -Xc "alter system set pgaudit.log_format = 'json'"
  && psql -Xc 'select pg_reload_conf()'

RUN psql -Xc 'create database pgbench' \
  && pgbench i pgbench \
  && pgbench -c 100 -j 10 -T 60 pgbench

USER root