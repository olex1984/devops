FROM ubuntu:xenial

RUN mkdir /Distr
COPY Distr /Distr/
RUN apt-get update -y
RUN apt-get install nano net-tools htop mc libicu55 curl ca-certificates gnupg libllvm6.0 libssl1.0.0 libxslt1.1 imagemagick unixodbc libgsf-1-114 -y

############## command for every comtainers ################ 

####################################
############## POSTGRESQL ##########
####################################
RUN curl https://www.postgresql.org/media/keys/ACCC4CF8.asc |apt-key add -
RUN echo 'deb http://apt.postgresql.org/pub/repos/apt/ bionic-pgdg main' > /etc/apt/sources.list.d/pgdg.list
RUN apt update -y
RUN apt install -y postgresql-common

WORKDIR /Distr/Postgresql/postgresql_11.7_7.1C_amd64_deb
RUN dpkg -i libpq5_11.7-7.1C_amd64.deb
RUN apt install -fy
RUN dpkg -i postgresql-client-11_11.7-7.1C_amd64.deb
RUN apt install -fy
RUN dpkg -i ppostgresql-11_11.7-7.1C_amd64.deb
RUN apt install -fy

# COPY /etc/postgresql/11/main/pg_hba.conf with local all postgres peer
#systemctl restart postgresql
#psql -U postgres -d template1 -c "ALTER USER postgres PASSWORD '123456'"
# COPY /etc/postgresql/11/main/pg_hba.conf with local all postgres md5
#systemctl restart postgresql
#######################################################
################ 1C ENTERPRISE ########################
#######################################################
#ttf-mscorefonts-installer
WORKDIR /Distr/1c/deb64_8_3_17_1549
RUN dpkg -i 1c-enterprise83-common*deb
RUN dpkg -i 1c-enterprise83-server*deb
RUN dpkg -i 1c-enterprise83-ws*deb
RUN chown -R usr1cv8:grp1cv8 /opt/1C
#systemctl start srv1cv83
################# APACHE #############################
RUN apt install -y apache2

RUN apt-get autoremove -y

EXPOSE 1541
EXPOSE 5432
EXPOSE 80
EXPOSE 443
