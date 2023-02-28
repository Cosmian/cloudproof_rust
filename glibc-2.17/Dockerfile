FROM centos:centos7.4.1708

RUN yum -y groupinstall "Development Tools" && yum -y clean all

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN cp ~/.cargo/bin/cargo /usr/bin/cargo

LABEL version="1.0"
LABEL name="Cosmian Cargo glibc 2.17"
