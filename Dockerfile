FROM scratch
COPY ghostscan /usr/local/bin/ghostscan
ENTRYPOINT ["ghostscan"]
