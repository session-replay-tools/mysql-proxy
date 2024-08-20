## Introduction
Cetus, originally developed from MySQL Proxy, is a high-performance, stable, and protocol-aware proxy for MySQL Group Replication.

## Getting Started

### 1. Prerequisites for Setup
1. cmake
2. gcc
3. glib2-devel （version >= 2.6.0)
4. zlib-devel
5. flex
6. mysql-devel 5.6 or mysql-devel 5.7 or mariadb-devel
7. jemalloc

### 2. Compiling Cetus: A Step-by-Step Guid
1. Go to the `cetus_mgr` directory
2. `mkdir build/`
3. `cd build/`
4. `CFLAGS='-O2 -w' cmake ../ -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXE_LINKER_FLAGS="-ljemalloc" -DCMAKE_INSTALL_PREFIX=/home/user/cetus_mgr_install`

### 3. Installation Guide
`make install`

### 4. How to Run
1. Go to /home/user/cetus_mgr_install/conf
2. cp proxy.conf.example proxy.conf
3. Modify proxy.conf 
4. cp users.json.example users.json
5. Modify users.json
6. cd ..
7. ./bin/cetus --defaults-file=conf/proxy.conf

### 5. How to Modify `proxy.conf`
- Set `proxy-backend-addresses` to the primary address of MySQL Group Replication.
- Set `proxy-read-only-backend-addresses` to the secondary addresses of MySQL Group Replication.
- Set `default-username` to a valid user with privileges for managing both MySQL Group Replication and MySQL.
- Set `log-file` to a valid file path.
- Adjust `worker-processes` to an appropriate number based on the workload.
- Configure `default-pool-size` appropriately.
- Add `group_replication_group_name` with the correct value.
- Add `group-replication-mode=1` for single-primary mode.
- Add `backend-multi-write=true` for multiple-primary mode.
- Add `session-causal-read=true` for session causal reading with `session_track_gtids=OWN_GTID` in MySQL configuration.

### 6. How to Modify `user.conf`
Modify passwords as needed for both your applications and MySQL.

## Note
1. Cetus runs exclusively on Linux.
2. Cetus cannot be compiled with MySQL 8.0 development.
3. Cetus is compatible only with MySQL Group Replication.
4. Cetus supports only `mysql_native_password`.
5. The total number of connections to each MySQL instance is the sum of `default-pool-size` and `worker-processes`.


## Bugs and Feature Requests:
If you encounter any issues with the release, I would encourage you to file a bug report.
Your feedback is really critical to myself and the rest of the team as we want to make cetus better.

