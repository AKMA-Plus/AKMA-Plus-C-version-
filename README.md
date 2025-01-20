# 5G AKMA-PLUS

## Build dependencies

* OS: Ubuntu 20.04 LTS.
* make,gcc,g++,openssl,libssl-dev

## How to build
* Use the following command(s) to install the required tools to build
```sh
sudo apt update
sudo apt install -y git make gcc openssl libssl-dev
```
* make
```sh
cd UE/Debug
make
cd ../../HN/Debug
make
cd ../../AF/Debug
make
cd ../..
```

## How to run
* run HN
Open a new terminal, named as terminal 1
```sh
cd HN/Debug
./HN
```
You can see "waiting on port 50001" in the terminal, please don't close the terminal. 
* run AF
Open a new terminal, named as terminal 2
```sh
cd AF/Debug
./AF
```
You can see "waiting on port 50002" in the terminal, please don't close the terminal.  
* run UE
Open a new terminal, named as terminal 3
```sh
cd UE/Debug
./UE
```

In termial 3, it outputs the hex values of K_AF_prime, for example:
```sh
K_AF_prime (len:128) is:
0000 - dc 50 df 5f 93 cc d1 7a-af 16 11 d0 7d d0 56 97   .P._...z....}.V.
0010 - fd 4e 96 2a a3 bc ba dc-a9 ac 61 d8 54 03 a9 e8   .N.*......a.T...
0020 - 63 76 66 9b 74 0f 1d 48-23 4a 4c 1c 3d 9a 88 a7   cvf.t..H#JL.=...
0030 - 4c 58 7d b9 64 80 a9 f3-ed 3f 77 7e 81 5e 4f 66   LX}.d....?w~.^Of
0040 - 00 96 43 cb 30 20 3f ef-55 b1 da 24 7b 1a 5e ff   ..C.0 ?.U..${.^.
0050 - 10 6c 67 81 96 0d 94 97-87 21 b5 cb a2 c2 28 54   .lg......!....(T
0060 - 38 9b 44 17 47 e7 0f 6d-83 06 35 71 e6 6f 3e 5f   8.D.G..m..5q.o>_
0070 - 4f 56 bc b8 01 e5 2e 99-86 c0 6d 9c 4c e7 68 03   OV........m.L.h.
```

In termial 2, it outputs the hex values of K_AF_prime too, for example:
```sh
K_AF_prime (len:128) is:
0000 - dc 50 df 5f 93 cc d1 7a-af 16 11 d0 7d d0 56 97   .P._...z....}.V.
0010 - fd 4e 96 2a a3 bc ba dc-a9 ac 61 d8 54 03 a9 e8   .N.*......a.T...
0020 - 63 76 66 9b 74 0f 1d 48-23 4a 4c 1c 3d 9a 88 a7   cvf.t..H#JL.=...
0030 - 4c 58 7d b9 64 80 a9 f3-ed 3f 77 7e 81 5e 4f 66   LX}.d....?w~.^Of
0040 - 00 96 43 cb 30 20 3f ef-55 b1 da 24 7b 1a 5e ff   ..C.0 ?.U..${.^.
0050 - 10 6c 67 81 96 0d 94 97-87 21 b5 cb a2 c2 28 54   .lg......!....(T
0060 - 38 9b 44 17 47 e7 0f 6d-83 06 35 71 e6 6f 3e 5f   8.D.G..m..5q.o>_
0070 - 4f 56 bc b8 01 e5 2e 99-86 c0 6d 9c 4c e7 68 03   OV........m.L.h.
```

Obvious, they are same. So they can communicate with each other later.