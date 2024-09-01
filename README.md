# 5G AKMA-PLUS

## build Dependencies

* OS: Ubuntu 20.04 LTS.
* make,gcc,g++

## how to build
* make
```sh
cd UE/Debug
make
cd ../../SEAF/Debug
make
```

## how to run
* run SEAF
```sh
cd SEAF/Debug
./SEAF
```
You can see "waiting on port 50001" in the terminal, please don't close the terminal.  
Open a new terminal
* run AF
```sh
cd SEAF/Debug
./AF
```
You can see "waiting on port 50002" in the terminal, please don't close the terminal.  
Open a new terminal
* run UE
```sh
cd UE/Debug
./UE
```