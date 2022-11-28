# FEAL 4 differential analysis

## Description

- `FEAL4-solver.cpp`: main file, where you provide plaintext and ciphertexts with corresponding differentials for each step.
- `keys_testing.cpp`: file for checking all possible key combinations
- `run_binary.py`: file for automated key checking for all plaintext-ciphertext pairs you provided

## Usage

Keep all files in one folder.

Create file `output.txt`.

- `FEAL4-solver.cpp`
  - Put plaintext and ciphertexts with differentials into corresponding arrays
  - Edit variable **MAX_CHOSEN_PAIRS** and put there amount of pairs you have
  - Compile code:
    -  `g++ FEAL4-solver.cpp -o FEAL4-solver`
  -  Run the code:
    -  `./FEAL4-solver`
  -  Full execution will take about 3 hours (Macbook Air M1)
  -  All steps and found keys will be displayed in terminal with coloured output
  -  `NOTE`: When you get all K0, K4, K5 - delete duplicates. It will reduce amount of keys from 300+ to about 100 for K0, K4, K5.


- `keys_testing.cpp`
  - Put all found keys into corresponding array
  - Compile file:
    - `g++ keys_testing.cpp -o keys_testing`
  - Edit and run **run_binary.py**
  - You can run this file manually with this command:
```sh
./keys_testing d4 43 3c e1 79 61 48 2f 7a 9a a3 55 4e b7 ff ee
               |------Plaintext------| |------Ciphertext-----|
```

- `run_binary.py`
  - **bin_name** - name of *keys_testing.cpp* binary
  - **plaintext** - list of plaintexts to be encrypted and checked
  - **ciphertext** - list of corresponding ciphertexts for checking encrypted plaintexts
  - Output of the program will be put into `output.txt` file.