# Sudoku-snark 

> Generate setup and proofs 

## About 

This repo uses nix flakes but (probably) works just fine with a normal cargo setup. 

The program has a cli interface which provides help for the various options. 
To run 
```sh
  cargo run -- -h
```

The program reads in and writes out files contained in a the directory `./out/`
```sample
$tree -L 1 out/
out/
├── keys 
├── results
└── sudokus
```

Generate a new set of keys and other setup files
```sh
  cargo run -- init <my-keys>
```
This will output a bunch of files to 
```sample
  ./out/keys/<my-keys>
```
including one called `params.json`.

Sudoku files are assumed to be space separated files. 
Zeros are used to represent blanks in a puzzle. 
For example 
```sample
1 0 
0 1  
```

Create a new puzzle by writing to 
```sample
  ./out/sudokus/<my-game>/puzzle.ssv 
```

Set a puzzle
```sh
  cargo run -- set <my-keys> <my-game>
```
This will output a file 
```sample
  ./out/results/<my-keys>_<my-game>/datum.json
```

Create a solution to a puzzle by writing to 
```sample
  ./out/sudokus/<my-game>/solution.ssv 
```

Prove a solution
```sh
  cargo run -- prove <my-keys> <my-game>
```
This will output a file 
```sample
  ./out/results/<my-keys>_<my-game>/redeemer.json
```

These three `*.json` files are ready to be copied across to `plutus-zk` to be read by the validator.

WARNING: The size of the sudoku is parameterized but has to be known at compile time.
So to change this you need to find `DIM`, edit, and recompile.

## TODO

This repo is incomplete. For example it checks only the row constraint for the sudoku problem.
It is also a far from polished code base.

## Sources 

This repo has borrowed from 

- [zkp-course material](https://github.com/rdi-berkeley/zkp-course-lecture3-code/tree/main/arkworks/src)
- [groth16 arkworks example](https://github.com/achimcc/groth16-example/blob/main/src/lib.rs)

And a sample from IOG to produce their test case. 