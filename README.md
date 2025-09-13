Name: Sharon Grace Kirubakaran
Email: s.kirubakaran1@wsu.edu

Files:
    main.c - Contains all the encryption and decryption code

Compile instruction:
    Option 1: make 
    Option 2: gcc -o main main.c

Run instructions: 
    Must be run in the format given
    All files, including the output file, must be created with the right permissions
        Read permission for the key and input files. 
        Write permission for the output file. 

    To encrypt: ./wsu-crypt -e - k {key.txt} -in {plaintext.txt} -out{ciphertext.txt}
    To decrypt: ./wsu-crypt -d - k {key.txt} -in {plaintext.txt} -out{ciphertext.txt}

    ./main -e -k key.txt -in input.txt -out output.txt