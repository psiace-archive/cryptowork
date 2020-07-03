# Crypto Work

> The value of the code is education, not the code itself.

The goal is to implement some possible useful encryption/decryption algorithms in Python, and currently focus on DES-CBC, because this is part of the job.

**Note:** This is not a complete project, it exists as a homework for *Information Assurance and Security*.

## Status

The framework of the project has been built and currently depends on [pyDes](https://github.com/twhiteman/pyDes), which needs to be replaced with my own implementation.

## TODO

- [x] Replace `pyDes` with my own implementation.
- [ ] Add more encryption/decryption algorithms.
- [ ] Provide a register-based mechanism to facilitate others to expand.

## Usage

Change the contents of the .env file to configure your own information.

``` Python
from cryptowork.app import des_encrypt, des_descrypt

string = "Let's test cryptowork."
encode = des_encrypt(string)
decode = des_descrypt(encode).decode()
assert decode == string
```

## Contact

Chojan Shang - [@PsiACE](https://github.com/psiace) - <psiace@outlook.com>

Project Link: [https://github.com/psiace/cryptowork](https://github.com/psiace/cryptowork)

## License

Licensed under MIT license ([LICENSE](./LICENSE) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
