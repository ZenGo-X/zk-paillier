Zero Knowledge Paillier
-------------------
This library contains a collection of Paillier cryptosystem zero knowledge proofs written in Rust. 
Each proof can be used as a stand alone proof but usually it will be used as part of another protocol. 
For each proof we state in comments what are the security assumptions required. Pay special attention to proofs that require more assumptions than just DCRA which is the assumption used in Paillier cryptosystem.

Currently implemented proofs
-------------------

* [Proof that a ciphertext encrypts zero](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/zero_enc_proof.rs)
* [Proof of knowledge of plaintext (correctness of ciphertext)](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/correct_ciphertext.rs#L109)
* [Proof of correct paillier keypair generation](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/correct_key.rs)
* [Non-interactive proof of correct paillier keypair generation](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/correct_key_ni.rs)
* [Range proof that a paillier ciphertext lies in interval [0,q]](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/range_proof.rs)
* [Non-interactive range proof that a paillier ciphertext lies in interval [0,q]](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/range_proof_ni.rs)
* [Proof of correct opening of a ciphertext](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/correct_opening.rs)
* [Proof that a ciphertext encrypts a message from a given message space](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/correct_message.rs)
* [Witness Indistinguishable Proof of knowledge of discrete log with composite modulus](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/wi_dlog_proof.rs)
* [NI Proof of plaintext multiplication: ciphertexts `e_a = Enc(a), e_b = Enc(b), e_c = Enc(c)` such that `ab = c mod n`](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/multiplication_proof.rs)
* [NI proof of linear relation between several plaintexts of several known ciphertexts](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/verlin_proof.rs)

Usage
-------------------
There is no unified API at the moment, please follow the test attached to each proof for example usage. 

Legacy 
-------------------
[Rust-paillier](https://github.com/mortendahl/rust-paillier) was orignally a library that implemented the basic Paillier cryptosystem with main contributors from [Snips](https://github.com/snipsco). Catalyzed by KZen needs for paillier zero knowledge proofs the original library was forked and another layer of proofs was added. As more and more zk-proofs were being added we realized that the base paillier cryptosystem layer is at a point of stability and only minor changes are required once in a while where on the other hand the second layer of zk-proofs are evolving at a much faster pace and the code should be considered more experimental. At this point we agreed to divide the library to the base layer (rust-paillier) and zk-paillier which is the current library. 

Finally. we would like to thank [Morten Dahl](https://github.com/mortendahl),lead maintainer of rust-paillier and KZen advisor. another thank you goes to [Pascal Paillier](https://github.com/Pascal-Paillier).

Development Process
-------------------
 **the [Rust utilities wiki](https://github.com/KZen-networks/rust-utils/wiki) contains information on workflow and environment set-up**. 
Feel free to [reach out](mailto:github@kzencorp.com) or join the KZen Research [Telegram]( https://t.me/kzen_research) for discussions on code and research.

License
-------
zk-paillier is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.

## Contact

Feel free to [reach out](mailto:github@kzencorp.com) or join ZenGo X [Telegram](https://t.me/zengo_x) for discussions on code and research.
