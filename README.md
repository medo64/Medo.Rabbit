Medo.Rabbit
===========

C# implementation of [Rabbit][rabbit] stream cipher.

Rabbit is a stream cipher designed by Martin Boesgaard, Mette Vesterager,
Thomas Pedersen, Jesper Christiansen, and Ove Scavenius. It was submitted to the
eSTREAM project of the eCRYPT network.

It is a 128-bit cipher, meaning it has a 128-bit key and generates a 128-bit
keystream. The keystream is then XORed with the plaintext to produce the
ciphertext.

Rabbit is designed to be fast on processors with small cache sizes, such as
those found in embedded systems. It is also designed to be resistant to
side-channel attacks, such as power analysis and timing attacks. Rabbit is a
lightweight and efficient stream cipher, suitable for use in embedded systems.



[rabbit]: https://www.ecrypt.eu.org/stream/e2-rabbit.html
