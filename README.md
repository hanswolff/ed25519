[Ed25519](http://ed25519.cr.yp.to/) is an 
[Elliptic Curve Digital Signature Algortithm](http://en.wikipedia.org/wiki/Elliptic_Curve_DSA) based on
[Curve25519](http://cr.yp.to/ecdh.html)
developed by [Dan Bernstein](http://cr.yp.to/djb.html),
[Niels Duif](http://www.nielsduif.nl/), 
[Tanja Lange](http://hyperelliptic.org/tanja), 
[Peter Schwabe](http://www.cryptojedi.org/users/peter/), 
and [Bo-Yin Yang](http://www.iis.sinica.edu.tw/pages/byyang/).

This project is a C# port of the Java version that was a port of the Python implementation.
Beware that this is a simple but **very slow** implementation and should be used for testing only.

If you need a faster implementation of Ed25519, have a look at:  
https://github.com/CodesInChaos/Chaos.NaCl

#### Usage Example

	byte[] signingKey = new byte[32];
	RNGCryptoServiceProvider.Create().GetBytes(signingKey);

	byte[] publicKey = Ed25519.PublicKey(signingKey);

	byte[] message = Encoding.UTF8.GetBytes("This is a secret message");
	byte[] signature = Ed25519.Signature(message, signingKey, publicKey);
	
	bool signatureValid = Ed25519.CheckValid(signature, message, publicKey);
