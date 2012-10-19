# Secure Tokens

Secure Tokens is a set of tools / classes / annotations allowing you to create secure encrypted tokens from any object, which can be later exchanged with 3 ^rd^ party systems or simply stored as license file.

# Example

Below there are some secret information in Example class. We would like to encrypt them and send to some 3 ^rd^ party system along with some kind of request identification - in this case this will be computer serial number obtained from @Hardware@ class.

'''java 
public static class Example implements Token {

	/**
	 * Some kind of secret data.
	 */
	@TokenPart("id")
	protected int id = 4;

	/**
	 * Some other kind of secret data 2.
	 */
	@TokenPart("sec")
	protected String secret = "secret.information.is.here";

	/**
	 * Computer Serial Number
	 */
	@TokenPart("sn")
	protected String sn = Hardware.getSerialNumber();

	// setters/getters
}

public static void main(String[] args) {

	Example example = new Example();
	CipherType cipher = CipherType.AES;
	String password = "secret password";

	String token = Tokenizer.tokenize(example, cipher, password);

	System.out.println("token:  " + token);

	Example checkme = Tokenizer.objectify(Example.class, token, cipher, password);

	System.out.println("id:     " + checkme.id);
	System.out.println("secret: " + checkme.secret);
	System.out.println("sn:     " + checkme.sn);
}
'''

The output will be:

''' 
token:  9bLvGViEM7zAG872nz9W3wHGIFfl0j14lfNoogwCkZn0i7bbOhz3xukYopBKxjAXR75ht/DeF29wxuFMO3kFQQ==
id:     4
secret: secret.information.is.here
sn:     CZC14057LY
'''

Of course there is a possibility to not encrypt data if someone would like to create clear text token. This can be done by using @CipherType.NOOP@ (no-operation) cipher:

'''java 
public static void main(String[] args) {
	Example example = new Example();
	CipherType cipher = CipherType.NOOP;
	String password = "secret password";
	String token = Tokenizer.tokenize(example, cipher, password);
	System.out.println("token:  " + token);
}
'''

This will print:

''' 
token:  id=4#sn=CZC14057LY#sec=secret.information.is.here
'''