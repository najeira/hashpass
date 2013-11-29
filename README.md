hashpass
========

A library to hash password with salt and streching.

A function `Key` returns hashed string that include
name of hash algorithm, iteration count, salt and hashed key.

It will be like this:

    sha256$10000$x9RZ11wpPIfxnT3HSYDg3Q$7vkzTKAtSoWpWMysIY6qBwF1zObW/64DLHsozMqikq8

A function `Check` returns whether password is correct or not.


Usage
-----

```go
import "hashpass"

func test() {
	mypass := hashpass.Key("my password")
	// mypass is like as "sha256$10000$x9RZ11wpPIfxnT3HSYDg3Q$7vkzTKAtSoWpWMysIY6qBwF1zObW/64DLHsozMqikq8"

	ret := hashpass.Check("my password", mypass)
	// ret is true

	ret = hashpass.Check("bad password", mypass)
	// ret is false
}
```


License
-------

* Copyright: 2013 by najeira.
* License: MIT
