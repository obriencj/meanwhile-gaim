
# Overview of meanwhile-gaim

This project is archived and should not be used.

This is the original source code history for what is today the [Pidgin]
[Sametime] [protocol plugin].

[Pidgin]: https://www.pidgin.im/

[Sametime]: https://en.wikipedia.org/wiki/IBM_Sametime

[protocol plugin]: https://bitbucket.org/pidgin/main/src/default/libpurple/protocols/sametime/

The content for the [Meanwhile] library originated as a part of this
Gaim plugin. It was split out into its own project once it became
clear that it was useful outside of just a Gaim environment.

[Meanwhile]: https://github.com/obriencj/meanwhile


## Build

Assuming you've built Gaim from source:

```bash
	./autogen.sh && make all
	su -c "make install"
```

and eveything should be fine. If Gaim is installed from an RPM, then:

```bash
	./autogen.sh && make dist
	rpmbuild -tb gaim-meanwhile-*.tar.gz
```

should create binary RPMs. Installing those should get Meanwhile working.


## Contact

Author: Christopher (siege) O'Brien  <obriencj@gmail.com>

IRC Channel: #meanwhile on [Freenode]

Original Git Repository: <https://github.com/obriencj/meanwhile-gaim>

Defunct Sourceforge Project: <https://sourceforge.net/projects/meanwhile/>

[Freenode]: https://freenode.net


## License

This library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, see
<http://www.gnu.org/licenses/>.
