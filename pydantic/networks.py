"""The networks module contains types for common network-related fields."""
from __future__ import annotations as _annotations

import dataclasses as _dataclasses
import re
from importlib.metadata import version
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network
from typing import TYPE_CHECKING, Any, Generic, TypeVar, Union

import pydantic_core
from pydantic_core import MultiHostUrl, PydanticCustomError, Url, core_schema
from typing_extensions import Annotated, Self, TypeAlias, get_args, get_origin

from ._internal import _fields, _repr, _schema_generation_shared
from ._migration import getattr_migration
from .annotated_handlers import GetCoreSchemaHandler
from .json_schema import JsonSchemaValue

if TYPE_CHECKING:
    import email_validator

    NetworkType: TypeAlias = 'str | bytes | int | tuple[str | bytes | int, str | int]'

else:
    email_validator = None


__all__ = [
    'AnyUrl',
    'AnyHttpUrl',
    'FileUrl',
    'HttpUrl',
    'UrlConstraints',
    'EmailStr',
    'NameEmail',
    'IPvAnyAddress',
    'IPvAnyInterface',
    'IPvAnyNetwork',
    'PostgresDsn',
    'CockroachDsn',
    'AmqpDsn',
    'RedisDsn',
    'MongoDsn',
    'KafkaDsn',
    'NatsDsn',
    'validate_email',
    'MySQLDsn',
    'MariaDBDsn',
]


@_dataclasses.dataclass
class UrlConstraints(_fields.PydanticMetadata):
    """Url constraints.

    Attributes:
        max_length: The maximum length of the url. Defaults to `None`.
        allowed_schemes: The allowed schemes. Defaults to `None`.
        host_required: Whether the host is required. Defaults to `None`.
        default_host: The default host. Defaults to `None`.
        default_port: The default port. Defaults to `None`.
        default_path: The default path. Defaults to `None`.
    """

    max_length: int | None = None
    allowed_schemes: list[str] | None = None
    host_required: bool | None = None
    default_host: str | None = None
    default_port: int | None = None
    default_path: str | None = None

    def __hash__(self) -> int:
        return hash(
            (
                self.max_length,
                tuple(self.allowed_schemes) if self.allowed_schemes is not None else None,
                self.host_required,
                self.default_host,
                self.default_port,
                self.default_path,
            )
        )


_UrlT = TypeVar('_UrlT', bound=Union[Url, MultiHostUrl])


class _AnyUrlWrapper(Generic[_UrlT]):
    __slots__ = ('_url',)

    def __init__(self, url: _UrlT | str) -> None:
        if isinstance(url, str):
            url = self._wrapped()(url)
        self._url: _UrlT = url

    @classmethod
    def _wrapped(cls) -> type[_UrlT]:
        raise NotImplementedError

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return []

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> core_schema.CoreSchema:
        if get_origin(source) is Annotated:
            source, *constraints = get_args(source)
            inner = Annotated[cls._wrapped(), *constraints]  # type: ignore
        else:
            inner = cls._wrapped()
        constraints = cls._constraints()
        if constraints:
            inner_schema = handler(Annotated[inner, *constraints])  # type: ignore
        else:
            inner_schema = handler(inner)
        return core_schema.no_info_after_validator_function(
            function=cls,
            schema=inner_schema,
            serialization=core_schema.wrap_serializer_function_ser_schema(
                cls._serialize,
                schema=inner_schema,
            ),
        )

    @staticmethod
    def _serialize(value: _AnyUrlWrapper[_UrlT], handler: core_schema.SerializerFunctionWrapHandler) -> Any:
        return handler(value._url)

    def __hash__(self) -> int:
        return hash((type(self), self._url))

    def __str__(self) -> str:
        """The URL as a string, this will punycode encode the host if required."""
        return str(self._url)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}('{self._url}')"


class _UrlWrapper(_AnyUrlWrapper[Url]):
    """Base type for all URLs.

    * Any scheme allowed
    * Top-level domain (TLD) not required
    * Host required

    Assuming an input URL of `http://samuel:pass@example.com:8000/the/path/?query=here#fragment=is;this=bit`,
    the types export the following properties:

    - `scheme`: the URL scheme (`http`), always set.
    - `host`: the URL host (`example.com`), always set.
    - `username`: optional username if included (`samuel`).
    - `password`: optional password if included (`pass`).
    - `port`: optional port (`8000`).
    - `path`: optional path (`/the/path/`).
    - `query`: optional URL query (for example, `GET` arguments or "search string", such as `query=here`).
    - `fragment`: optional fragment (`fragment=is;this=bit`).
    """

    @classmethod
    def _wrapped(cls) -> type[Url]:
        return Url

    @property
    def scheme(self) -> str:
        """The scheme part of the URL.

        e.g. `https` in `https://user:pass@host:port/path?query#fragment`
        """
        return self._url.scheme

    @property
    def username(self) -> str | None:
        """The username part of the URL, or `None`.

        e.g. `user` in `https://user:pass@host:port/path?query#fragment`
        """
        return self._url.username

    @property
    def password(self) -> str | None:
        """The password part of the URL, or `None`.

        e.g. `pass` in `https://user:pass@host:port/path?query#fragment`
        """
        return self._url.password

    @property
    def host(self) -> str | None:
        """The host part of the URL, or `None`.

        If the URL must be punycode encoded, this is the encoded host, e.g if the input URL is `https://£££.com`,
        `host` will be `xn--9aaa.com`
        """
        return self._url.host

    def unicode_host(self) -> str | None:
        """The host part of the URL as a unicode string, or `None`.

        e.g. `host` in `https://user:pass@host:port/path?query#fragment`

        If the URL must be punycode encoded, this is the decoded host, e.g if the input URL is `https://£££.com`,
        `unicode_host()` will be `£££.com`
        """
        return self._url.unicode_host()

    @property
    def port(self) -> int | None:
        """The port part of the URL, or `None`.

        e.g. `port` in `https://user:pass@host:port/path?query#fragment`
        """
        return self._url.port

    @property
    def path(self) -> str | None:
        """The path part of the URL, or `None`.

        e.g. `/path` in `https://user:pass@host:port/path?query#fragment`
        """
        return self._url.path

    @property
    def query(self) -> str | None:
        """The query part of the URL, or `None`.

        e.g. `query` in `https://user:pass@host:port/path?query#fragment`
        """
        return self._url.query

    @property
    def fragment(self) -> str | None:
        """The fragment part of the URL, or `None`.

        e.g. `fragment` in `https://user:pass@host:port/path?query#fragment`
        """
        return self._url.fragment

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, _UrlWrapper):
            return False
        return self._url == other._url


class _MultiHostUrlWrapper(_AnyUrlWrapper[MultiHostUrl]):
    @classmethod
    def _wrapped(cls) -> type[MultiHostUrl]:
        return MultiHostUrl

    @property
    def scheme(self) -> str:
        """The scheme part of the URL.

        e.g. `https` in `https://foo.com,bar.com/path?query#fragment`
        """
        return self._url.scheme

    @property
    def path(self) -> str | None:
        """The path part of the URL, or `None`.

        e.g. `/path` in `https://foo.com,bar.com/path?query#fragment`
        """
        return self._url.path

    @property
    def query(self) -> str | None:
        """The query part of the URL, or `None`.

        e.g. `query` in `https://foo.com,bar.com/path?query#fragment`
        """
        return self._url.query

    def query_params(self) -> list[tuple[str, str]]:
        """The query part of the URL as a list of key-value pairs.

        e.g. `[('foo', 'bar')]` in `https://foo.com,bar.com/path?query#fragment`
        """
        return self._url.query_params()

    @property
    def fragment(self) -> str | None:
        """The fragment part of the URL, or `None`.

        e.g. `fragment` in `https://foo.com,bar.com/path?query#fragment`
        """
        return self._url.fragment

    def hosts(self) -> list[pydantic_core.MultiHostHost]:
        '''The hosts of the `MultiHostUrl` as [`MultiHostHost`][pydantic_core.MultiHostHost] typed dicts.

        ```py
        from pydantic_core import MultiHostUrl

        mhu = MultiHostUrl('https://foo.com:123,foo:bar@bar.com/path')
        print(mhu.hosts())
        """
        [
            {'username': None, 'password': None, 'host': 'foo.com', 'port': 123},
            {'username': 'foo', 'password': 'bar', 'host': 'bar.com', 'port': 443}
        ]
        ```
        Returns:
            A list of dicts, each representing a host.
        '''
        return self._url.hosts()

    def unicode_string(self) -> str:
        """The URL as a unicode string, unlike `__str__()` this will not punycode encode the hosts."""
        return self._url.unicode_string()

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, _MultiHostUrlWrapper):
            return False
        return self._url == other._url


class AnyUrl(_UrlWrapper):
    """Base type for all URLs.

    * Any scheme allowed
    * Top-level domain (TLD) not required
    * Host required

    Assuming an input URL of `http://samuel:pass@example.com:8000/the/path/?query=here#fragment=is;this=bit`,
    the types export the following properties:

    - `scheme`: the URL scheme (`http`), always set.
    - `host`: the URL host (`example.com`), always set.
    - `username`: optional username if included (`samuel`).
    - `password`: optional password if included (`pass`).
    - `port`: optional port (`8000`).
    - `path`: optional path (`/the/path/`).
    - `query`: optional URL query (for example, `GET` arguments or "search string", such as `query=here`).
    - `fragment`: optional fragment (`fragment=is;this=bit`).
    """


class AnyHttpUrl(_UrlWrapper):
    """A type that will accept any http or https URL.

    * TLD not required
    * Host required
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [UrlConstraints(allowed_schemes=['http', 'https'])]


class HttpUrl(_UrlWrapper):
    """A type that will accept any http or https URL.

    * TLD required
    * Host required
    * Max length 2083

    ```py
    from pydantic import BaseModel, HttpUrl, ValidationError

    class MyModel(BaseModel):
        url: HttpUrl

    m = MyModel(url='http://www.example.com')  # (1)!
    print(m.url)
    #> http://www.example.com/

    try:
        MyModel(url='ftp://invalid.url')
    except ValidationError as e:
        print(e)
        '''
        1 validation error for MyModel
        url
          URL scheme should be 'http' or 'https' [type=url_scheme, input_value='ftp://invalid.url', input_type=str]
        '''

    try:
        MyModel(url='not a url')
    except ValidationError as e:
        print(e)
        '''
        1 validation error for MyModel
        url
          Input should be a valid URL, relative URL without a base [type=url_parsing, input_value='not a url', input_type=str]
        '''
    ```

    1. Note: mypy would prefer `m = MyModel(url=HttpUrl('http://www.example.com'))`, but Pydantic will convert the string to an HttpUrl instance anyway.

    "International domains" (e.g. a URL where the host or TLD includes non-ascii characters) will be encoded via
    [punycode](https://en.wikipedia.org/wiki/Punycode) (see
    [this article](https://www.xudongz.com/blog/2017/idn-phishing/) for a good description of why this is important):

    ```py
    from pydantic import BaseModel, HttpUrl

    class MyModel(BaseModel):
        url: HttpUrl

    m1 = MyModel(url='http://puny£code.com')
    print(m1.url)
    #> http://xn--punycode-eja.com/
    m2 = MyModel(url='https://www.аррӏе.com/')
    print(m2.url)
    #> https://www.xn--80ak6aa92e.com/
    m3 = MyModel(url='https://www.example.珠宝/')
    print(m3.url)
    #> https://www.example.xn--pbt977c/
    ```


    !!! warning "Underscores in Hostnames"
        In Pydantic, underscores are allowed in all parts of a domain except the TLD.
        Technically this might be wrong - in theory the hostname cannot have underscores, but subdomains can.

        To explain this; consider the following two cases:

        - `exam_ple.co.uk`: the hostname is `exam_ple`, which should not be allowed since it contains an underscore.
        - `foo_bar.example.com` the hostname is `example`, which should be allowed since the underscore is in the subdomain.

        Without having an exhaustive list of TLDs, it would be impossible to differentiate between these two. Therefore
        underscores are allowed, but you can always do further validation in a validator if desired.

        Also, Chrome, Firefox, and Safari all currently accept `http://exam_ple.com` as a URL, so we're in good
        (or at least big) company.
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [UrlConstraints(max_length=2083, allowed_schemes=['http', 'https'])]


class FileUrl(_UrlWrapper):
    """A type that will accept any file URL.

    * Host not required
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [UrlConstraints(allowed_schemes=['file'])]


class PostgresDsn(_MultiHostUrlWrapper):
    """A type that will accept any Postgres DSN.

    * User info required
    * TLD not required
    * Host required
    * Supports multiple hosts

    If further validation is required, these properties can be used by validators to enforce specific behaviour:

    ```py
    from pydantic import (
        BaseModel,
        HttpUrl,
        PostgresDsn,
        ValidationError,
        field_validator,
    )

    class MyModel(BaseModel):
        url: HttpUrl

    m = MyModel(url='http://www.example.com')

    # the repr() method for a url will display all properties of the url
    print(repr(m.url))
    #> HttpUrl('http://www.example.com/')
    print(m.url.scheme)
    #> http
    print(m.url.host)
    #> www.example.com
    print(m.url.port)
    #> 80

    class MyDatabaseModel(BaseModel):
        db: PostgresDsn

        @field_validator('db')
        def check_db_name(cls, v):
            assert v.path and len(v.path) > 1, 'database must be provided'
            return v

    m = MyDatabaseModel(db='postgres://user:pass@localhost:5432/foobar')
    print(m.db)
    #> postgres://user:pass@localhost:5432/foobar

    try:
        MyDatabaseModel(db='postgres://user:pass@localhost:5432')
    except ValidationError as e:
        print(e)
        '''
        1 validation error for MyDatabaseModel
        db
          Assertion failed, database must be provided
        assert (None)
         +  where None = PostgresDsn('postgres://user:pass@localhost:5432').path [type=assertion_error, input_value='postgres://user:pass@localhost:5432', input_type=str]
        '''
    ```
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [
            UrlConstraints(
                host_required=True,
                allowed_schemes=[
                    'postgres',
                    'postgresql',
                    'postgresql+asyncpg',
                    'postgresql+pg8000',
                    'postgresql+psycopg',
                    'postgresql+psycopg2',
                    'postgresql+psycopg2cffi',
                    'postgresql+py-postgresql',
                    'postgresql+pygresql',
                ],
            )
        ]


class CockroachDsn(_MultiHostUrlWrapper):
    """A type that will accept any Cockroach DSN.

    * User info required
    * TLD not required
    * Host required
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [
            UrlConstraints(
                host_required=True,
                allowed_schemes=[
                    'cockroachdb',
                    'cockroachdb+psycopg2',
                    'cockroachdb+asyncpg',
                ],
            )
        ]


class AmqpDsn(_UrlWrapper):
    """A type that will accept any AMQP DSN.

    * User info required
    * TLD not required
    * Host required
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [UrlConstraints(allowed_schemes=['amqp', 'amqps'])]


class RedisDsn(_UrlWrapper):
    """A type that will accept any Redis DSN.

    * User info required
    * TLD not required
    * Host required (e.g., `rediss://:pass@localhost`)
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [
            UrlConstraints(
                allowed_schemes=['redis', 'rediss'],
                default_host='localhost',
                default_port=6379,
                default_path='/0',
            )
        ]


class MongoDsn(_MultiHostUrlWrapper):
    """A type that will accept any MongoDB DSN.

    * User info not required
    * Database name not required
    * Port not required
    * User info may be passed without user part (e.g., `mongodb://mongodb0.example.com:27017`).
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [UrlConstraints(allowed_schemes=['mongodb', 'mongodb+srv'], default_port=27017)]


class KafkaDsn(_UrlWrapper):
    """A type that will accept any Kafka DSN.

    * User info required
    * TLD not required
    * Host required
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [UrlConstraints(allowed_schemes=['kafka'], default_host='localhost', default_port=9092)]


class NatsDsn(_MultiHostUrlWrapper):
    """A type that will accept any NATS DSN.

    NATS is a connective technology built for the ever increasingly hyper-connected world.
    It is a single technology that enables applications to securely communicate across
    any combination of cloud vendors, on-premise, edge, web and mobile, and devices.
    More: https://nats.io
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [
            UrlConstraints(
                allowed_schemes=['nats', 'tls', 'ws'],
                default_host='localhost',
                default_port=4222,
            )
        ]


class MySQLDsn(_UrlWrapper):
    """A type that will accept any MySQL DSN.

    * User info required
    * TLD not required
    * Host required
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [
            UrlConstraints(
                allowed_schemes=[
                    'mysql',
                    'mysql+mysqlconnector',
                    'mysql+aiomysql',
                    'mysql+asyncmy',
                    'mysql+mysqldb',
                    'mysql+pymysql',
                    'mysql+cymysql',
                    'mysql+pyodbc',
                ],
                default_port=3306,
            )
        ]


class MariaDBDsn(_UrlWrapper):
    """A type that will accept any MariaDB DSN.

    * User info required
    * TLD not required
    * Host required
    """

    @classmethod
    def _constraints(cls) -> list[UrlConstraints]:
        return [
            UrlConstraints(
                allowed_schemes=['mariadb', 'mariadb+mariadbconnector', 'mariadb+pymysql'],
                default_port=3306,
            )
        ]


def import_email_validator() -> None:
    global email_validator
    try:
        import email_validator
    except ImportError as e:
        raise ImportError('email-validator is not installed, run `pip install pydantic[email]`') from e
    if not version('email-validator').partition('.')[0] == '2':
        raise ImportError('email-validator version >= 2.0 required, run pip install -U email-validator')


if TYPE_CHECKING:
    EmailStr = Annotated[str, ...]
else:

    class EmailStr:
        """
        Info:
            To use this type, you need to install the optional
            [`email-validator`](https://github.com/JoshData/python-email-validator) package:

            ```bash
            pip install email-validator
            ```

        Validate email addresses.

        ```py
        from pydantic import BaseModel, EmailStr

        class Model(BaseModel):
            email: EmailStr

        print(Model(email='contact@mail.com'))
        #> email='contact@mail.com'
        ```
        """  # noqa: D212

        @classmethod
        def __get_pydantic_core_schema__(
            cls,
            _source: type[Any],
            _handler: GetCoreSchemaHandler,
        ) -> core_schema.CoreSchema:
            import_email_validator()
            return core_schema.no_info_after_validator_function(cls._validate, core_schema.str_schema())

        @classmethod
        def __get_pydantic_json_schema__(
            cls, core_schema: core_schema.CoreSchema, handler: _schema_generation_shared.GetJsonSchemaHandler
        ) -> JsonSchemaValue:
            field_schema = handler(core_schema)
            field_schema.update(type='string', format='email')
            return field_schema

        @classmethod
        def _validate(cls, input_value: str, /) -> str:
            return validate_email(input_value)[1]


class NameEmail(_repr.Representation):
    """
    Info:
        To use this type, you need to install the optional
        [`email-validator`](https://github.com/JoshData/python-email-validator) package:

        ```bash
        pip install email-validator
        ```

    Validate a name and email address combination, as specified by
    [RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322#section-3.4).

    The `NameEmail` has two properties: `name` and `email`.
    In case the `name` is not provided, it's inferred from the email address.

    ```py
    from pydantic import BaseModel, NameEmail

    class User(BaseModel):
        email: NameEmail

    user = User(email='Fred Bloggs <fred.bloggs@example.com>')
    print(user.email)
    #> Fred Bloggs <fred.bloggs@example.com>
    print(user.email.name)
    #> Fred Bloggs

    user = User(email='fred.bloggs@example.com')
    print(user.email)
    #> fred.bloggs <fred.bloggs@example.com>
    print(user.email.name)
    #> fred.bloggs
    ```
    """  # noqa: D212

    __slots__ = 'name', 'email'

    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, NameEmail) and (self.name, self.email) == (other.name, other.email)

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: core_schema.CoreSchema, handler: _schema_generation_shared.GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        field_schema = handler(core_schema)
        field_schema.update(type='string', format='name-email')
        return field_schema

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source: type[Any],
        _handler: GetCoreSchemaHandler,
    ) -> core_schema.CoreSchema:
        import_email_validator()

        return core_schema.no_info_after_validator_function(
            cls._validate,
            core_schema.json_or_python_schema(
                json_schema=core_schema.str_schema(),
                python_schema=core_schema.union_schema(
                    [core_schema.is_instance_schema(cls), core_schema.str_schema()],
                    custom_error_type='name_email_type',
                    custom_error_message='Input is not a valid NameEmail',
                ),
                serialization=core_schema.to_string_ser_schema(),
            ),
        )

    @classmethod
    def _validate(cls, input_value: Self | str, /) -> Self:
        if isinstance(input_value, cls):
            return input_value
        else:
            name, email = validate_email(input_value)
            return cls(name, email)

    def __str__(self) -> str:
        if '@' in self.name:
            return f'"{self.name}" <{self.email}>'

        return f'{self.name} <{self.email}>'


class IPvAnyAddress:
    """Validate an IPv4 or IPv6 address.

    ```py
    from pydantic import BaseModel
    from pydantic.networks import IPvAnyAddress

    class IpModel(BaseModel):
        ip: IPvAnyAddress

    print(IpModel(ip='127.0.0.1'))
    #> ip=IPv4Address('127.0.0.1')

    try:
        IpModel(ip='http://www.example.com')
    except ValueError as e:
        print(e.errors())
        '''
        [
            {
                'type': 'ip_any_address',
                'loc': ('ip',),
                'msg': 'value is not a valid IPv4 or IPv6 address',
                'input': 'http://www.example.com',
            }
        ]
        '''
    ```
    """

    __slots__ = ()

    def __new__(cls, value: Any) -> IPv4Address | IPv6Address:
        """Validate an IPv4 or IPv6 address."""
        try:
            return IPv4Address(value)
        except ValueError:
            pass

        try:
            return IPv6Address(value)
        except ValueError:
            raise PydanticCustomError('ip_any_address', 'value is not a valid IPv4 or IPv6 address')

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: core_schema.CoreSchema, handler: _schema_generation_shared.GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        field_schema = {}
        field_schema.update(type='string', format='ipvanyaddress')
        return field_schema

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source: type[Any],
        _handler: GetCoreSchemaHandler,
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._validate, serialization=core_schema.to_string_ser_schema()
        )

    @classmethod
    def _validate(cls, input_value: Any, /) -> IPv4Address | IPv6Address:
        return cls(input_value)  # type: ignore[return-value]


class IPvAnyInterface:
    """Validate an IPv4 or IPv6 interface."""

    __slots__ = ()

    def __new__(cls, value: NetworkType) -> IPv4Interface | IPv6Interface:
        """Validate an IPv4 or IPv6 interface."""
        try:
            return IPv4Interface(value)
        except ValueError:
            pass

        try:
            return IPv6Interface(value)
        except ValueError:
            raise PydanticCustomError('ip_any_interface', 'value is not a valid IPv4 or IPv6 interface')

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: core_schema.CoreSchema, handler: _schema_generation_shared.GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        field_schema = {}
        field_schema.update(type='string', format='ipvanyinterface')
        return field_schema

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source: type[Any],
        _handler: GetCoreSchemaHandler,
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._validate, serialization=core_schema.to_string_ser_schema()
        )

    @classmethod
    def _validate(cls, input_value: NetworkType, /) -> IPv4Interface | IPv6Interface:
        return cls(input_value)  # type: ignore[return-value]


class IPvAnyNetwork:
    """Validate an IPv4 or IPv6 network."""

    __slots__ = ()

    def __new__(cls, value: NetworkType) -> IPv4Network | IPv6Network:
        """Validate an IPv4 or IPv6 network."""
        # Assume IP Network is defined with a default value for `strict` argument.
        # Define your own class if you want to specify network address check strictness.
        try:
            return IPv4Network(value)
        except ValueError:
            pass

        try:
            return IPv6Network(value)
        except ValueError:
            raise PydanticCustomError('ip_any_network', 'value is not a valid IPv4 or IPv6 network')

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: core_schema.CoreSchema, handler: _schema_generation_shared.GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        field_schema = {}
        field_schema.update(type='string', format='ipvanynetwork')
        return field_schema

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source: type[Any],
        _handler: GetCoreSchemaHandler,
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._validate, serialization=core_schema.to_string_ser_schema()
        )

    @classmethod
    def _validate(cls, input_value: NetworkType, /) -> IPv4Network | IPv6Network:
        return cls(input_value)  # type: ignore[return-value]


def _build_pretty_email_regex() -> re.Pattern[str]:
    name_chars = r'[\w!#$%&\'*+\-/=?^_`{|}~]'
    unquoted_name_group = rf'((?:{name_chars}+\s+)*{name_chars}+)'
    quoted_name_group = r'"((?:[^"]|\")+)"'
    email_group = r'<\s*(.+)\s*>'
    return re.compile(rf'\s*(?:{unquoted_name_group}|{quoted_name_group})?\s*{email_group}\s*')


pretty_email_regex = _build_pretty_email_regex()

MAX_EMAIL_LENGTH = 2048
"""Maximum length for an email.
A somewhat arbitrary but very generous number compared to what is allowed by most implementations.
"""


def validate_email(value: str) -> tuple[str, str]:
    """Email address validation using [email-validator](https://pypi.org/project/email-validator/).

    Note:
        Note that:

        * Raw IP address (literal) domain parts are not allowed.
        * `"John Doe <local_part@domain.com>"` style "pretty" email addresses are processed.
        * Spaces are striped from the beginning and end of addresses, but no error is raised.
    """
    if email_validator is None:
        import_email_validator()

    if len(value) > MAX_EMAIL_LENGTH:
        raise PydanticCustomError(
            'value_error',
            'value is not a valid email address: {reason}',
            {'reason': f'Length must not exceed {MAX_EMAIL_LENGTH} characters'},
        )

    m = pretty_email_regex.fullmatch(value)
    name: str | None = None
    if m:
        unquoted_name, quoted_name, value = m.groups()
        name = unquoted_name or quoted_name

    email = value.strip()

    try:
        parts = email_validator.validate_email(email, check_deliverability=False)
    except email_validator.EmailNotValidError as e:
        raise PydanticCustomError(
            'value_error', 'value is not a valid email address: {reason}', {'reason': str(e.args[0])}
        ) from e

    email = parts.normalized
    assert email is not None
    name = name or parts.local_part
    return name, email


__getattr__ = getattr_migration(__name__)
