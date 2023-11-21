# std::basic_ostream
Defined in header <ostream>
```c
template<
    class CharT,
    class Traits = std::char_traits<CharT>
> class basic_ostream : virtual public std::basic_ios<CharT, Traits>
```
The class template basic_ostream provides support for high level output operations on character streams. The supported operations include formatted output (e.g. integer values) and unformatted output (e.g. raw characters and character arrays). This functionality is implemented in terms of the interface provided by the basic_streambuf class, accessed through the basic_ios base class. In typical implementations, basic_ostream has no non-inherited data members.
## Template parameters
```
- charT
    Character type.
    This shall be a non-array POD type.
    Aliased as member type basic_istream::char_type.
- traits
    Character traits class that defines essential properties of the characters used by stream objects (see char_traits).
    traits::char_type shall be the same as charT.
    Aliased as member type basic_istream::traits_type.
```

