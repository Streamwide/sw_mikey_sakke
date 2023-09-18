#ifndef UTIL_PRINTABLE_INL
#define UTIL_PRINTABLE_INL

#include <algorithm>
#include <string>
#include <ostream>

inline std::string make_printable(std::string s)
{
   std::replace(s.begin(), s.end(), '\0', '.');
   return s;
}
struct stream_printable
{
   stream_printable(std::string const& s) : s(s) {}

   friend std::ostream& operator<< (std::ostream& out, stream_printable const& s)
   {
      char const* b = s.s.c_str(), *m = b, *e = b + s.s.size();
      for (;;)
      {
         while (*m) 
            ++m;
         out.write(b, m - b);
         if (m == e)
            return out;
         out.put('.');
         b = ++m;
      }
   }
   std::string const& s;
};

#endif//UTIL_PRINTABLE_INL

