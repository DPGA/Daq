#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <iostream>
#include <sstream>

/* consider adding boost thread id since we'll want to know whose writting and
 * won't want to repeat it for every single call */

/* consider adding policy class to allow users to redirect logging to specific
 * files via the command line
 */

enum loglevel_e
    {logERROR=0, logWARNING=1, logINFO=2, logDEBUG=3, logDEBUG1=4, logDEBUG2=5, logDEBUG3=6, logDEBUG4=7};

class logIt
{
public:
    logIt(loglevel_e _loglevel = logERROR,const bool endl=true) {
        Endl = endl;
        _buffer << _loglevel << " :" 
            << std::string(
                _loglevel > logDEBUG 
                ? (_loglevel - logDEBUG) * 4 
                : 1
                , ' ');
    }

    template <typename T>
    logIt & operator<<(T const & value)
    {
        _buffer << value;
        return *this;
    }

    ~logIt()
    {
        if (Endl) _buffer << std::endl;
        // This is atomic according to the POSIX standard
        // http://www.gnu.org/s/libc/manual/html_node/Streams-and-Threads.html
        std::cerr << _buffer.str();
    }

private:
    std::ostringstream _buffer;
    bool Endl;
};

extern loglevel_e loglevel;

#define log(level,endl) \
if (level > loglevel) ; \
else logIt(level,endl)

#endif
